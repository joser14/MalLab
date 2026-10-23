"""Static triage: hashes, type, entropy, strings, PE structure, Office macros, archives.

Pure inspection of bytes on disk. Nothing here executes the sample. Optional libraries
(pefile, oletools, yara-python, python-magic) are used when present and skipped otherwise,
so the engine degrades gracefully on a bare install.
"""

import datetime
import hashlib
import ipaddress
import json
import math
import re
import shutil
import subprocess
import zipfile
from collections import Counter
from pathlib import Path

# Imports whose presence in a PE is worth calling out during triage.
SUSPICIOUS_APIS = {
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
    "QueueUserAPC", "SetWindowsHookEx", "GetAsyncKeyState", "GetKeyState",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt",
    "URLDownloadToFile", "InternetOpen", "InternetReadFile", "WinHttpOpen", "HttpSendRequest",
    "WinExec", "ShellExecute", "CreateProcess", "RegSetValue", "RegCreateKey",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "GetProcAddress", "LoadLibrary", "VirtualProtect", "CreateService", "OpenSCManager",
    "CreateToolhelp32Snapshot", "Process32First", "FindResource", "WSASocket", "connect",
}

MACRO_AUTOEXEC = ("AutoOpen", "Auto_Open", "Document_Open", "AutoExec", "Workbook_Open",
                  "Auto_Close", "Document_Close")

URL_RE = re.compile(rb"https?://[\w\-./%?=&#:@~+]{4,200}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Generic + the ccTLDs/new gTLDs most seen in malware infrastructure. Filenames like "kernel32.dll"
# never match because file extensions aren't in the list.
DOMAIN_RE = re.compile(
    rb"\b(?:[a-zA-Z0-9\-]{1,63}\.)+(?:com|net|org|edu|gov|mil|int|info|biz|io|co|me|tv|cc|ws|su|ru|ua|by|kz|"
    rb"cn|hk|tw|jp|kr|in|ir|tr|br|ar|mx|de|fr|uk|nl|pl|it|es|eu|ch|se|no|fi|cz|ro|bg|hu|gr|pt|ca|us|au|"
    rb"top|xyz|online|site|club|live|shop|store|icu|cyou|buzz|fun|space|website|tech|pw|tk|ml|ga|cf|gq|"
    rb"onion|bit|duckdns\.org|ngrok\.io|app|dev|cloud|link|click|work|vip|win|bid|loan|today|rest|lol)\b")
REG_RE = re.compile(rb"(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE\\\\?[\w\\]+)")


def _hashes(data: bytes) -> dict:
    out = {"md5": hashlib.md5(data).hexdigest(),
           "sha1": hashlib.sha1(data).hexdigest(),
           "sha256": hashlib.sha256(data).hexdigest()}
    try:  # fuzzy hash for "similar sample" search (optional: pip install py-tlsh)
        import tlsh
        h = tlsh.hash(data)
        out["tlsh"] = h if h and h != "TNULL" else None
    except Exception:
        pass
    return out


# Built-in similarity that needs no native library: a MinHash over the file's distinct strings.
# Two samples' signatures estimate the Jaccard overlap of their string sets, which tracks family
# variants (shared config strings, URLs, mutexes, error text) well. Not TLSH, and not comparable
# with TLSH values from other tools.
_MH_N = 64
_MH_P = (1 << 61) - 1
_MH_COEF = [(int.from_bytes(hashlib.blake2b(b"a%d" % i, digest_size=8).digest(), "big") % _MH_P | 1,
             int.from_bytes(hashlib.blake2b(b"b%d" % i, digest_size=8).digest(), "big") % _MH_P)
            for i in range(_MH_N)]


def strings_minhash(strings: list[str]) -> list[int] | None:
    feats = {int.from_bytes(hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=8).digest(), "big")
             for s in strings if len(s) >= 6}
    if len(feats) < 8:   # too little text to say anything about similarity
        return None
    return [min((a * x + b) % _MH_P for x in feats) for a, b in _MH_COEF]


def minhash_similarity(a, b) -> float | None:
    if not a or not b or len(a) != len(b):
        return None
    return sum(x == y for x, y in zip(a, b)) / len(a)


def tlsh_distance(a: str | None, b: str | None) -> int | None:
    if not a or not b:
        return None
    try:
        import tlsh
        return tlsh.diff(a, b)
    except Exception:
        return None


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def detect_type(data: bytes, filename: str) -> str:
    sigs = [
        (b"MZ", "PE executable (EXE/DLL)"),
        (b"\x7fELF", "ELF executable"),
        (b"%PDF", "PDF document"),
        (b"PK\x03\x04", "ZIP / OOXML / JAR"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"\xd0\xcf\x11\xe0", "OLE / legacy Office (doc/xls)"),
        (b"\x1f\x8b", "GZIP"),
        (b"#!", "Script with shebang"),
        (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
        (b"\xfe\xed\xfa", "Mach-O executable"),
    ]
    for magic, name in sigs:
        if data.startswith(magic):
            return name
    try:
        import magic  # python-magic, optional
        return magic.from_buffer(data)
    except Exception:
        pass
    ext = Path(filename).suffix.lower()
    return f"unknown ({ext or 'no extension'})"


def extract_strings(data: bytes, minlen: int = 5, cap: int = 4000) -> list[str]:
    out = []
    # ASCII runs
    for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, data):
        out.append(m.group().decode("ascii", "replace"))
        if len(out) >= cap:
            break
    # UTF-16LE runs (common in Windows binaries)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, data):
        out.append(m.group().decode("utf-16le", "replace"))
        if len(out) >= cap:
            break
    return out


def _iocs(data: bytes) -> dict:
    def grab(rx, limit=60):
        seen, out = set(), []
        for m in rx.finditer(data):
            v = m.group().decode("utf-8", "replace")
            if v not in seen:
                seen.add(v)
                out.append(v)
            if len(out) >= limit:
                break
        return out
    def real_ip(s: str) -> bool:  # drops version strings like 999.1.2.3 and local/reserved ranges
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            return False
        return not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_reserved
                    or ip.is_link_local or s.startswith("0."))
    ips = [ip for ip in grab(IP_RE) if real_ip(ip)]
    return {"urls": grab(URL_RE), "ips": ips,
            "domains": grab(DOMAIN_RE), "registry": grab(REG_RE, 40)}


def _pe_analysis(path: Path) -> dict | None:
    try:
        import pefile
    except ImportError:
        return {"note": "pefile not installed; `pip install pefile` for PE import/section detail"}
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY[d] for d in (
                "IMAGE_DIRECTORY_ENTRY_IMPORT", "IMAGE_DIRECTORY_ENTRY_EXPORT",
                "IMAGE_DIRECTORY_ENTRY_TLS", "IMAGE_DIRECTORY_ENTRY_RESOURCE")])
    except Exception as e:
        return {"error": f"not a parseable PE: {e}"}
    dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY

    def has_dir(name):
        i = pefile.DIRECTORY_ENTRY[name]
        return len(dirs) > i and dirs[i].VirtualAddress != 0 and dirs[i].Size != 0

    sections = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        ent = s.get_entropy()
        sections.append({"name": name, "vsize": s.Misc_VirtualSize,
                         "rawsize": s.SizeOfRawData, "entropy": round(ent, 2),
                         "suspicious": ent > 7.2 or s.SizeOfRawData == 0})

    imports, flagged = [], []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("latin-1", "replace")
        funcs = [imp.name.decode("latin-1", "replace") for imp in entry.imports if imp.name]
        imports.append({"dll": dll, "count": len(funcs)})
        for fn in funcs:
            # Match with one A/W charset suffix and/or an Ex suffix removed: ShellExecuteExW -> ShellExecute.
            cands = {fn, fn[:-1]} if fn[-1:] in ("A", "W") else {fn}
            cands |= {c[:-2] for c in cands if c.endswith("Ex")}
            if cands & SUSPICIOUS_APIS:
                flagged.append(f"{dll}!{fn}")

    ts = pe.FILE_HEADER.TimeDateStamp
    try:
        compiled = (datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
                    .strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None)
    except (OSError, OverflowError, ValueError):
        compiled = f"invalid ({ts})"

    # .NET assemblies import only mscoree.dll!_CorExeMain by design: few imports is normal there,
    # so it isn't a packing hint. Native code with almost no imports is.
    dotnet = has_dir("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR")
    n_funcs = sum(i["count"] for i in imports)

    try:
        imphash = pe.get_imphash() or None
    except Exception:
        imphash = None
    exports = []
    for sym in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []) or []:
        if sym.name:
            exports.append(sym.name.decode("latin-1", "replace"))
    tls_callbacks = 0
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls and tls.struct.AddressOfCallBacks:
        try:
            base = pe.OPTIONAL_HEADER.ImageBase
            rva = tls.struct.AddressOfCallBacks - base
            ptr = 8 if pe.FILE_HEADER.Machine == 0x8664 else 4
            while tls_callbacks < 32:
                val = pe.get_qword_at_rva(rva) if ptr == 8 else pe.get_dword_at_rva(rva)
                if not val:
                    break
                tls_callbacks += 1
                rva += ptr
        except Exception:
            pass
    overlay = pe.get_overlay_data_start_offset()
    size = path.stat().st_size
    resources = []
    for top in getattr(getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None), "entries", []) or []:
        rtype = str(top.name) if top.name else pefile.RESOURCE_TYPE.get(top.id, str(top.id))
        for entry in getattr(getattr(top, "directory", None), "entries", []) or []:
            for lang in getattr(getattr(entry, "directory", None), "entries", []) or []:
                d = lang.data.struct
                try:
                    blob = pe.get_data(d.OffsetToData, min(d.Size, 4 * 2**20))
                    ent = round(shannon_entropy(blob), 2)
                    embedded_pe = blob[:2] == b"MZ"
                except Exception:
                    ent, embedded_pe = None, False
                if len(resources) < 50:
                    resources.append({"type": rtype, "size": d.Size, "entropy": ent, "embedded_pe": embedded_pe})

    return {
        "machine": hex(pe.FILE_HEADER.Machine),
        "subsystem": pe.OPTIONAL_HEADER.Subsystem,
        "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
        "dotnet": dotnet,
        "compiled": compiled,
        "imphash": imphash,
        "signed": has_dir("IMAGE_DIRECTORY_ENTRY_SECURITY"),   # has an Authenticode blob (not verified)
        "sections": sections,
        "imports": imports,
        "suspicious_imports": sorted(set(flagged)),
        "exports": exports[:200],
        "tls_callbacks": tls_callbacks,
        "overlay": {"offset": overlay, "size": size - overlay} if overlay and overlay < size else None,
        "resources": resources,
        "packed_hint": any(s["entropy"] > 7.2 for s in sections) or (not dotnet and n_funcs <= 5),
    }


def _could_hold_macros(path: Path, data: bytes) -> bool:
    """Only real Office containers: OLE (doc/xls/ppt) or OOXML zips. olevba also parses plain
    text as 'VBA source', which flagged every text-bearing sample as having macros."""
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        return True
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(path) as z:
                return any(n.startswith(("word/", "xl/", "ppt/")) or n.endswith("vbaProject.bin")
                           for n in z.namelist())
        except Exception:
            return False
    return False


def _office_macros(path: Path, data: bytes) -> dict | None:
    if not _could_hold_macros(path, data):
        return None
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return None
    try:
        vp = VBA_Parser(str(path))
        if not vp.detect_vba_macros():
            vp.close()
            return {"has_macros": False}
        autos, snippets = [], []
        for _, _, vba_filename, vba_code in vp.extract_macros():
            for kw in MACRO_AUTOEXEC:
                if kw.lower() in (vba_code or "").lower():
                    autos.append(kw)
            if vba_code:
                snippets.append({"name": vba_filename, "lines": vba_code.count("\n") + 1})
        vp.close()
        return {"has_macros": True, "autoexec": sorted(set(autos)), "streams": snippets}
    except Exception as e:
        return {"error": str(e)}


def _archive_listing(path: Path) -> dict | None:
    if not zipfile.is_zipfile(path):
        return None
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            encrypted = any(i.flag_bits & 0x1 for i in z.infolist())
            risky = [n for n in names
                     if Path(n).suffix.lower() in
                     (".exe", ".dll", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1",
                      ".jar", ".hta", ".lnk", ".wsf", ".com", ".pif")]
            return {"entries": len(names), "encrypted": encrypted,
                    "names": names[:100], "risky_members": risky}
    except Exception as e:
        return {"error": str(e)}


def _yara_scan(path: Path, rules_dir: Path | None) -> dict | None:
    if not rules_dir or not Path(rules_dir).exists():
        return None
    try:
        import yara
    except ImportError:
        return {"note": "yara-python not installed"}
    rule_files = {}
    for rf in Path(rules_dir).rglob("*.yar"):
        rule_files[rf.stem] = str(rf)
    for rf in Path(rules_dir).rglob("*.yara"):
        rule_files[rf.stem] = str(rf)
    if not rule_files:
        return {"note": f"no .yar/.yara rules in {rules_dir}"}
    try:
        rules = yara.compile(filepaths=rule_files)
        matches = rules.match(str(path), timeout=60)
        return {"matches": [{"rule": m.rule, "tags": list(m.tags)} for m in matches],
                "rules_loaded": len(rule_files)}
    except Exception as e:
        return {"error": str(e)}


def find_capa(tools_dir: Path | None) -> str | None:
    """Mandiant capa (capability detection), if the analyst dropped capa.exe into lab\\tools or
    has it on PATH. Optional: https://github.com/mandiant/capa/releases"""
    if tools_dir and (Path(tools_dir) / "capa.exe").is_file():
        return str(Path(tools_dir) / "capa.exe")
    return shutil.which("capa")


def _capa(path: Path, tools_dir: Path | None) -> dict | None:
    exe = find_capa(tools_dir)
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-j", str(path)], capture_output=True, text=True, timeout=300,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        doc = json.loads(r.stdout)
    except subprocess.TimeoutExpired:
        return {"error": "capa timed out (5 min)"}
    except Exception as e:
        return {"error": f"capa failed: {type(e).__name__}: {e}"}
    caps = []
    for name, rule in (doc.get("rules") or {}).items():
        meta = rule.get("meta") or {}
        if meta.get("lib") or "internal" in (meta.get("namespace") or ""):
            continue
        caps.append({"name": meta.get("name") or name, "namespace": meta.get("namespace") or "",
                     "attck": sorted({a.get("id") for a in meta.get("attack") or [] if a.get("id")})})
    caps.sort(key=lambda c: (c["namespace"], c["name"]))
    return {"capabilities": caps[:300], "count": len(caps)}


def _risk_score(report: dict) -> tuple[int, list[str]]:
    """A heuristic 0-100 triage score with reasons. Not a verdict — a reading aid."""
    score, reasons = 0, []

    def bump(n, why):
        nonlocal score
        score += n
        reasons.append(why)

    pe = report.get("pe") or {}
    if pe.get("suspicious_imports"):
        bump(min(30, 5 * len(pe["suspicious_imports"])),
             f"{len(pe['suspicious_imports'])} suspicious imports")
    if pe.get("packed_hint"):
        bump(15, "high-entropy sections / minimal imports (possible packing)")
    if any(r.get("embedded_pe") for r in pe.get("resources") or []):
        bump(15, "executable embedded in resources")
    if report.get("entropy", 0) > 7.2:
        bump(10, f"overall entropy {report['entropy']} (compressed/encrypted)")

    macros = report.get("office_macros") or {}
    if macros.get("has_macros"):
        bump(15, "contains VBA macros")
    if macros.get("autoexec"):
        bump(20, f"auto-executing macros: {', '.join(macros['autoexec'])}")

    arch = report.get("archive") or {}
    if arch.get("encrypted"):
        bump(10, "password-protected archive (common malware delivery)")
    if arch.get("risky_members"):
        bump(10, f"archive bundles executables: {len(arch['risky_members'])}")

    iocs = report.get("iocs") or {}
    if iocs.get("urls") or iocs.get("ips"):
        bump(min(15, 3 * (len(iocs.get("urls", [])) + len(iocs.get("ips", [])))),
             "embedded URLs/IPs")

    if (report.get("yara") or {}).get("matches"):
        bump(25, f"{len(report['yara']['matches'])} YARA matches")

    return min(100, score), reasons


def analyze(path: Path, filename: str, rules_dir: Path | None = None,
            tools_dir: Path | None = None) -> dict:
    path = Path(path)
    data = path.read_bytes()
    report: dict = {
        "filename": filename,
        "size": len(data),
        "hashes": _hashes(data),
        "file_type": detect_type(data, filename),
        "entropy": shannon_entropy(data),
    }
    strings = extract_strings(data)
    report["strings_minhash"] = strings_minhash(strings)
    report["string_count"] = len(strings)
    report["strings_sample"] = strings[:400]
    report["iocs"] = _iocs(data)

    if data.startswith(b"MZ"):
        report["pe"] = _pe_analysis(path)
        capa = _capa(path, tools_dir)   # capa only reads the file; nothing is executed
        if capa is not None:
            report["capa"] = capa
    macros = _office_macros(path, data)
    if macros is not None:
        report["office_macros"] = macros
    arch = _archive_listing(path)
    if arch is not None:
        report["archive"] = arch
    yara_res = _yara_scan(path, rules_dir)
    if yara_res is not None:
        report["yara"] = yara_res

    report["risk"], report["risk_reasons"] = _risk_score(report)
    return report
