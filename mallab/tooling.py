"""Download the lab's optional analysis tools from their official GitHub releases into lab\\tools.

    capa            Mandiant capability detection          https://github.com/mandiant/capa
    FakeNet-NG      Mandiant network simulation (in-VM)    https://github.com/mandiant/flare-fakenet-ng
    hollows_hunter  pe-sieve memory implant dumper (in-VM) https://github.com/hasherezade/hollows_hunter
    Sigma rules     SigmaHQ community detections (DRL 1.1) https://github.com/SigmaHQ/sigma
    YARA Forge      curated public YARA rule packs         https://github.com/YARAHQ/yara-forge

Used by the installer's optional steps and by Settings. Each download is the latest release asset
matching a strict name pattern, checked against the SHA-256 digest GitHub publishes for it when
available, size-capped, and extracted with path checks (no absolute paths, no "..", no links).
Neither tool is run on the host by this module: capa reads samples statically, FakeNet is only
staged into the sandbox VM.
"""

import hashlib
import io
import re
import shutil
import zipfile
from pathlib import Path, PurePosixPath

import httpx

UA = "mallab/1.0"
MAX_DOWNLOAD = 400 * 2**20
MAX_EXTRACT = 800 * 2**20

TOOLS = {
    "capa": {"repo": "mandiant/capa", "asset": re.compile(r"^capa-v[\d.]+-windows\.zip$", re.I), "web": "capa-{tag}-windows.zip",
             "name": "capa"},
    "fakenet": {"repo": "mandiant/flare-fakenet-ng", "asset": re.compile(r"^fakenet[\w.\-]*\.zip$", re.I), "web": "fakenet{ver}.zip",
                "name": "FakeNet-NG"},
    # Runs only inside the sandbox VM, at the end of a detonation, to dump injected / unpacked code.
    "hollows_hunter": {"repo": "hasherezade/hollows_hunter", "asset": re.compile(r"^hollows_hunter64\.exe$", re.I), "web": "hollows_hunter64.exe",
                       "name": "hollows_hunter (pe-sieve)"},
    # Rule packs: data, not programs.
    "sigma": {"repo": "SigmaHQ/sigma", "asset": re.compile(r"^sigma_core\.zip$", re.I), "web": "sigma_core.zip", "name": "SigmaHQ rules"},
    "yara_forge": {"repo": "YARAHQ/yara-forge", "asset": re.compile(r"^yara-forge-rules-core\.zip$", re.I), "web": "yara-forge-rules-core.zip",
                   "name": "YARA Forge rules"},
}


class ToolError(RuntimeError):
    pass


# Rule packs on disk: a header plus the rules XORed with a fixed key. This is not secrecy (the key
# is right here); it only keeps antivirus from reading malware strings quoted in the rules and
# quarantining the file. Packs are decoded in memory just before compiling.
PACK_SUFFIX = ".mlx"
_PACK_MAGIC = b"MALLAB-PACK1\n"
_PACK_KEY = b"MalLab rule pack, not malware. "


def _xor(data: bytes) -> bytes:
    if not data:
        return b""
    key = (_PACK_KEY * (len(data) // len(_PACK_KEY) + 1))[:len(data)]
    return (int.from_bytes(data, "little") ^ int.from_bytes(key, "little")).to_bytes(len(data), "little")


def encode_pack(data: bytes) -> bytes:
    return _PACK_MAGIC + _xor(data)


def decode_pack(blob: bytes) -> bytes:
    if not blob.startswith(_PACK_MAGIC):
        raise ValueError("not a MalLab rule pack")
    return _xor(blob[len(_PACK_MAGIC):])


def _web_latest(repo: str, template: str, client: httpx.Client) -> dict:
    """Fallback that doesn't use the GitHub API (whose unauthenticated limit is 60 calls/hour per
    IP, easily used up on shared connections): read the latest tag from the releases/latest
    redirect, then build the asset's download link from a known name template. GitHub doesn't
    publish a digest here, so this path is HTTPS-only."""
    r = client.get(f"https://github.com/{repo}/releases/latest", follow_redirects=False)
    loc = r.headers.get("location", "")
    m = re.search(r"/releases/tag/([^/?#]+)$", loc)
    if r.status_code not in (301, 302) or not m:
        raise ToolError(f"could not find {repo}'s latest release")
    tag = m.group(1)
    name = template.format(tag=tag, ver=tag.lstrip("v"))
    if not re.fullmatch(r"[\w.\-+]{1,120}", name):
        raise ToolError(f"unexpected release asset name {name!r}")
    return {"name": name, "url": f"https://github.com/{repo}/releases/download/{tag}/{name}",
            "size": 0, "digest": "", "version": tag}


def latest_asset(repo: str, pattern: re.Pattern, client: httpx.Client, template: str | None = None) -> dict:
    try:
        r = client.get(f"https://api.github.com/repos/{repo}/releases/latest",
                       headers={"Accept": "application/vnd.github+json"})
        r.raise_for_status()
    except httpx.HTTPError:
        if template:
            return _web_latest(repo, template, client)
        raise
    rel = r.json()
    for a in rel.get("assets") or []:
        if pattern.match(a.get("name", "")):
            return {"name": a["name"], "url": a["browser_download_url"], "size": a.get("size") or 0,
                    "digest": a.get("digest") or "", "version": rel.get("tag_name") or ""}
    raise ToolError(f"no matching download in {repo}'s latest release ({rel.get('tag_name')})")


def download(asset: dict, client: httpx.Client) -> bytes:
    if asset["size"] > MAX_DOWNLOAD:
        raise ToolError(f"{asset['name']} is larger than {MAX_DOWNLOAD // 2**20} MB")
    chunks, size = [], 0
    with client.stream("GET", asset["url"]) as r:
        r.raise_for_status()
        for chunk in r.iter_bytes():
            size += len(chunk)
            if size > MAX_DOWNLOAD:
                raise ToolError(f"{asset['name']} is larger than {MAX_DOWNLOAD // 2**20} MB")
            chunks.append(chunk)
    data = b"".join(chunks)
    algo, _, want = asset["digest"].partition(":")
    if algo == "sha256" and want and hashlib.sha256(data).hexdigest() != want.lower():
        raise ToolError(f"{asset['name']} does not match the SHA-256 GitHub published for it; not installed")
    return data


def safe_extract(data: bytes, dest: Path, only: re.Pattern | None = None) -> list[Path]:
    """Extract a zip into dest, refusing absolute paths, '..', symlinks and oversize content."""
    dest = Path(dest).resolve()
    out, total = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            name = info.filename.replace("\\", "/")
            parts = PurePosixPath(name).parts
            if info.is_dir() or not parts:
                continue
            if name.startswith("/") or ".." in parts or ":" in parts[0]:
                raise ToolError(f"unsafe path in archive: {info.filename!r}")
            if (info.external_attr >> 16) & 0o170000 == 0o120000:     # symlink entry
                raise ToolError(f"archive contains a link: {info.filename!r}")
            if only and not only.search(name):
                continue
            total += info.file_size
            if total > MAX_EXTRACT:
                raise ToolError("archive unpacks to more than 800 MB")
            target = (dest / Path(*parts)).resolve()
            if dest not in target.parents:
                raise ToolError(f"unsafe path in archive: {info.filename!r}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(info) as src, open(target, "wb") as f:
                shutil.copyfileobj(src, f)
            out.append(target)
    return out


def _replace_dir(staging: Path, target: Path, what: str):
    """Swap a freshly extracted folder into place, keeping the old one if it can't be removed."""
    shutil.rmtree(target, ignore_errors=True)
    if target.exists():
        shutil.rmtree(staging, ignore_errors=True)
        raise ToolError(f"Could not replace the old {what} folder {target}: a file in it is in use or "
                        "locked (antivirus?). Close anything using it and try again.")
    staging.rename(target)


def install(tool: str, tools_dir: Path, client: httpx.Client | None = None,
            yara_dir: Path | None = None) -> dict:
    """Download and install one tool into tools_dir (YARA packs into yara_dir/packs).
    Returns {tool, version, path}."""
    if tool not in TOOLS:
        raise ValueError(f"unknown tool {tool!r}")
    spec = TOOLS[tool]
    tools_dir = Path(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    own = client is None
    client = client or httpx.Client(timeout=300, follow_redirects=True, headers={"User-Agent": UA})
    try:
        asset = latest_asset(spec["repo"], spec["asset"], client, spec.get("web"))
        if not spec["asset"].match(asset["name"]):
            raise ToolError(f"unexpected release asset {asset['name']!r}")
        data = download(asset, client)
    finally:
        if own:
            client.close()
    if tool == "capa":
        staging = tools_dir / ".capa-new"
        shutil.rmtree(staging, ignore_errors=True)
        files = safe_extract(data, staging, re.compile(r"(^|/)capa\.exe$", re.I))
        if not files:
            raise ToolError("capa.exe was not in the release archive")
        shutil.move(str(files[0]), str(tools_dir / "capa.exe"))
        shutil.rmtree(staging, ignore_errors=True)
        path = tools_dir / "capa.exe"
    elif tool == "hollows_hunter":
        if data[:2] != b"MZ":
            raise ToolError("the hollows_hunter download is not a Windows executable")
        path = tools_dir / "hollows_hunter64.exe"
        tmp = path.with_suffix(".new")
        tmp.write_bytes(data)
        tmp.replace(path)
    elif tool == "sigma":
        staging = tools_dir / ".sigma-new"
        shutil.rmtree(staging, ignore_errors=True)
        if not safe_extract(data, staging, re.compile(r"\.ya?ml$|LICENSE", re.I)):
            raise ToolError("no Sigma rules in the release archive")
        _replace_dir(staging, tools_dir / "sigma", "Sigma rules")
        path = tools_dir / "sigma"
    elif tool == "yara_forge":
        if not yara_dir:
            raise ValueError("yara_dir is required for YARA packs")
        # Read the rules straight out of the downloaded zip in memory and store them encoded.
        # Public rule packs quote real malware strings, and antivirus (Defender included)
        # quarantines a plain .yar the moment it touches the disk, even in a temp folder.
        target = Path(yara_dir) / "packs"
        target.mkdir(parents=True, exist_ok=True)
        written, total = [], 0
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                base = PurePosixPath(info.filename.replace("\\", "/")).name
                if info.is_dir() or not re.fullmatch(r"[\w.\-]+\.yara?", base, re.I):
                    continue
                total += info.file_size
                if total > MAX_EXTRACT:
                    raise ToolError("YARA Forge archive unpacks to more than 800 MB")
                with z.open(info) as src:
                    (target / (base + PACK_SUFFIX)).write_bytes(encode_pack(src.read()))
                written.append(base)
        if not written:
            raise ToolError("no YARA rules in the YARA Forge archive")
        path = target
    else:
        target = tools_dir / "fakenet"
        staging = tools_dir / ".fakenet-new"
        shutil.rmtree(staging, ignore_errors=True)
        safe_extract(data, staging)
        if not any(staging.glob("**/fakenet.exe")):
            shutil.rmtree(staging, ignore_errors=True)
            raise ToolError("fakenet.exe was not in the release archive")
        _replace_dir(staging, target, "FakeNet-NG")   # only once the new copy is known good
        path = next(target.glob("**/fakenet.exe")).parent
    (tools_dir / f"{tool}.version").write_text(asset["version"], encoding="utf-8")
    return {"tool": tool, "name": spec["name"], "version": asset["version"], "path": str(path)}


def installed_version(tool: str, tools_dir: Path) -> str | None:
    f = Path(tools_dir) / f"{tool}.version"
    return f.read_text(encoding="utf-8").strip() if f.exists() else None
