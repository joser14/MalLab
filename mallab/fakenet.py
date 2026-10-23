"""FakeNet-NG support for the "Simulated" network mode.

FakeNet-NG (https://github.com/mandiant/flare-fakenet-ng) runs inside the VM and diverts the
sample's traffic to local fake services: DNS answers every name with a fake address, HTTP(S)
returns canned pages, other ports get a generic listener. The sample "talks to its C2" and we
see what it asked for, while the traffic stays inside the VM.

FakeNet-NG lives under lab\\tools: the installer or Settings downloads the official release there
(tooling.py), or the analyst extracts one by hand. It only ever runs inside the VM. Its log comes
back from the VM, so it is untrusted text: size-capped, parsed with strict patterns, every value
length-limited.
"""

import re
import shutil
from pathlib import Path

MAX_LOG_BYTES = 16 * 2**20        # read at most this much of fakenet.log
LOG_EXCERPT = 256 * 1024          # kept in the report
MAX_ITEMS = 500

_HOST = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)*[A-Za-z0-9-]{1,63}"
_DNS_RE = re.compile(r"Received (A|AAAA|MX|TXT|CNAME|NS|PTR|SRV|ANY|SOA) request for domain '(" + _HOST + r")\.?'", re.I)
_REQ_RE = re.compile(r"\[\s*([^\]]{1,60}?)\s*\]\s+(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) (\S{1,2000}) HTTP/\d(?:\.\d)?")
_HOSTHDR_RE = re.compile(r"\[\s*([^\]]{1,60}?)\s*\]\s+Host:\s*(" + _HOST + r")(?::(\d{1,5}))?\s*$", re.I)
# Diverter, current releases (diverterbase.PidCommDest): "<name> (<pid>) requested TCP 203.0.113.9:443"
_CONN_RE = re.compile(r"([\w.\- ]{1,80}?) \((\d{1,7})\) requested (TCP|UDP) (\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
# Older releases log two lines: "from: 10.0.0.5:2179 -> 192.0.2.123:80" then "pid:  456 name: x.exe"
_FROM_RE = re.compile(r"\[\s*Diverter\s*\]\s+from:\s*[\d.]{7,15}:\d{1,5}\s*->\s*(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
_PIDNAME_RE = re.compile(r"\[\s*Diverter\s*\]\s+pid:\s*(\d{1,7})\s+name:\s*([\w.\- ]{1,80}?)\s*$")


def find(tools_dir: Path | None) -> Path | None:
    """The folder holding fakenet.exe under lab\\tools (as extracted from a release zip, e.g.
    tools\\fakenet3.5\\fakenet.exe), searched at most two levels deep."""
    if not tools_dir or not Path(tools_dir).is_dir():
        return None
    root = Path(tools_dir)
    for pattern in ("fakenet.exe", "*/fakenet.exe", "*/*/fakenet.exe"):
        for exe in sorted(root.glob(pattern)):
            if exe.is_file() and not exe.is_symlink():
                return exe.parent
    return None


MAX_STAGE_BYTES = 400 * 2**20
STAGED_CONFIG = "mallab.ini"

# FakeNet's stock config lets some traffic bypass the diverter and go out for real: blacklisted
# ports (default.ini: TCP 139; UDP 137, 138, 443 = QUIC, 1900, 5355) and process/host black- and
# whitelists, which the diverter reads both from [Diverter] and from each listener section. In
# the lab nothing may leave, so the staged copy removes all of them from every section; only DHCP
# (to the host's switch, which the host guard allows) stays undiverted so the VM keeps its
# address. The diverter only applies the port blacklists with RedirectAllTraffic on, and needs it
# on to divert at all, so it is forced on.
_DIVERTER_OVERRIDES = {"RedirectAllTraffic": "Yes", "BlackListPortsUDP": "67, 68"}
_DIVERTER_REMOVE = ("BlackListPortsTCP",)
_ANY_SECTION_REMOVE = ("ProcessBlackList", "HostBlackList", "ProcessWhiteList", "HostWhiteList")


def harden_config(text: str) -> str:
    import configparser
    import io
    cp = configparser.RawConfigParser(strict=False)
    cp.optionxform = str                                   # keep the file's own key spelling
    cp.read_string(text)
    sec = next((s for s in cp.sections() if s.lower() == "diverter"), None)
    if not sec:
        raise ValueError("FakeNet config has no [Diverter] section")
    drop_any = {x.lower() for x in _ANY_SECTION_REMOVE}
    drop_div = drop_any | {x.lower() for x in (*_DIVERTER_OVERRIDES, *_DIVERTER_REMOVE)}
    for s in cp.sections():
        for k in list(cp[s]):
            if k.lower() in (drop_div if s == sec else drop_any):
                cp.remove_option(s, k)
    for k, v in _DIVERTER_OVERRIDES.items():
        cp.set(sec, k, v)
    buf = io.StringIO()
    cp.write(buf)
    return buf.getvalue()


def stage(src: Path, dest: Path) -> str:
    """Copy the FakeNet folder into the VM's input folder with a hardened config next to the
    stock one. Returns the staged config's file name."""
    src, dest = Path(src), Path(dest)
    total = sum(f.stat().st_size for f in src.rglob("*") if f.is_file() and not f.is_symlink())
    if total > MAX_STAGE_BYTES:
        raise RuntimeError(f"The FakeNet-NG folder {src} is over {MAX_STAGE_BYTES // 2**20} MB; "
                           "point lab\\tools at a plain release folder.")
    cfg = src / "configs" / "default.ini"
    if not cfg.is_file():
        raise RuntimeError(f"FakeNet-NG's configs\\default.ini wasn't found in {src}; "
                           "extract the whole release, not just fakenet.exe.")
    try:
        hardened = harden_config(cfg.read_text(encoding="utf-8-sig", errors="replace"))
    except Exception as e:
        raise RuntimeError(f"Could not read FakeNet-NG's config ({e}); simulated mode needs it.") from e
    shutil.copytree(src, dest, symlinks=False, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("*.pcap", "*.log", STAGED_CONFIG))
    (dest / "configs" / STAGED_CONFIG).write_text(hardened, encoding="utf-8")
    return STAGED_CONFIG


def missing_message(tools_dir: Path | None) -> str:
    where = str(tools_dir) if tools_dir else r"lab\tools"
    return ("Simulated network needs FakeNet-NG, and it isn't in the lab's tools folder. Install it from "
            "Settings > Analysis tools (one click), or extract a release from "
            f"https://github.com/mandiant/flare-fakenet-ng/releases into {where}, then try again.")


def parse(text: str) -> dict:
    """Pull requested domains, URLs and raw connections out of a FakeNet-NG log."""
    text = str(text or "")
    domains, urls, conns = {}, {}, {}
    pending = {}                      # listener -> (method, target) awaiting its Host header
    last_from = None                  # older two-line Diverter format
    for line in text.splitlines():
        line = line[:4000]
        m = _DNS_RE.search(line)
        if m:
            domains.setdefault(m.group(2).lower().rstrip("."), None)
            continue
        m = _REQ_RE.search(line)
        if m:
            listener, method, target = m.group(1), m.group(2).upper(), m.group(3)
            if re.match(r"https?://", target, re.I):          # proxy-style absolute URL
                urls.setdefault(target[:2000], method)
            else:
                pending[listener] = (method, target)
            continue
        m = _HOSTHDR_RE.search(line)
        if m and m.group(1) in pending:
            method, target = pending.pop(m.group(1))
            host = m.group(2).lower()
            tls = bool(re.search(r"443|ssl|https", m.group(1), re.I))
            port = m.group(3)
            default = "443" if tls else "80"
            netloc = host + (f":{port}" if port and port != default else "")
            path = target if target.startswith("/") else "/" + target
            urls.setdefault(f"{'https' if tls else 'http'}://{netloc}{path}"[:2000], method)
            domains.setdefault(host, None)
            continue
        m = _CONN_RE.search(line)
        if m:
            key = f"{m.group(4)}:{m.group(5)}/{m.group(3).lower()}"
            conns.setdefault(key, {"process": m.group(1).strip()[:80], "pid": int(m.group(2)),
                                   "proto": m.group(3).upper(), "ip": m.group(4), "port": int(m.group(5))})
            continue
        m = _FROM_RE.search(line)
        if m:
            last_from = (m.group(1), int(m.group(2)))
            continue
        m = _PIDNAME_RE.search(line)
        if m and last_from:
            ip, port = last_from
            last_from = None
            conns.setdefault(f"{ip}:{port}/?", {"process": m.group(2).strip()[:80], "pid": int(m.group(1)),
                                                "proto": None, "ip": ip, "port": port})
    return {"domains": list(domains)[:MAX_ITEMS],
            "urls": [{"url": u, "method": meth} for u, meth in list(urls.items())[:MAX_ITEMS]],
            "connections": list(conns.values())[:MAX_ITEMS]}


def read_log(path: Path) -> dict | None:
    """Read and parse the VM's fakenet.log, refusing links and capping the size."""
    p = Path(path)
    try:
        if p.is_symlink() or not p.is_file():
            return None
        with open(p, "rb") as f:
            raw = f.read(MAX_LOG_BYTES + 1)
    except OSError:
        return None
    text = raw[:MAX_LOG_BYTES].decode("utf-8", errors="replace")
    out = parse(text)
    out["log"] = text[:LOG_EXCERPT]
    out["log_truncated"] = len(raw) > LOG_EXCERPT
    return out
