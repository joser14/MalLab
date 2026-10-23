"""Download the lab's optional analysis tools from their official GitHub releases into lab\\tools.

    capa        Mandiant capability detection        https://github.com/mandiant/capa
    FakeNet-NG  Mandiant network simulation (in-VM)  https://github.com/mandiant/flare-fakenet-ng

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
    "capa": {"repo": "mandiant/capa", "asset": re.compile(r"^capa-v[\d.]+-windows\.zip$", re.I),
             "name": "capa"},
    "fakenet": {"repo": "mandiant/flare-fakenet-ng", "asset": re.compile(r"^fakenet[\w.\-]*\.zip$", re.I),
                "name": "FakeNet-NG"},
}


class ToolError(RuntimeError):
    pass


def latest_asset(repo: str, pattern: re.Pattern, client: httpx.Client) -> dict:
    r = client.get(f"https://api.github.com/repos/{repo}/releases/latest",
                   headers={"Accept": "application/vnd.github+json"})
    r.raise_for_status()
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


def install(tool: str, tools_dir: Path, client: httpx.Client | None = None) -> dict:
    """Download and install one tool into tools_dir. Returns {tool, version, path}."""
    if tool not in TOOLS:
        raise ValueError(f"unknown tool {tool!r}")
    spec = TOOLS[tool]
    tools_dir = Path(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    own = client is None
    client = client or httpx.Client(timeout=300, follow_redirects=True, headers={"User-Agent": UA})
    try:
        asset = latest_asset(spec["repo"], spec["asset"], client)
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
    else:
        target = tools_dir / "fakenet"
        staging = tools_dir / ".fakenet-new"
        shutil.rmtree(staging, ignore_errors=True)
        safe_extract(data, staging)
        if not any(staging.glob("**/fakenet.exe")):
            shutil.rmtree(staging, ignore_errors=True)
            raise ToolError("fakenet.exe was not in the release archive")
        # Replace an older copy only once the new one is good.
        shutil.rmtree(target, ignore_errors=True)
        if target.exists():
            shutil.rmtree(staging, ignore_errors=True)
            raise ToolError(f"Could not replace the old FakeNet-NG folder {target}: a file in it is in use or "
                            "locked (antivirus?). Close anything using it and try again.")
        staging.rename(target)
        path = next(target.glob("**/fakenet.exe")).parent
    (tools_dir / f"{tool}.version").write_text(asset["version"], encoding="utf-8")
    return {"tool": tool, "name": spec["name"], "version": asset["version"], "path": str(path)}


def installed_version(tool: str, tools_dir: Path) -> str | None:
    f = Path(tools_dir) / f"{tool}.version"
    return f.read_text(encoding="utf-8").strip() if f.exists() else None
