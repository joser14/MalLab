"""Sample acquisition from VX Underground's repository (virus.exchange, an MWDB instance)
and by direct hash/URL. Everything lands in quarantine as raw bytes named by hash — never
with the original extension, and never executed on download.

Credentials come from the environment, not the code:
    VX_API_URL    default https://virus.exchange/api   (MWDB-compatible)
    VX_API_KEY    your virus.exchange / MWDB API token

Without a key the client can still fetch from any direct URL you paste (e.g. a mirror link).
"""

import hashlib
import ipaddress
import os
import re
import socket
from urllib.parse import unquote, urlsplit

import httpx

DEFAULT_API = os.environ.get("VX_API_URL", "https://virus.exchange/api").rstrip("/")
MAX_SAMPLE_BYTES = 200 * 1024 * 1024  # 200 MB cap


HASH_RE = re.compile(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{128}")


def _public(addr: str) -> bool:
    """Only globally routable addresses. is_global also rejects CGNAT (100.64/10), benchmark and
    documentation ranges that is_private misses; IPv4-mapped IPv6 is unwrapped first."""
    ip = ipaddress.ip_address(addr.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _check_public_url(url: str):
    """Block fetches aimed at this machine or the local network (SSRF guard)."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("only http(s) URLs are allowed")
    try:
        infos = socket.getaddrinfo(parts.hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"could not resolve {parts.hostname}") from e
    for info in infos:
        if not _public(info[4][0]):
            raise ValueError("URLs on this computer or the local network are blocked")


def _check_peer(r: httpx.Response):
    """Re-check the address we actually connected to: DNS can answer differently between the
    pre-check and the connection (DNS rebinding)."""
    stream = r.extensions.get("network_stream")
    peer = stream.get_extra_info("server_addr") if stream else None
    if peer and not _public(peer[0]):
        raise ValueError("URL resolved to this computer or the local network; blocked")


def _safe_name(name: str, fallback: str) -> str:
    """A server-supplied filename is only a label: strip paths and control characters."""
    name = unquote(name).replace("\\", "/").rsplit("/", 1)[-1]
    name = re.sub(r"[\x00-\x1f<>:\"|?*]", "_", name).strip(" .")[:200]
    return name or fallback


class SampleSource:
    def __init__(self, api_url: str | None = None, api_key: str | None = None):
        self.api_url = (api_url or DEFAULT_API).rstrip("/")
        self.api_key = api_key or os.environ.get("VX_API_KEY", "")

    def configured(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict:
        h = {"User-Agent": "mallab/1.0", "Accept": "application/json"}
        if self.api_key:
            h["Authorization"] = f"Bearer {self.api_key}"
        return h

    def search(self, query: str, limit: int = 25) -> list[dict]:
        """Search the MWDB catalog. Returns metadata only (no bytes downloaded)."""
        if not self.configured():
            raise RuntimeError("Set VX_API_KEY (and optionally VX_API_URL) to search the repository.")
        with httpx.Client(timeout=30, headers=self._headers()) as c:
            r = c.get(f"{self.api_url}/file", params={"query": query, "pager_limit": min(limit, 100)})
            r.raise_for_status()
            data = r.json()
        files = data.get("files", data if isinstance(data, list) else [])
        return [{"sha256": f.get("sha256") or f.get("id"),
                 "name": (f.get("file_name") or f.get("name") or f.get("sha256", ""))[:120],
                 "size": f.get("file_size") or f.get("size"),
                 "type": f.get("file_type") or f.get("type"),
                 "tags": [t.get("tag") if isinstance(t, dict) else t for t in (f.get("tags") or [])]}
                for f in files][:limit]

    def fetch_by_hash(self, sha256: str) -> tuple[bytes, str]:
        """Download one sample by hash from the MWDB repository."""
        if not self.configured():
            raise RuntimeError("Set VX_API_KEY to download from the repository, or paste a direct URL instead.")
        sha256 = sha256.strip().lower()
        if not HASH_RE.fullmatch(sha256):   # it goes into the URL path
            raise ValueError("not a valid MD5 / SHA-1 / SHA-256 / SHA-512 hex hash")
        with httpx.Client(timeout=120, headers=self._headers(), follow_redirects=True) as c:
            # MWDB: request a short-lived download token, then GET the bytes.
            url, params = f"{self.api_url}/file/{sha256}/download", None
            r = c.post(url)
            if r.status_code == 200 and r.headers.get("content-type", "").startswith("application/json"):
                params = {"token": r.json().get("token")}
            with c.stream("GET", url, params=params) as r:
                r.raise_for_status()
                data = self._read_capped(r)
                cd = r.headers.get("content-disposition", "")
        name = f"{sha256}.bin"
        if "filename=" in cd:
            name = _safe_name(cd.split("filename=", 1)[1].strip('"; '), name)
        return data, name

    def fetch_url(self, url: str) -> tuple[bytes, str]:
        """Download a sample from an arbitrary http(s) URL (a mirror/share link).
        Redirects are followed by hand so every hop is re-checked against the SSRF guard."""
        _check_public_url(url)
        with httpx.Client(timeout=120, headers={"User-Agent": "mallab/1.0"},
                          follow_redirects=False) as c:
            for _ in range(6):
                with c.stream("GET", url) as r:
                    _check_peer(r)
                    if r.is_redirect:
                        url = str(r.url.join(r.headers["location"]))
                        _check_public_url(url)
                        continue
                    r.raise_for_status()
                    data = self._read_capped(r)
                    ctype = r.headers.get("content-type", "")
                    break
            else:
                raise RuntimeError("too many redirects")
        if "text/html" in ctype and (b"Just a moment" in data[:4096] or b"cf-chl" in data[:4096]):
            raise RuntimeError(
                "This link is behind Cloudflare's bot protection and can't be fetched directly. "
                "Open it in your browser, let the page load, then paste the final file-download URL.")
        name = _safe_name(urlsplit(url).path.rstrip("/").split("/")[-1], "download.bin")
        return data, name

    @staticmethod
    def _read_capped(r: httpx.Response) -> bytes:
        """Read a streamed body, stopping as soon as it passes the cap (never buffers more)."""
        if int(r.headers.get("content-length") or 0) > MAX_SAMPLE_BYTES:
            raise RuntimeError(f"sample exceeds {MAX_SAMPLE_BYTES // (1024*1024)} MB cap")
        chunks, size = [], 0
        for chunk in r.iter_bytes():
            size += len(chunk)
            if size > MAX_SAMPLE_BYTES:
                raise RuntimeError(f"sample exceeds {MAX_SAMPLE_BYTES // (1024*1024)} MB cap")
            chunks.append(chunk)
        return b"".join(chunks)


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
