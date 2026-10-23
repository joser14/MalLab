"""Unpack password-protected sample archives (vx-underground, MalwareBazaar, etc.) straight
into memory so each member can be quarantined. Nothing is extracted to disk here, and members
are never written under their original names — ingest stores each one by hash as sample.bin.

Supported: .zip (ZipCrypto via zipfile; AES via pyzipper) and .7z (via py7zr, incl. AES).
Malware-sharing convention is the password "infected"; a few other common ones are tried too.

Guards: member count, per-member size and total size are capped before and while reading, so a
zip bomb fails fast instead of filling memory.
"""

import io
import zipfile

from .samples import MAX_SAMPLE_BYTES

COMMON_PASSWORDS = ("infected", "malware", "virus", "")
MAX_MEMBERS = 200
MAX_TOTAL_BYTES = 1024 * 1024 * 1024  # 1 GB unpacked, across all members

ZIP_MAGIC = (b"PK\x03\x04", b"PK\x05\x06")
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"


class ArchiveError(RuntimeError):
    pass


def kind(data: bytes) -> str | None:
    if data.startswith(SEVENZ_MAGIC):
        return "7z"
    if data.startswith(ZIP_MAGIC):
        return "zip"
    return None


def _passwords(password: str | None) -> list[str]:
    out = [password] if password else []
    return out + [p for p in COMMON_PASSWORDS if p not in out]


def _check_sizes(sizes: list[int]):
    if len(sizes) > MAX_MEMBERS:
        raise ArchiveError(f"archive has {len(sizes)} files (limit {MAX_MEMBERS})")
    for s in sizes:
        if s > MAX_SAMPLE_BYTES:
            raise ArchiveError(f"a member unpacks to {s // (1024 * 1024)} MB (limit "
                               f"{MAX_SAMPLE_BYTES // (1024 * 1024)} MB)")
    if sum(sizes) > MAX_TOTAL_BYTES:
        raise ArchiveError("archive unpacks to more than 1 GB")


def _unzip(data: bytes, passwords: list[str]) -> tuple[list[tuple[str, bytes]], str | None]:
    try:
        import pyzipper
        opener = pyzipper.AESZipFile
    except ImportError:
        opener = zipfile.ZipFile
    with opener(io.BytesIO(data)) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]
        _check_sizes([i.file_size for i in infos])
        encrypted = any(i.flag_bits & 0x1 for i in infos)
        for pw in (passwords if encrypted else [None]):
            try:
                out = []
                for i in infos:
                    with z.open(i, pwd=pw.encode() if pw is not None else None) as f:
                        blob = f.read(MAX_SAMPLE_BYTES + 1)
                    if len(blob) > MAX_SAMPLE_BYTES:
                        raise ArchiveError(f"{i.filename} is larger than its header claims")
                    out.append((i.filename, blob))
                return out, pw
            except ArchiveError:
                raise
            except NotImplementedError as e:  # AES zip without pyzipper
                raise ArchiveError("this zip uses AES encryption: pip install pyzipper") from e
            except (RuntimeError, zipfile.BadZipFile, ValueError) as e:
                if "password" in str(e).lower() or "bad" in str(e).lower() or "crc" in str(e).lower():
                    continue
                raise
    raise ArchiveError("wrong password")


def _un7z(data: bytes, passwords: list[str]) -> tuple[list[tuple[str, bytes]], str | None]:
    try:
        import py7zr
    except ImportError as e:
        raise ArchiveError("7z support needs py7zr: pip install py7zr") from e
    from py7zr.io import BytesIOFactory

    def read(pw):
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r", password=pw,
                                max_extract_size=MAX_TOTAL_BYTES) as z:
            infos = [i for i in z.list() if not i.is_directory]
            _check_sizes([i.uncompressed or 0 for i in infos])
            encrypted = z.needs_password()
            if encrypted and pw is None:
                return None
            # In-memory extraction; each buffer stops filling past the cap, so oversize is detectable.
            factory = BytesIOFactory(limit=MAX_SAMPLE_BYTES + 1)
            z.extractall(factory=factory)
        out = []
        for name, f in sorted(factory.products.items()):
            f.seek(0)
            blob = f.read()
            if len(blob) > MAX_SAMPLE_BYTES:
                raise ArchiveError(f"{name} is larger than its header claims")
            out.append((name, blob))
        return out

    try:
        out = read(None)
    except ArchiveError:
        raise
    except py7zr.exceptions.PasswordRequired:
        out = None
    except Exception as e:
        raise ArchiveError(f"could not read 7z: {type(e).__name__}: {e}") from e
    if out is not None:
        return out, None
    for pw in passwords:
        if not pw:
            continue
        try:
            return read(pw), pw
        except ArchiveError:
            raise
        except Exception:  # a wrong password surfaces as CRC / LZMA / bad-header errors
            continue
    raise ArchiveError("wrong password")


def unpack(data: bytes, password: str | None = None) -> dict:
    """Return {"kind", "password", "members": [(name, bytes), ...]}. Raises ArchiveError."""
    k = kind(data)
    if not k:
        raise ArchiveError("not a zip or 7z archive")
    pws = _passwords(password)
    members, used = (_un7z if k == "7z" else _unzip)(data, pws)
    members = [(n.replace("\\", "/").split("/")[-1] or "member.bin", b) for n, b in members if b]
    if not members:
        raise ArchiveError("archive is empty")
    return {"kind": k, "password": used, "members": members}
