"""Archive unpacking: vx-underground-style password-protected 7z/zip are unpacked in memory,
each member quarantined by hash; wrong passwords and oversize archives fail cleanly.
All archive contents here are harmless text blobs. Nothing is executed."""

import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

py7zr = pytest.importorskip("py7zr")
pyzipper = pytest.importorskip("pyzipper")

from mallab import MalLab, archives

A = b"MZ harmless member one http://bad.example/a"
B = b"plain readme text"


def make_7z(password=None, header_encryption=False, files=None):
    buf = io.BytesIO()
    with py7zr.SevenZipFile(buf, "w", password=password, header_encryption=header_encryption) as z:
        for name, data in (files or {"dir/a.exe": A, "b.txt": B}).items():
            z.writestr(data, name)
    return buf.getvalue()


def make_zip(password=None):
    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", encryption=pyzipper.WZ_AES if password else None) as z:
        if password:
            z.setpassword(password.encode())
        z.writestr("nested/dir/a.exe", A)
    return buf.getvalue()


@pytest.mark.parametrize("data", [
    make_7z(), make_7z("infected"), make_7z("infected", header_encryption=True),
    make_zip(), make_zip("infected"),
], ids=["7z", "7z-infected", "7z-encrypted-headers", "zip", "zip-aes-infected"])
def test_unpacks_common_formats(data):
    res = archives.unpack(data)
    members = dict(res["members"])
    assert members["a.exe"] == A                       # path stripped to the base name
    if res["kind"] == "7z":
        assert members["b.txt"] == B


def test_custom_password_and_wrong_password():
    data = make_7z("s3cret")
    with pytest.raises(archives.ArchiveError, match="wrong password"):
        archives.unpack(data)
    assert archives.unpack(data, "s3cret")["password"] == "s3cret"


def test_member_count_cap(monkeypatch):
    monkeypatch.setattr(archives, "MAX_MEMBERS", 2)
    with pytest.raises(archives.ArchiveError, match="limit 2"):
        archives.unpack(make_7z(files={f"f{i}": b"x%d" % i for i in range(3)}))


def test_member_size_cap(monkeypatch):
    monkeypatch.setattr(archives, "MAX_SAMPLE_BYTES", 10)
    with pytest.raises(archives.ArchiveError):
        archives.unpack(make_zip())


def test_non_archive_is_ingested_as_is(tmp_path):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    got = lab.ingest_any(cid, A, "a.exe")
    assert got["archive"] is None and len(got["samples"]) == 1


def test_service_quarantines_each_member(tmp_path):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    got = lab.ingest_any(cid, make_7z("infected", header_encryption=True), "pack.7z", "upload")
    assert got["archive"]["count"] == 2 and got["archive"]["password"] == "infected"
    names = {s["filename"] for s in got["samples"]}
    assert names == {"a.exe", "b.txt"}
    for s in got["samples"]:
        stored = lab.store.sample_path(s["sha256"])
        assert stored.name == "sample.bin" and s["source"] == "upload ← pack.7z"
    assert got["samples"][0]["risk"] >= got["samples"][1]["risk"]   # riskiest first


def test_unpack_off_keeps_archive_whole(tmp_path):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    got = lab.ingest_any(cid, make_7z("infected"), "pack.7z", unpack=False)
    assert got["archive"] is None and got["samples"][0]["filename"] == "pack.7z"


def test_wrong_password_message_is_actionable(tmp_path):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    with pytest.raises(ValueError, match="wrong password.*'infected'"):
        lab.ingest_any(cid, make_7z("s3cret"), "pack.7z")


def test_quick_detonate_static_only_picks_riskiest(tmp_path):
    lab = MalLab(tmp_path)
    res = lab.quick_detonate(make_7z("infected"), "pack.7z", do_detonate=False)
    assert res["archive"]["count"] == 2 and len(res["siblings"]) == 1
    assert res["sample"]["risk"] >= res["siblings"][0]["risk"]
