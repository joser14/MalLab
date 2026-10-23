"""Tool downloads used by the installer and Settings: official release asset only, SHA-256 checked,
safe extraction. GitHub is mocked; nothing is downloaded or run."""

import hashlib
import io
import sys
import zipfile
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab, fakenet, static, tooling


def _zip(files: dict, links: tuple = ()) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
        for name in links:
            info = zipfile.ZipInfo(name)
            info.external_attr = (0o120777 << 16)
            z.writestr(info, "target")
    return buf.getvalue()


def _client(repo: str, asset_name: str, blob: bytes, digest: str | None = None):
    digest = digest if digest is not None else "sha256:" + hashlib.sha256(blob).hexdigest()

    def handler(req):
        if req.url.path == f"/repos/{repo}/releases/latest":
            return httpx.Response(200, json={"tag_name": "v9.9.9", "assets": [
                {"name": "source.tar.gz", "browser_download_url": "https://dl/src", "size": 1},
                {"name": asset_name, "browser_download_url": "https://dl/asset", "size": len(blob), "digest": digest}]})
        if str(req.url) == "https://dl/asset":
            return httpx.Response(200, content=blob)
        return httpx.Response(404)
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_capa_install(tmp_path):
    blob = _zip({"capa.exe": b"MZ capa", "README.txt": b"x"})
    res = tooling.install("capa", tmp_path, _client("mandiant/capa", "capa-v9.9.9-windows.zip", blob))
    assert (tmp_path / "capa.exe").read_bytes() == b"MZ capa" and res["version"] == "v9.9.9"
    assert static.find_capa(tmp_path) == str(tmp_path / "capa.exe")
    assert tooling.installed_version("capa", tmp_path) == "v9.9.9"
    assert not (tmp_path / "README.txt").exists()


def test_fakenet_install_replaces_old_copy(tmp_path):
    (tmp_path / "fakenet" / "old").mkdir(parents=True)
    blob = _zip({"fakenet3.5/fakenet.exe": b"MZ", "fakenet3.5/configs/default.ini": b"[Diverter]\n"})
    tooling.install("fakenet", tmp_path, _client("mandiant/flare-fakenet-ng", "fakenet3.5.zip", blob))
    assert fakenet.find(tmp_path) == tmp_path / "fakenet" / "fakenet3.5"
    assert not (tmp_path / "fakenet" / "old").exists()


def test_digest_mismatch_is_refused(tmp_path):
    blob = _zip({"capa.exe": b"MZ"})
    with pytest.raises(tooling.ToolError, match="SHA-256"):
        tooling.install("capa", tmp_path, _client("mandiant/capa", "capa-v1-windows.zip", blob, "sha256:" + "0" * 64))
    assert not (tmp_path / "capa.exe").exists()


@pytest.mark.parametrize("files,links", [({"../evil.exe": b"x"}, ()), ({"/abs/evil.exe": b"x"}, ()),
                                         ({"C:/evil.exe": b"x"}, ()), ({"ok.txt": b"x"}, ("link",))])
def test_unsafe_archives_are_refused(tmp_path, files, links):
    with pytest.raises(tooling.ToolError):
        tooling.safe_extract(_zip(files, links), tmp_path / "out")
    assert not (tmp_path / "evil.exe").exists()


def test_missing_asset_and_unknown_tool(tmp_path):
    with pytest.raises(tooling.ToolError, match="no matching"):
        tooling.install("capa", tmp_path, _client("mandiant/capa", "capa-v1-linux.zip", b"x"))
    with pytest.raises(ValueError):
        tooling.install("mimikatz", tmp_path)


def test_string_minhash_finds_variants(tmp_path):
    base = [f"config_value_{i}_xyz" for i in range(60)]
    a = static.strings_minhash(base)
    b = static.strings_minhash(base[:50] + [f"new_string_{i}_abc" for i in range(10)])
    c = static.strings_minhash([f"unrelated_text_{i}_qq" for i in range(60)])
    assert static.minhash_similarity(a, b) > 0.5 > static.minhash_similarity(a, c)
    assert static.strings_minhash(["short"]) is None
    lab = MalLab(tmp_path)
    blob = "\x00".join(base).encode()
    x = lab.ingest(lab.store.create_case("a")["id"], b"MZ" + blob, "a.exe")
    lab.ingest(lab.store.create_case("b")["id"], b"MZ\x01" + blob + b"\x00extra_trailing_string", "b.exe")
    rel = lab.related_samples(x["id"])
    assert rel and any("strings shared" in w for w in rel[0]["why"])


def test_ambiguous_aliases_do_not_merge_groups():
    from mallab import actors
    existing = [{"id": "1", "name": "Group One", "aliases": "Shared Name", "families": "", "techniques": ""},
                {"id": "2", "name": "Group Two", "aliases": "Other Name", "families": "", "techniques": ""}]
    misp = [{"name": "Vendor Label", "aliases": ["Shared Name", "Other Name"], "country": "XX", "motivation": "", "description": ""}]
    updates, creates = actors.merge_catalog(existing, [], misp, {})
    assert not updates and [c["name"] for c in creates] == ["Vendor Label"]
    misp = [{"name": "Vendor Label", "aliases": ["Shared Name"], "country": "XX", "motivation": "", "description": ""}]
    updates, creates = actors.merge_catalog(existing, [], misp, {})
    assert updates["1"]["country"] == "XX" and not creates


def test_defer_flag_records_pending(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Installer"))
    import desktop
    monkeypatch.setattr(sys, "argv", ["MalLab.exe", "--lab-root", str(tmp_path / "lab"), "--defer", "host network guard"])
    assert desktop.main() == 0
    assert MalLab(tmp_path / "lab").setup_pending() == ["host network guard"]


def test_setup_pending_round_trip(tmp_path):
    lab = MalLab(tmp_path)
    assert lab.setup_pending() == []
    (tmp_path / "setup-pending.txt").write_text("capa\nFakeNet-NG\n", encoding="utf-8")
    assert lab.state()["setup_pending"] == ["capa", "FakeNet-NG"]
    lab.clear_setup_pending()
    assert lab.setup_pending() == []


def test_desktop_setup_flags_record_failures(tmp_path, monkeypatch):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Installer"))
    import desktop
    from mallab import service
    monkeypatch.setattr(service.MalLab, "setup_tool", lambda self, t: (_ for _ in ()).throw(RuntimeError("offline")))
    monkeypatch.setattr(service.MalLab, "import_actor_catalog", lambda self: {"created": 1})
    monkeypatch.setattr(sys, "argv", ["MalLab.exe", "--lab-root", str(tmp_path / "lab"), "--setup-capa", "--import-actors"])
    assert desktop.main() == 1                       # capa failed, actors still ran
    assert (tmp_path / "lab" / "setup-pending.txt").read_text(encoding="utf-8").split() == ["capa"]


def test_installer_detects_existing_installs_and_uninstall_restores_windows():
    # The installer reads these exact markers to show a tool as already installed; the app must
    # keep writing them where the installer looks.
    iss = (Path(__file__).resolve().parent.parent / "Installer" / "MalLab.iss").read_text(encoding="utf-8")
    for marker in ("Sysmon64.exe", "capa.exe", "fakenet.version", "hollows_hunter64.exe", "sigma.version",
                   "yara_forge.version", "actors.version"):
        assert marker in iss, marker
    # Upgrades replace the old program files; uninstall undoes every system change MalLab makes.
    assert '[InstallDelete]' in iss and '{app}\\_internal' in iss
    assert "Remove-MpPreference" in iss and "Remove-NetFirewallRule" in iss
    assert "defender-state.json" in iss and "netguard-state.json" in iss
    assert "EnabledWindowsSandbox" in iss and "/disable-feature" in iss
