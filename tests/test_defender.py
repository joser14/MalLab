"""Defender exclusion toggle: fixed lab paths only, elevation is requested (never assumed),
a declined UAC prompt changes nothing, and status reflects only verified results.
The elevated PowerShell is mocked — these tests never touch real Defender settings."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import defender

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


@pytest.fixture(autouse=True)
def no_realtime_probe(monkeypatch):
    monkeypatch.setattr(defender, "_realtime", lambda: {"available": True, "realtime": True, "tamper": True})


def test_script_targets_only_lab_folders_and_parses(tmp_path):
    paths = defender.lab_paths(tmp_path / "it's lab")
    text = defender._script(paths, True, tmp_path / "state.json")
    assert text.count("Add-MpPreference") == 1 and "Remove-MpPreference" not in text
    assert "it''s lab" in text                                  # single quotes escaped
    # PowerShell's own parser must accept it (parse only, nothing executed).
    p = tmp_path / "s.ps1"; p.write_text(text, encoding="utf-8-sig")
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('{p}', [ref]$null, [ref]$e); $e.Count"],
                       capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == "0", r.stdout + r.stderr


def _fake_elevated(monkeypatch, tmp_path, state=None, rc=0, err=""):
    calls = []

    def run(cmd, timeout=30):
        calls.append(cmd)
        if state is not None:
            (tmp_path / "tools" / defender.STATE_FILE).write_text(json.dumps(state), encoding="utf-8")
        return subprocess.CompletedProcess([], rc, "", err)
    monkeypatch.setattr(defender, "_run_ps", run)
    return calls


def test_toggle_requests_uac_and_reports_verified_state(monkeypatch, tmp_path):
    paths = defender.lab_paths(tmp_path)
    calls = _fake_elevated(monkeypatch, tmp_path, {"ok": True, "excluded": True, "paths": paths, "time": 1})
    st = defender.set_excluded(tmp_path, tmp_path / "tools", True)
    assert "-Verb RunAs" in calls[0]                             # elevation is asked for
    assert st["excluded"] is True and st["verified"] == 1


def test_declined_prompt_changes_nothing(monkeypatch, tmp_path):
    _fake_elevated(monkeypatch, tmp_path, None, rc=1, err="This command cannot be run due to the error: The operation was canceled by the user.")
    with pytest.raises(RuntimeError, match="declined"):
        defender.set_excluded(tmp_path, tmp_path / "tools", True)
    assert defender.status(tmp_path, tmp_path / "tools")["excluded"] is None


def test_defender_refusal_is_surfaced(monkeypatch, tmp_path):
    _fake_elevated(monkeypatch, tmp_path, {"ok": False, "error": "Operation blocked by policy",
                                           "paths": defender.lab_paths(tmp_path), "time": 2})
    with pytest.raises(RuntimeError, match="blocked by policy"):
        defender.set_excluded(tmp_path, tmp_path / "tools", True)


def test_state_for_other_paths_is_ignored(tmp_path):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / defender.STATE_FILE).write_text(
        json.dumps({"ok": True, "excluded": True, "paths": ["C:\\elsewhere"], "time": 3}), encoding="utf-8")
    assert defender.status(tmp_path, tmp_path / "tools")["excluded"] is None
