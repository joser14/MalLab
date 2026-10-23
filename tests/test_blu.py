"""BLU MODE: blue-team host observation. The one safety-critical property is that this path NEVER
executes a sample, and that it is gated behind an explicit armed flag plus a typed confirmation.
No host observation is actually started here (that would run PowerShell); the gate and report
shaping are tested directly."""

import json
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server
from mallab import MalLab, hostmon

TOKEN = "I ACCEPT THE RISK"


def test_blu_observe_script_executes_nothing():
    # The PowerShell that runs on the host must not launch, open or invoke the sample in any way.
    ps = hostmon.OBSERVE_PS1
    for forbidden in ("Start-Process", "Invoke-Item", "Invoke-Expression", "& $sample",
                      "-Detonate", "rundll32", "cmd.exe /c", "Start-Job"):
        assert forbidden not in ps, forbidden
    assert "$report.detonated = $false" in ps or "host_observation = $true" in ps


def test_blu_report_is_never_marked_executed():
    rep = hostmon._sanitize({"host_observation": True, "detonated": True, "new_processes": {"pid": 1, "name": "x.exe"}})
    assert rep["detonated"] is False                       # forced off no matter what the host JSON said
    assert rep["new_processes"] == [{"pid": 1, "name": "x.exe"}]
    assert hostmon._summarize({"new_processes": [1, 2], "new_runkeys": ["r"]}).startswith("host observation:")


def test_blu_gate_requires_armed_and_confirmation(tmp_path):
    lab = MalLab(tmp_path)
    s = lab.ingest(lab.store.create_case("t")["id"], b"MZ", "x.exe")
    assert lab.blu_status()["armed"] is False
    with pytest.raises(RuntimeError, match="not armed"):
        lab.host_observe(s["id"], seconds=10, confirm=TOKEN)
    with pytest.raises(ValueError, match="type exactly"):
        lab.set_blu_mode(True, "please")
    assert lab.set_blu_mode(True, "  i accept the risk  ")["armed"] is True   # case/space tolerant
    with pytest.raises(ValueError, match="confirm"):
        lab.host_observe(s["id"], seconds=10, confirm="no")
    assert lab.set_blu_mode(False)["armed"] is False
    assert not (tmp_path / "blu-mode.on").exists()


def test_blu_routes_enforce_the_gate(tmp_path):
    c = TestClient(server.LocalOnly(server.build_app(MalLab(tmp_path), server.Hub())),
                   base_url="http://127.0.0.1:7860", client=("127.0.0.1", 5000))
    cid = c.post("/api/lab/case", json={"name": "t"}).json()["id"]
    sid = c.post(f"/api/lab/case/{cid}/upload", content=b"MZ", headers={"X-Filename": "x.exe"}).json()["samples"][0]["id"]
    assert "blu" in c.get("/api/lab/state").json()
    # Not armed: observe is refused.
    assert c.post(f"/api/lab/sample/{sid}/observe", json={"seconds": 10, "confirm": TOKEN}).json()["error"]
    # Arm needs the phrase.
    assert c.post("/api/lab/blu/arm", json={"arm": True, "confirm": "x"}).json()["error"]
    assert c.post("/api/lab/blu/arm", json={"arm": True, "confirm": TOKEN}).json()["armed"] is True
    # Armed but wrong confirm on observe: still refused (nothing is started).
    assert c.post(f"/api/lab/sample/{sid}/observe", json={"seconds": 10, "confirm": "nope"}).status_code == 400


def test_host_report_renders_through_signatures():
    # A host-observation report flows through the same signature engine as a detonation.
    from mallab import signatures, sysmon
    rep = {"host_observation": True, "detonated": False, "network_mode": "host",
           "new_runkeys": [r"HKCU:\...\Run :: evil = C:\x.exe"], "new_processes": [], "new_files": []}
    rep["behavior"] = sysmon.parse([], None, None)
    names = {d["name"] for d in signatures.evaluate(None, rep)["detections"]}
    assert "Persistence via Run key" in names
    # Evasion flag never fires on host observation (nothing was executed by MalLab).
    assert "Sandbox evasion suspected" not in names
