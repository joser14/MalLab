"""Regression tests for the second review: VM output is untrusted, the monitor's own tooling isn't
reported as sample behaviour, SSRF / download caps, and input-handling bugs. Nothing is executed
and no network is used."""

import hashlib
import json
import sys
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server
from mallab import MalLab, sandbox, samples, signatures, sysmon
from mallab.service import defang, endpoint_host


# ---- 1. sandbox output is treated as hostile -----------------------------------------

def test_forged_artifact_names_are_dropped():
    rep = sandbox._sanitize({"screenshot": "..\\..\\Users\\me\\secret.txt", "pcap": "C:\\x.pcap",
                             "new_processes": {"pid": 1, "name": "a.exe"},   # one-element array flattened
                             "new_files": "C:\\one.exe", "network": [1, None, "x"]})
    assert "screenshot" not in rep and "pcap" not in rep
    assert rep["new_processes"] == [{"pid": 1, "name": "a.exe"}]
    assert rep["new_files"] == ["C:\\one.exe"] and rep["network"] == ["1", "x"]
    with pytest.raises(RuntimeError):
        sandbox._sanitize(["not", "a", "dict"])


def test_artifact_paths_cannot_escape_the_report_dir(tmp_path):
    lab = MalLab(tmp_path)
    s = lab.ingest(lab.store.create_case("t")["id"], b"MZ x", "x.exe")
    d = lab.store.report_dir(s["sha256"])
    (d / "screenshot-0123456789.png").write_bytes(b"png")
    from mallab.service import _SHOT_RE
    assert lab._artifact(s, "screenshot-0123456789.png", _SHOT_RE)
    (tmp_path / "secret.txt").write_text("nope")
    for bad in ("../../secret.txt", "..\\..\\secret.txt", "C:\\Windows\\win.ini", None, 5):
        assert lab._artifact(s, bad, _SHOT_RE) is None


def test_dropped_files_are_read_back_by_index_only(tmp_path):
    out = tmp_path / "output"
    (out / "dropped").mkdir(parents=True)
    (out / "dropped" / "000.bin").write_bytes(b"MZ payload")
    (out / "dropped" / "001.bin").write_bytes(b"")                      # empty: skipped
    report = {"dropped": [{"index": 0, "path": "C:\\Users\\x\\AppData\\evil.exe"},
                          {"index": 1, "path": "empty"},
                          {"index": "../../x", "path": "traversal"},
                          {"index": 99, "path": "out of range"}]}
    blobs = sandbox._collect_dropped(report, out)
    assert blobs == [("C:\\Users\\x\\AppData\\evil.exe", b"MZ payload")]
    assert report["dropped"][0]["sha256"] == hashlib.sha256(b"MZ payload").hexdigest()


def test_dropped_payloads_become_child_samples(tmp_path, monkeypatch):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    s = lab.ingest(cid, b"MZ parent", "parent.exe")

    def fake(*a, **kw):
        return {"verdict": "x", "detonated": True, "dropped": [{"path": "C:\\t\\child.exe", "size": 8, "sha256": "x"}],
                "_dropped_blobs": [("C:\\t\\child.exe", b"MZ child")]}
    monkeypatch.setattr("mallab.sandbox.detonate", fake)
    lab.detonate(s["id"])
    names = {x["filename"]: x["source"] for x in lab.store.list_samples(cid)}
    assert names["child.exe"] == "dropped by parent.exe"
    run = lab.store.list_runs(s["id"])[0]
    assert "_dropped_blobs" not in lab.dynamic_report(s["id"], run["id"])


# ---- 2/3. monitor's own tooling is not sample behaviour --------------------------------

def test_monitor_installs_tooling_before_the_baseline():
    m = sandbox.MONITOR_PS1
    assert m.index("Sysmon64.exe") < m.index("$before = Snapshot")
    assert m.index("pktmon start") < m.index("$before = Snapshot")
    assert "-PassThru" in m and "$report.launcher_pid" in m


def test_safe_net_failure_is_fail_closed():
    m = sandbox.MONITOR_PS1
    assert "LAN/host block could not be applied" in m
    assert "Set-DnsClientServerAddress" in m        # DNS still works with the private ranges blocked


def test_launcher_interpreter_is_not_a_lolbin_detection():
    dyn = {"launcher_pid": 10, "new_processes": [
        {"pid": 10, "name": "powershell.exe", "cmd": "powershell.exe -ExecutionPolicy Bypass -File sample.ps1"}]}
    names = {d["name"] for d in signatures.evaluate(None, dyn)["detections"]}
    assert "Living-off-the-land binary spawned" not in names
    assert "Suspicious PowerShell flags" not in names
    dyn["new_processes"].append({"pid": 11, "name": "cmd.exe", "cmd": "cmd /c vssadmin delete shadows /all"})
    names = {d["name"] for d in signatures.evaluate(None, dyn)["detections"]}
    assert {"Living-off-the-land binary spawned", "Recovery inhibition"} <= names


SYSMON_EVENTS = [
    {"id": 1, "time": "t", "data": {"ProcessId": "50", "ParentProcessId": "7", "Image": "C:\\Windows\\System32\\PktMon.exe",
                                     "ProcessGuid": "g50", "CommandLine": "pktmon stop"}},
    {"id": 1, "time": "t", "data": {"ProcessId": "10", "ParentProcessId": "7", "Image": "C:\\in\\sample.exe",
                                     "ProcessGuid": "g10", "CommandLine": "sample.exe"}},
    {"id": 1, "time": "t", "data": {"ProcessId": "11", "ParentProcessId": "10", "Image": "C:\\Windows\\cmd.exe",
                                     "ProcessGuid": "g11", "ParentProcessGuid": "g10", "CommandLine": "cmd /c whoami"}},
    {"id": 3, "time": "t", "data": {"ProcessId": "10", "Image": "C:\\in\\sample.exe", "DestinationIp": "203.0.113.5",
                                     "DestinationPort": "443", "DestinationHostname": ""}},
    {"id": 10, "time": "t", "data": {"SourceImage": "C:\\in\\sample.exe", "SourceProcessId": "10",
                                      "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010"}},
    {"id": 8, "time": "t", "data": {"SourceImage": "C:\\in\\sample.exe", "SourceProcessId": "10", "TargetImage": "C:\\Windows\\explorer.exe"}},
    {"id": 3, "time": "t", "data": {"ProcessId": "7", "Image": "powershell.exe", "DestinationIp": "1.1.1.1"}},  # monitor itself
]


def test_sysmon_parse_filters_monitor_and_keeps_short_lived_processes():
    beh = sysmon.parse(SYSMON_EVENTS, monitor_pid=7, launcher_pid=10)
    assert [p["name"] for p in beh["processes"]] == ["sample.exe", "cmd.exe"]
    assert beh["processes"][0]["launcher"] is True
    assert [n["dst_ip"] for n in beh["network"]] == ["203.0.113.5"]
    tree = sysmon.process_tree(beh)
    assert tree[0]["name"] == "sample.exe" and tree[0]["children"][0]["name"] == "cmd.exe"
    names = {d["name"] for d in signatures.evaluate(None, {"behavior": beh, "launcher_pid": 10})["detections"]}
    assert {"LSASS memory access", "Remote thread injection", "Connection to raw IP address",
            "System / account discovery"} <= names


def test_early_report_is_flagged():
    assert sandbox._summarize({"early_finish": True, "detonated": True}).startswith("WARNING")


# ---- 4/5. SSRF guard and download caps -------------------------------------------------

@pytest.mark.parametrize("addr,ok", [("8.8.8.8", True), ("10.0.0.1", False), ("100.64.1.1", False),
                                     ("127.0.0.1", False), ("::ffff:127.0.0.1", False), ("169.254.169.254", False),
                                     ("2606:4700:4700::1111", True), ("fe80::1%3", False)])
def test_public_address_check(addr, ok):
    assert samples._public(addr) is ok


def test_streamed_download_stops_at_the_cap(monkeypatch):
    monkeypatch.setattr(samples, "MAX_SAMPLE_BYTES", 10)
    big = httpx.Response(200, stream=httpx.ByteStream(b"x" * 50))
    with pytest.raises(RuntimeError, match="cap"):
        samples.SampleSource._read_capped(big)
    small = httpx.Response(200, stream=httpx.ByteStream(b"x" * 5))
    assert samples.SampleSource._read_capped(small) == b"x" * 5


def test_hash_and_filename_validation():
    src = samples.SampleSource(api_key="k")
    with pytest.raises(ValueError):
        src.fetch_by_hash("../../admin")
    assert samples._safe_name("..\\..\\evil.exe", "f") == "evil.exe"
    assert samples._safe_name("a%2F..%2Fb.dll", "f") == "b.dll"
    assert samples._safe_name("", "fallback.bin") == "fallback.bin"


# ---- 6. .NET assemblies aren't "packed" -------------------------------------------------

DOTNET_EXE = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe")


@pytest.mark.skipif(not DOTNET_EXE.exists(), reason="needs a .NET Framework binary")
def test_dotnet_binary_is_not_flagged_as_packed():
    pytest.importorskip("pefile")
    from mallab import static
    pe = static._pe_analysis(DOTNET_EXE)
    # 64-bit managed binaries often have no import table at all; the old "<= 2 imports" heuristic
    # called every one of them packed.
    assert pe["dotnet"] is True and pe["packed_hint"] is False


# ---- 8/9. IOC handling --------------------------------------------------------------

def test_endpoint_host_handles_ipv6_and_ports():
    assert endpoint_host("1.2.3.4:443 [Established]") == "1.2.3.4"
    assert endpoint_host("2001:db8::1:443 [Established]") == "2001:db8::1"
    assert endpoint_host("[2001:db8::1]:443") == "2001:db8::1"


def test_case_iocs_drop_private_and_windows_noise(tmp_path, monkeypatch):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    s = lab.ingest(cid, b"MZ http://evil.top/a 8.8.4.4", "x.exe")
    monkeypatch.setattr("mallab.sandbox.detonate", lambda *a, **k: {
        "verdict": "x", "network": ["172.20.0.1:53 [x]", "203.0.113.7:443 [x]", "2606:4700::1:443 [x]"],
        "dns": ["settings-win.data.microsoft.com", "c2.evil.top"]})
    lab.detonate(s["id"])
    io = lab.case_iocs(cid)
    assert "172.20.0.1" not in io["ips"] and "203.0.113.7" not in io["ips"]   # private / documentation range
    assert "2606:4700::1" in io["ips"] and "8.8.4.4" in io["ips"]
    assert "c2.evil.top" in io["domains"] and not any("microsoft" in d for d in io["domains"])


def test_ioc_exports(tmp_path):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("=cmd|' /C calc'!A0")["id"]
    lab.ingest(cid, b"MZ http://evil.top/gate 8.8.4.4", "x.exe")
    body, media, ext = lab.export_iocs(cid, "csv")
    assert "'=cmd" in body and ext == "csv"                    # spreadsheet formula injection neutralised
    stix = json.loads(lab.export_iocs(cid, "stix")[0])
    pats = {o["pattern"] for o in stix["objects"]}
    assert "[ipv4-addr:value = '8.8.4.4']" in pats and stix["type"] == "bundle"
    assert "hxxp://evil[.]top/gate" in lab.export_iocs(cid, "txt")[0]
    assert defang("https://a.b/c") == "hxxps://a[.]b/c"
    with pytest.raises(ValueError):
        lab.export_iocs(cid, "exe")


# ---- 10. server input handling ----------------------------------------------------------

@pytest.fixture
def client(tmp_path):
    return TestClient(server.LocalOnly(server.build_app(MalLab(tmp_path), server.Hub())),
                      base_url="http://127.0.0.1:7860", client=("127.0.0.1", 5000))


def test_malformed_bodies_do_not_500(client):
    cid = client.post("/api/lab/case", json={"name": "t"}).json()["id"]
    assert client.post(f"/api/lab/case/{cid}/update", json={"cid": "x", "notes": "n"}).json()["notes"] == "n"
    assert client.post(f"/api/lab/case/{cid}/update", content=b"not json").status_code == 200
    assert client.post("/api/lab/case", json=["a", "list"]).status_code == 200
    assert client.post("/api/lab/case/nope/update", json={"notes": "n"}).status_code == 404


def test_tampered_quarantine_is_refused(tmp_path):
    lab = MalLab(tmp_path)
    s = lab.ingest(lab.store.create_case("t")["id"], b"MZ original", "x.exe")
    lab.store.sample_path(s["sha256"]).write_bytes(b"MZ swapped")
    with pytest.raises(ValueError, match="integrity"):
        lab.run_static(s["id"])
    with pytest.raises(ValueError, match="integrity"):
        lab.store.read_sample(s["sha256"])
