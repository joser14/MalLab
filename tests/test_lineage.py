"""Regressions from the first real detonation on Windows: only the sample's process lineage counts
as its behaviour, Windows' own background activity in the VM doesn't, and dropped files are
collected once. No VM is started."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab, sandbox, signatures, sysmon

MON, LAUNCH = 7, 10


def ev(eid, **d):
    return {"id": eid, "time": "t", "data": {k: str(v) for k, v in d.items()}}


# What the real run looked like: the launcher (cmd), its children, plus Windows doing its own thing.
EVENTS = [
    ev(1, ProcessId=LAUNCH, ParentProcessId=MON, ProcessGuid="gL", Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c sample.bat"),
    ev(1, ProcessId=20, ParentProcessId=LAUNCH, ProcessGuid="gR", ParentProcessGuid="gL", Image=r"C:\Windows\System32\reg.exe", CommandLine="reg add ...Run"),
    ev(1, ProcessId=21, ParentProcessId=LAUNCH, ProcessGuid="gW", ParentProcessGuid="gL", Image=r"C:\Windows\System32\whoami.exe", CommandLine="whoami"),
    ev(1, ProcessId=30, ParentProcessId=600, ProcessGuid="gS", ParentProcessGuid="gSvc", Image=r"C:\Windows\System32\smartscreen.exe", CommandLine="smartscreen.exe -Embedding"),
    ev(10, SourceImage=r"C:\Windows\System32\svchost.exe", SourceProcessGUID="gSvc", TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1000"),
    ev(11, ProcessId=LAUNCH, ProcessGuid="gL", Image="cmd.exe", TargetFilename=r"C:\Users\WDAGUtilityAccount\AppData\Roaming\mallab-test-copy.bat"),
    ev(11, ProcessId=31, ProcessGuid="gEdge", Image="msedgewebview2.exe",
       TargetFilename=r"C:\Users\WDAGUtilityAccount\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Preferences"),
    ev(13, ProcessId=20, ProcessGuid="gR", Image="reg.exe", EventType="SetValue",
       TargetObject=r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run\MalLabTest", Details="x.bat"),
]


def test_only_the_lineage_is_the_samples_behaviour():
    beh = sysmon.parse(EVENTS, MON, LAUNCH)
    assert beh["lineage_known"] is True
    assert [p["name"] for p in beh["processes"]] == ["cmd.exe", "reg.exe", "whoami.exe"]
    assert beh["lsass_access"] == []                       # svchost touching LSASS is Windows, not the sample
    assert [p["name"] for p in beh["background"]["processes"]] == ["smartscreen.exe"]
    assert beh["background"]["counts"]["lsass_access"] == 1
    names = {d["name"] for d in signatures.evaluate(None, {"behavior": beh, "launcher_pid": LAUNCH})["detections"]}
    assert "LSASS memory access" not in names and "Persistence via Run key" in names


def test_background_process_before_the_launcher_is_not_the_samples():
    # Seen on real Windows: SmartScreen started a moment before the launcher's own event.
    beh = sysmon.parse([EVENTS[3]] + EVENTS[:3] + EVENTS[4:], MON, LAUNCH)
    assert [p["name"] for p in beh["processes"]] == ["cmd.exe", "reg.exe", "whoami.exe"]
    assert beh["lineage"]["pids"] == [LAUNCH, 20, 21]


def test_injection_extends_the_lineage():
    events = EVENTS + [
        ev(8, SourceImage="cmd.exe", SourceProcessGuid="gL", TargetImage="explorer.exe", TargetProcessGuid="gX"),
        ev(3, ProcessId=99, ProcessGuid="gX", Image="explorer.exe", DestinationIp="203.0.113.9", DestinationPort="443"),
    ]
    beh = sysmon.parse(events, MON, LAUNCH)
    assert [n["dst_ip"] for n in beh["network"]] == ["203.0.113.9"]    # injected explorer acts for the sample


def test_old_reports_without_a_launcher_keep_everything():
    beh = sysmon.parse(EVENTS, None, None)
    assert beh["lineage_known"] is False and len(beh["processes"]) == 4 and len(beh["lsass_access"]) == 1


def test_dropped_files_limited_to_lineage_and_deduped(tmp_path):
    out = tmp_path / "output"
    (out / "dropped").mkdir(parents=True)
    copy = r"C:\Users\WDAGUtilityAccount\AppData\Roaming\mallab-test-copy.bat"
    pref = r"C:\Users\WDAGUtilityAccount\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Preferences"
    for i, data in enumerate([b"@echo off", b"{}", b"@echo off"]):
        (out / "dropped" / f"{i:03d}.bin").write_bytes(data)
    report = {"dropped": [{"index": 0, "path": copy}, {"index": 1, "path": pref}, {"index": 2, "path": copy}],
              "new_processes": [{"pid": 20, "name": "reg.exe"}, {"pid": 30, "name": "smartscreen.exe"}]}
    report["_dropped_blobs"] = sandbox._collect_dropped(report, out)
    assert len(report["_dropped_blobs"]) == 2                         # duplicate path collected once
    report["behavior"] = sysmon.parse(EVENTS, MON, LAUNCH)
    sandbox._keep_lineage(report)
    assert [p for p, _ in report["_dropped_blobs"]] == [copy]         # the WebView cache file isn't the sample's
    assert [d["path"] for d in report["dropped"]] == [copy]
    assert [p["name"] for p in report["new_processes"]] == ["reg.exe"]
    assert [p["name"] for p in report["background_processes"]] == ["smartscreen.exe"]


def test_noise_filter_without_sysmon():
    assert sandbox.NOISE_FILES.search(r"C:\Users\x\AppData\Local\Packages\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\LocalState\EBWebView\Default\Preferences")
    assert not sandbox.NOISE_FILES.search(r"C:\Users\x\AppData\Roaming\payload.exe")
    report = {"dropped": [{"path": "a"}, {"path": "b"}],
              "_dropped_blobs": [(r"C:\x\EBWebView\y", b"1"), (r"C:\x\Roaming\evil.exe", b"2")]}
    sandbox._keep_lineage(report)
    assert [p for p, _ in report["_dropped_blobs"]] == [r"C:\x\Roaming\evil.exe"]


def test_old_mallab_sysmon_config_is_upgraded_custom_one_kept(tmp_path):
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "sysmon-config.xml").write_text('<!-- mallab default -->\n<Sysmon><RegistryEvent onmatch="exclude"></RegistryEvent></Sysmon>')
    MalLab(tmp_path)
    assert '<RegistryEvent onmatch="include">' in (tools / "sysmon-config.xml").read_text()
    (tools / "sysmon-config.xml").write_text("<Sysmon><!-- my own --></Sysmon>")
    MalLab(tmp_path)
    assert (tools / "sysmon-config.xml").read_text() == "<Sysmon><!-- my own --></Sysmon>"
