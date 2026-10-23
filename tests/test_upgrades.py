"""Sigma detections, hollows_hunter memory dumps, YARA packs + retrohunt, and the evasion flag.
No VM, no network: rule packs and tool downloads are fixtures / mocks."""

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab, sandbox, signatures, sigma, static, sysmon, tooling

RULE_ENC = """
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
level: high
tags: [attack.execution, attack.t1059.001]
logsource: {category: process_creation, product: windows}
detection:
  selection_img:
    - Image|endswith: '\\powershell.exe'
    - OriginalFileName: 'PowerShell.EXE'
  selection_cli:
    CommandLine|contains|windash: ' -enc '
  filter_main:
    ParentImage|startswith: 'C:\\Program Files\\Good\\'
  condition: all of selection_* and not 1 of filter_*
falsepositives: [Administrative scripts]
"""
RULE_RUNKEY = """
title: Run Key Write
id: 11111111-2222-3333-4444-555555555555
level: medium
tags: [attack.persistence, attack.t1547.001]
logsource: {category: registry_set, product: windows}
detection:
  sel:
    TargetObject|contains: '\\CurrentVersion\\Run\\'
    Details|re: '(?i)\\.(bat|exe)$'
  condition: sel
"""
RULE_AGG = """
title: Aggregation (unsupported)
logsource: {category: process_creation, product: windows}
detection: {sel: {Image: x}, condition: sel | count() > 5}
"""
RULE_LINUX = """
title: Linux only
logsource: {category: process_creation, product: linux}
detection: {sel: {Image: /bin/sh}, condition: sel}
"""


def ev(eid, **d):
    return {"id": eid, "time": "t", "data": {k: str(v) for k, v in d.items()}}


@pytest.fixture
def rules_dir(tmp_path):
    d = tmp_path / "sigma" / "rules" / "windows"
    d.mkdir(parents=True)
    for i, r in enumerate((RULE_ENC, RULE_RUNKEY, RULE_AGG, RULE_LINUX)):
        (d / f"r{i}.yml").write_text(r, encoding="utf-8")
    (d / "broken.yml").write_text("title: [unclosed", encoding="utf-8")
    return tmp_path / "sigma"


def test_sigma_rules_compile_and_skip_honestly(rules_dir):
    c = sigma.load_rules(rules_dir)
    assert [r["title"] for r in c["rules"]] == ["Suspicious Encoded PowerShell Command Line", "Run Key Write"]
    assert c["skipped"] == 1 and c["errors"] == 1          # aggregation skipped, broken YAML counted


def test_sigma_matches_only_the_lineage(rules_dir):
    c = sigma.load_rules(rules_dir)
    events = [
        ev(1, ProcessId=10, ParentProcessId=7, ProcessGuid="gL", Image=r"C:\Windows\System32\cmd.exe", CommandLine="cmd /c x"),
        ev(1, ProcessId=11, ParentProcessId=10, ProcessGuid="gP", ParentProcessGuid="gL", Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           CommandLine="powershell /enc SQBFAFgA", ParentImage=r"C:\Windows\System32\cmd.exe"),
        ev(13, ProcessId=11, ProcessGuid="gP", Image="powershell.exe", TargetObject=r"HKU\S\Software\Microsoft\Windows\CurrentVersion\Run\x", Details=r"C:\a\b.BAT"),
        # Same command line from a process outside the lineage: not the sample's.
        ev(1, ProcessId=50, ParentProcessId=600, ProcessGuid="gO", ParentProcessGuid="gSvc", Image=r"C:\x\powershell.exe", CommandLine="powershell -enc AAAA"),
    ]
    beh = sysmon.parse(events, 7, 10)
    hits = sigma.match(events, c, sigma.lineage_filter(beh))
    assert [(h["title"], h["count"]) for h in hits] == [("Suspicious Encoded PowerShell Command Line", 1), ("Run Key Write", 1)]
    assert hits[0]["attck"] == ["T1059.001"] and "windash" not in hits[0]["evidence"][0]
    det = signatures.evaluate(None, {"sigma": hits})["detections"]
    names = {d["name"]: d for d in det}
    assert names["Sigma: Suspicious Encoded PowerShell Command Line"]["severity"] == "high"
    assert "Administrative scripts" in names["Sigma: Suspicious Encoded PowerShell Command Line"]["description"]


def test_sigma_condition_grammar():
    sels = {"a": lambda d: d["x"] == "1", "b": lambda d: d["y"] == "1", "f_1": lambda d: d.get("z") == "1"}
    p = sigma._condition("(a or b) and not 1 of f_*", sels)
    assert p({"x": "1", "y": "0"}) and not p({"x": "1", "y": "0", "z": "1"}) and not p({"x": "0", "y": "0"})
    with pytest.raises(sigma.Unsupported):
        sigma._condition("a | count() > 2", sels)
    with pytest.raises(sigma.Unsupported):
        sigma._condition("missing", sels)


def test_sigma_wildcards_and_modifiers():
    m = sigma._field_matcher("CommandLine|contains|all", ["vssadmin", "delete shadows"])
    assert m({"CommandLine": "VSSADMIN.exe Delete Shadows /all"}) and not m({"CommandLine": "vssadmin list"})
    assert sigma._field_matcher("Image", r"*\rundll32.exe")({"Image": r"C:\Windows\System32\RUNDLL32.EXE"})
    assert sigma._field_matcher("DestinationIp|cidr", "10.0.0.0/8")({"DestinationIp": "10.1.2.3"})
    assert sigma._field_matcher("Image|exists", True)({"Image": "x"})
    with pytest.raises(sigma.Unsupported):
        sigma._field_matcher("CommandLine|base64offset|contains", "x")


def test_sandbox_runs_sigma_when_rules_are_installed(rules_dir):
    report = {"sysmon_events": [ev(1, ProcessId=10, ParentProcessId=7, ProcessGuid="gL", Image=r"C:\x\powershell.exe",
                                   CommandLine="powershell -enc AAAA")], "launcher_pid": 10, "monitor_pid": 7}
    report["behavior"] = sysmon.parse(report["sysmon_events"], 7, 10)
    compiled = sigma.cached_rules(rules_dir)
    assert sigma.match(report["sysmon_events"], compiled, sigma.lineage_filter(report["behavior"]))[0]["count"] == 1


# ---- hollows_hunter memory dumps ------------------------------------------------------

def _memdir(tmp_path):
    root = tmp_path / "memdump"
    p1 = root / "process_10"
    p1.mkdir(parents=True)
    (p1 / "scan_report.json").write_text(json.dumps({"pid": 10, "main_image_path": r"C:\in\sample.exe",
        "scanned": {"total": 30, "modified": {"total": 2, "implanted_pe": 1, "patched": 1}}}))
    (p1 / "7ff6a000.sample.exe").write_bytes(b"MZ unpacked payload")
    (p1 / "notes.txt").write_bytes(b"not a dump")
    p2 = root / "process_600"
    p2.mkdir()
    (p2 / "scan_report.json").write_text(json.dumps({"pid": 600, "main_image_path": r"C:\Windows\System32\svchost.exe",
        "scanned": {"modified": {"iat_hooked": 3}}}))
    (p2 / "1000.svchost.dll").write_bytes(b"MZ svchost module")
    p3 = root / "process_11"
    p3.mkdir()
    (p3 / "scan_report.json").write_text(json.dumps({"pid": 11, "scanned": {"modified": {"total": 0}}}))
    (root / "process_bad").mkdir()
    (root / "process_bad" / "scan_report.json").write_text("{not json")
    return root


def test_memory_dumps_are_collected_defensively(tmp_path):
    entries, blobs = sandbox._collect_memory(_memdir(tmp_path))
    assert [e["pid"] for e in entries] == [10, 600]            # clean process and broken JSON skipped
    assert entries[0]["modified"]["implanted_pe"] == 1
    assert [b for _, b in blobs] == [b"MZ unpacked payload", b"MZ svchost module"]
    assert sandbox._collect_memory(tmp_path / "missing") == ([], [])


def test_memory_findings_limited_to_lineage_and_detected(tmp_path):
    entries, blobs = sandbox._collect_memory(_memdir(tmp_path))
    report = {"memory": entries, "_memory_blobs": blobs, "_dropped_blobs": [], "dropped": [],
              "behavior": sysmon.parse([ev(1, ProcessId=10, ParentProcessId=7, ProcessGuid="gL", Image="sample.exe")], 7, 10)}
    sandbox._keep_lineage(report)
    assert [m["pid"] for m in report["memory"]] == [10]
    assert [m["pid"] for m in report["background_memory"]] == [600]      # svchost's hooks aren't the sample's
    assert [b for _, b in report["_memory_blobs"]] == [b"MZ unpacked payload"]
    names = {d["name"] for d in signatures.evaluate(None, report)["detections"]}
    assert "Code implanted in memory" in names


def test_vm_cannot_forge_memory_findings():
    assert "memory" not in sandbox._sanitize({"memory": [{"pid": 1, "dumps": [{"name": "x"}]}], "_memory_blobs": [1]})


def test_memory_dumps_become_child_samples(tmp_path, monkeypatch):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    s = lab.ingest(cid, b"MZ packed", "packed.exe")
    monkeypatch.setattr("mallab.sandbox.detonate", lambda *a, **k: {
        "verdict": "x", "detonated": True, "_memory_blobs": [("packed.exe[10] 7ff6.packed.exe", b"MZ unpacked")]})
    lab.detonate(s["id"])
    srcs = {x["filename"]: x["source"] for x in lab.store.list_samples(cid)}
    assert srcs["packed.exe[10] 7ff6.packed.exe"] == "memory dump from packed.exe run"


# ---- evasion flag ----------------------------------------------------------------------

def test_evasion_suspected_when_anti_vm_code_does_nothing():
    st = {"capa": {"capabilities": [{"name": "check if running in a virtual machine", "namespace": "anti-analysis/anti-vm/vm-detection", "attck": []}]}}
    quiet = {"detonated": True, "behavior": {"processes": [{"name": "s.exe", "launcher": True}]}}
    assert "Sandbox evasion suspected" in {d["name"] for d in signatures.evaluate(st, quiet)["detections"]}
    busy = {"detonated": True, "new_runkeys": ["a"], "new_files": ["b", "c"], "network": ["d"]}
    assert "Sandbox evasion suspected" not in {d["name"] for d in signatures.evaluate(st, busy)["detections"]}
    assert "Sandbox evasion suspected" not in {d["name"] for d in signatures.evaluate({}, quiet)["detections"]}


# ---- YARA packs + retrohunt ---------------------------------------------------------

def test_broken_pack_never_blocks_your_rules_and_retrohunt(tmp_path):
    pytest.importorskip("yara")
    lab = MalLab(tmp_path)
    packs = lab.yara_dir / "packs"
    packs.mkdir()
    (packs / "forge-core.yar").write_text('rule Forge_Hit { strings: $a = "EVIL_MARKER" condition: $a }')
    (packs / "broken.yar").write_text("rule nope { condition: ")
    a = lab.ingest(lab.store.create_case("a")["id"], b"MZ has EVIL_MARKER inside", "a.exe")
    lab.ingest(lab.store.create_case("b")["id"], b"MZ clean", "b.exe")
    rep = lab.static_report(a["id"])
    assert any(m["rule"] == "Forge_Hit" and m["source"] == "forge-core" for m in rep["yara"]["matches"])
    assert any("broken.yar" in e for e in rep["yara"]["errors"])
    r = lab.retrohunt(name="forge-core.yar")
    assert r["scanned"] == 2 and [h["filename"] for h in r["hits"]] == ["a.exe"]
    r = lab.retrohunt(text='rule Unsaved { strings: $a = "clean" condition: $a }')
    assert [h["filename"] for h in r["hits"]] == ["b.exe"]
    with pytest.raises(ValueError):
        lab.retrohunt(text="rule bad {")
    assert [p["name"] for p in lab.yara_packs()] == ["broken.yar", "forge-core.yar"]
    assert all(r["name"] != "forge-core.yar" for r in lab.yara_list())     # packs stay out of the editor


# ---- downloader kinds -------------------------------------------------------------------

def _client(repo, asset, blob):
    digest = "sha256:" + hashlib.sha256(blob).hexdigest()

    def h(req):
        if req.url.path == f"/repos/{repo}/releases/latest":
            return httpx.Response(200, json={"tag_name": "v1", "assets": [
                {"name": asset, "browser_download_url": "https://dl/a", "size": len(blob), "digest": digest}]})
        return httpx.Response(200, content=blob)
    return httpx.Client(transport=httpx.MockTransport(h))


def _zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return buf.getvalue()


def test_new_tool_kinds_install(tmp_path):
    tooling.install("hollows_hunter", tmp_path, _client("hasherezade/hollows_hunter", "hollows_hunter64.exe", b"MZ hh"))
    assert (tmp_path / "hollows_hunter64.exe").read_bytes() == b"MZ hh"
    with pytest.raises(tooling.ToolError):
        tooling.install("hollows_hunter", tmp_path, _client("hasherezade/hollows_hunter", "hollows_hunter64.exe", b"<html>"))
    tooling.install("sigma", tmp_path, _client("SigmaHQ/sigma", "sigma_core.zip",
                    _zip({"rules/windows/a.yml": RULE_ENC, "README.md": "x", "LICENSE.Detection.Rules.md": "DRL"})))
    assert (tmp_path / "sigma" / "rules" / "windows" / "a.yml").exists() and not (tmp_path / "sigma" / "README.md").exists()
    yd = tmp_path / "yara"
    tooling.install("yara_forge", tmp_path, _client("YARAHQ/yara-forge", "yara-forge-rules-core.zip",
                    _zip({"packages/core/yara-rules-core.yar": "rule x { condition: true }"})), yara_dir=yd)
    stored = yd / "packs" / "yara-rules-core.yar.mlx"
    assert stored.exists() and not (yd / "packs" / "yara-rules-core.yar").exists()
    assert b"condition" not in stored.read_bytes()                       # no plain rule text on disk for AV to flag
    assert tooling.decode_pack(stored.read_bytes()) == b"rule x { condition: true }"


def test_encoded_pack_compiles_and_retrohunts(tmp_path):
    pytest.importorskip("yara")
    lab = MalLab(tmp_path)
    (lab.yara_dir / "packs").mkdir()
    (lab.yara_dir / "packs" / "core.yar.mlx").write_bytes(
        tooling.encode_pack(b'rule Enc_Hit { strings: $a = "ENC_MARKER" condition: $a }'))
    s = lab.ingest(lab.store.create_case("a")["id"], b"MZ ENC_MARKER", "a.exe")
    assert any(m["rule"] == "Enc_Hit" and m["source"] == "core" for m in lab.static_report(s["id"])["yara"]["matches"])
    assert lab.yara_packs()[0]["rule_count"] == 1
    assert [h["filename"] for h in lab.retrohunt(name="core.yar.mlx")["hits"]] == ["a.exe"]
