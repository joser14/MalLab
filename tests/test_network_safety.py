"""Host network guard and the Simulated (FakeNet-NG) network mode. No VM is started, no firewall
rule is changed and no network is used: the elevated PowerShell, the live firewall probe and the
sandbox launch are all mocked."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server
from mallab import MalLab, fakenet, netguard, sandbox

ADAPTER = netguard.ADAPTER


def _client(lab):
    return TestClient(server.LocalOnly(server.build_app(lab, server.Hub())), base_url="http://127.0.0.1:7860",
                      client=("127.0.0.1", 50000))


def _rule(name, alias=ADAPTER, enabled=True, action="Block", direction="Inbound"):
    return {"name": name, "enabled": enabled, "action": action, "direction": direction, "alias": [alias]}


def _probe(rules=None, profiles_on=True, adapter=ADAPTER):
    return {"adapter": adapter, "ipv4": "172.22.64.1", "prefix": 20,
            "rules": rules if rules is not None else [_rule(f"r{i}") for i in range(4)],
            "profiles": [{"name": n, "enabled": profiles_on or n != "Public"} for n in ("Domain", "Private", "Public")]}


def _ps_parses(text, tmp_path):
    p = tmp_path / "s.ps1"
    p.write_text(text, encoding="utf-8-sig")
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('{p}', [ref]$null, [ref]$e); $e.Count"],
                       capture_output=True, text=True, timeout=60)
    return r.stdout.strip() == "0", r.stdout + r.stderr


# ---- host network guard ---------------------------------------------------------------

def test_guard_is_on_only_when_every_rule_is_live_and_aimed_at_the_sandbox_switch():
    assert netguard.evaluate(_probe(), {})["enabled"] is True
    st = netguard.evaluate(_probe(), {})
    assert st["subnet"] == "172.22.64.0/20" and st["rules"] == 4
    # A rule on another adapter, a disabled rule, or an allow rule doesn't count.
    for bad in (_rule("x", alias="Ethernet"), _rule("x", enabled=False), _rule("x", action="Allow")):
        assert netguard.evaluate(_probe([_rule(f"r{i}") for i in range(3)] + [bad]), {})["enabled"] is False
    # Firewall off for a profile: rules exist but aren't enforced.
    off = netguard.evaluate(_probe(profiles_on=False), {})
    assert off["enabled"] is False and any("Public" in p for p in off["problems"])
    # Adapter missing (e.g. after a reboot before Hyper-V networking starts).
    gone = netguard.evaluate(_probe(adapter=None), {})
    assert gone["enabled"] is False and gone["problems"]


def test_guard_status_tolerates_flattened_and_forged_probe_output():
    p = _probe()
    p["rules"] = p["rules"][0]                      # ConvertTo-Json unwraps a one-element array
    assert netguard.evaluate(p, {})["rules"] == 1
    p["rules"] = [{**_rule("x"), "enabled": "True"}] * 4   # strings are not booleans
    assert netguard.evaluate(p, {})["enabled"] is False
    assert netguard.evaluate("garbage", {})["enabled"] is False
    assert netguard.subnet("bad", 20) is None


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
@pytest.mark.parametrize("enable", [True, False])
def test_guard_script_parses_and_is_scoped_to_the_sandbox_adapter(tmp_path, enable):
    text = netguard._script(enable, tmp_path / "it's state.json")
    ok, out = _ps_parses(text, tmp_path)
    assert ok, out
    assert "Remove-NetFirewallRule" in text                     # always rebuilt from scratch
    assert "it''s state.json" in text
    if enable:
        assert text.count("New-NetFirewallRule") == 4
        assert "Direction = 'Inbound'" in text and "Action = 'Block'" in text
        assert "InterfaceAlias = $alias" in text and "Profile = 'Any'" in text
        assert "'1-52','54-66','68-65535'" in text              # only DHCP (67) and DNS (53) stay open
    else:
        assert "New-NetFirewallRule" not in text


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_guard_probe_script_parses(tmp_path):
    ok, out = _ps_parses(netguard._PROBE, tmp_path)
    assert ok, out


def _fake_elevated(monkeypatch, tools, state=None, rc=0, err="", probe=None):
    calls = []

    def run(cmd, timeout=30):
        calls.append(cmd)
        if state is not None:
            (tools / netguard.STATE_FILE).write_text(json.dumps(state), encoding="utf-8")
        return subprocess.CompletedProcess([], rc, "", err)
    monkeypatch.setattr(netguard, "_run_ps", run)
    monkeypatch.setattr(netguard, "_probe", lambda: probe if probe is not None else _probe())
    monkeypatch.setattr(netguard.sys, "platform", "win32")
    return calls


def test_guard_toggle_requests_uac_and_reports_live_state(monkeypatch, tmp_path):
    tools = tmp_path / "tools"
    calls = _fake_elevated(monkeypatch, tools, {"ok": True, "enabled": True, "rules": 4, "time": 7})
    st = netguard.set_enabled(tools, True)
    assert "-Verb RunAs" in calls[0] and st["enabled"] is True and st["verified"] == 7
    assert "New-NetFirewallRule" in (tools / netguard.SCRIPT_FILE).read_text(encoding="utf-8-sig")


def test_guard_declined_prompt_and_refusal(monkeypatch, tmp_path):
    tools = tmp_path / "tools"
    _fake_elevated(monkeypatch, tools, None, rc=1, err="The operation was canceled by the user.", probe=_probe([]))
    with pytest.raises(RuntimeError, match="declined"):
        netguard.set_enabled(tools, True)
    assert netguard.status(tools)["enabled"] is False
    _fake_elevated(monkeypatch, tools, {"ok": False, "error": "adapter was not found", "time": 8})
    with pytest.raises(RuntimeError, match="adapter was not found"):
        netguard.set_enabled(tools, True)


def test_networked_detonation_records_and_warns_when_guard_is_off(tmp_path, monkeypatch):
    lab = MalLab(tmp_path)
    s = lab.ingest(lab.store.create_case("t")["id"], b"MZ x", "x.exe")
    seen, logs = {}, []
    lab.emit = lambda e: logs.append(e.get("text", ""))
    monkeypatch.setattr(lab, "netguard_status", lambda: {"enabled": False})
    monkeypatch.setattr("mallab.sandbox.detonate", lambda *a, **kw: seen.update(kw) or {"verdict": "x"})
    lab.detonate(s["id"], networking=True)
    assert seen["host_guard"] is False and any("guard is off" in t for t in logs)
    lab.detonate(s["id"])                                       # networking off: guard not consulted
    assert seen["host_guard"] is None


# ---- FakeNet-NG log parsing -----------------------------------------------------------

LOG = """10/17/26 01:00:00 PM [          FakeNet] Loaded configuration file: C:\\mallab-fakenet\\configs\\mallab.ini
10/17/26 01:00:05 PM [       DNS Server] Received A request for domain 'c2.evil-example.com'.
10/17/26 01:00:05 PM [       DNS Server] Received AAAA request for domain 'cdn.bad-example.net.'.
10/17/26 01:00:05 PM [       DNS Server] Received A request for domain '../../etc'; DROP TABLE'.
10/17/26 01:00:06 PM [         Diverter] sample.exe (4242) requested TCP 203.0.113.9:8443
10/17/26 01:00:06 PM [   HTTPListener80]   POST /gate.php?id=1 HTTP/1.1
10/17/26 01:00:06 PM [   HTTPListener80]   Host: c2.evil-example.com
10/17/26 01:00:06 PM [   HTTPListener80]   User-Agent: Mozilla/4.0
10/17/26 01:00:07 PM [  HTTPListener443]   GET /payload.bin HTTP/1.1
10/17/26 01:00:07 PM [  HTTPListener443]   Host: cdn.bad-example.net:8443
10/17/26 01:00:08 PM [ ProxyTCPListener]   GET http://proxy-example.org/x HTTP/1.1
"""


def test_fakenet_log_becomes_domains_urls_and_connections():
    r = fakenet.parse(LOG)
    assert r["domains"] == ["c2.evil-example.com", "cdn.bad-example.net"]
    urls = {u["url"]: u["method"] for u in r["urls"]}
    assert urls == {"http://c2.evil-example.com/gate.php?id=1": "POST",
                    "https://cdn.bad-example.net:8443/payload.bin": "GET",
                    "http://proxy-example.org/x": "GET"}
    assert r["connections"] == [{"process": "sample.exe", "pid": 4242, "proto": "TCP", "ip": "203.0.113.9", "port": 8443}]
    assert fakenet.parse("") == {"domains": [], "urls": [], "connections": []}
    # Older releases log a connection on two Diverter lines.
    old = ("07/06/16 10:21:04 PM [          Diverter]   from: 192.168.250.140:2179 -> 198.51.100.7:80\n"
           "07/06/16 10:21:04 PM [          Diverter]   pid:  456 name: malware.exe\n")
    assert fakenet.parse(old)["connections"] == [{"process": "malware.exe", "pid": 456, "proto": None,
                                                  "ip": "198.51.100.7", "port": 80}]


def test_fakenet_log_read_back_is_capped_and_refuses_links(tmp_path, monkeypatch):
    monkeypatch.setattr(fakenet, "MAX_LOG_BYTES", 2048)
    monkeypatch.setattr(fakenet, "LOG_EXCERPT", 100)
    p = tmp_path / "fakenet.log"
    p.write_text(LOG + "x" * 50_000, encoding="utf-8")
    r = fakenet.read_log(p)
    assert len(r["log"]) == 100 and r["log_truncated"] and "c2.evil-example.com" in r["domains"]
    assert fakenet.read_log(tmp_path / "missing.log") is None
    assert fakenet.read_log(tmp_path) is None                   # a directory, not a file


# ---- FakeNet-NG staging ---------------------------------------------------------------

DEFAULT_INI = """[FakeNet]
DivertTraffic: Yes

[Diverter]
NetworkMode:         Auto
RedirectAllTraffic:  No
DefaultTCPListener:  ProxyTCPListener
BlackListPortsTCP:   139
BlackListPortsUDP:   67, 68, 137, 138, 443, 1900, 5355
ProcessBlackList:    java.exe
HostBlackList:       6.6.6.6

[DNS Server]
Enabled:     True
ResponseA:   192.0.2.123

[FilteredListener]
Enabled:     False
ProcessWhiteList: ncat.exe, nc.exe
HostBlackList: 5.5.5.5
"""


def _fakenet_release(tools: Path) -> Path:
    d = tools / "fakenet3.5"
    (d / "configs").mkdir(parents=True)
    (d / "fakenet.exe").write_bytes(b"MZ fake")
    (d / "configs" / "default.ini").write_text(DEFAULT_INI, encoding="utf-8")
    return d


def test_fakenet_is_found_in_tools_and_staged_with_a_hardened_config(tmp_path):
    tools = tmp_path / "tools"
    assert fakenet.find(tools) is None
    src = _fakenet_release(tools)
    assert fakenet.find(tools) == src
    dest = tmp_path / "in" / "tools" / "fakenet"
    name = fakenet.stage(src, dest)
    assert (dest / "fakenet.exe").exists() and (dest / "configs" / "default.ini").exists()
    import configparser
    cp = configparser.RawConfigParser()
    cp.optionxform = str
    cp.read_string((dest / "configs" / name).read_text(encoding="utf-8"))
    div = cp["Diverter"]
    assert div["RedirectAllTraffic"] == "Yes" and div["BlackListPortsUDP"] == "67, 68"
    for k in ("BlackListPortsTCP", "ProcessBlackList", "HostBlackList"):   # nothing bypasses the diverter
        assert k not in div
    assert cp["DNS Server"]["ResponseA"] == "192.0.2.123"                 # rest of the config untouched
    assert dict(cp["FilteredListener"]) == {"Enabled": "False"}           # listener-level exemptions gone too


def test_fakenet_staging_refuses_an_incomplete_release(tmp_path):
    d = tmp_path / "tools" / "fn"
    d.mkdir(parents=True)
    (d / "fakenet.exe").write_bytes(b"MZ")
    with pytest.raises(RuntimeError, match="default.ini"):
        fakenet.stage(d, tmp_path / "dest")
    with pytest.raises(ValueError):
        fakenet.harden_config("[FakeNet]\nx: 1\n")


# ---- Simulated mode end to end (VM mocked) -------------------------------------------

def test_simulated_mode_is_refused_without_fakenet(tmp_path, monkeypatch):
    monkeypatch.setattr(sandbox, "available", lambda: pytest.fail("must refuse before touching the sandbox"))
    with pytest.raises(RuntimeError, match="FakeNet-NG"):
        sandbox.detonate(b"MZ", "x.exe", tmp_path / "runs", simulate=True, tools_dir=tmp_path / "tools")
    lab = MalLab(tmp_path / "lab")
    s = lab.ingest(lab.store.create_case("t")["id"], b"MZ x", "x.exe")
    with pytest.raises(RuntimeError, match="FakeNet-NG"):
        lab.detonate(s["id"], simulate=True)
    assert lab.store.list_runs(s["id"]) == [] and not lab.detonating
    client = _client(lab)
    r = client.post(f"/api/lab/sample/{s['id']}/detonate", json={"simulate": True})
    assert r.status_code == 400 and "FakeNet-NG" in r.json()["error"]
    r = client.post("/api/lab/quick?simulate=1", content=b"MZ y", headers={"X-Filename": "y.exe"})
    assert r.status_code == 400 and "FakeNet-NG" in r.json()["error"]


def test_monitor_starts_fakenet_before_the_baseline_and_fails_closed():
    m = sandbox.MONITOR_PS1
    assert m.index("fakenet.exe") < m.index("$before = Snapshot")
    assert "simulated network (FakeNet-NG) did not start" in m
    assert m.index("configs\\mallab.ini") > 0 and '"-l", (Join-Path $outDir "fakenet.log")' in m
    assert '-ArgumentList "-p"' in m                    # no "Press Enter" pause if it fails to start
    assert m.count("Disable-NetAdapter") >= 3          # on startup failure, if it dies, and at the end
    assert "{fakenet}" in sandbox.WSB_TEMPLATE


def test_simulated_detonation_end_to_end(tmp_path, monkeypatch):
    tools = tmp_path / "tools"
    _fakenet_release(tools)
    launched = {}

    def fake_vm(args, **kw):            # plays the VM: reads the .wsb, writes the monitor's outputs
        wsb = Path(args[1])
        launched["wsb"] = wsb.read_text(encoding="utf-8")
        launched["staged"] = sorted(p.name for p in (wsb.parent / "input" / "tools" / "fakenet" / "configs").iterdir())
        out = wsb.parent / "output"
        (out / "fakenet.log").write_text(LOG, encoding="utf-8")
        (out / "report.json").write_text(json.dumps({
            "detonated": True, "fakenet": True, "fakenet_pid": 99, "has_default_route": True,
            "dns": ["c2.evil-example.com"], "host_guard": True,             # forged: the host decides
            "fakenet_log": {"domains": ["forged.example"]}}), encoding="utf-8")
        (out / "done.flag").write_text("done")
    monkeypatch.setattr(sandbox, "available", lambda: (True, ""))
    monkeypatch.setattr(sandbox, "sandbox_running", lambda: False)
    monkeypatch.setattr(sandbox, "_kill_sandbox", lambda: None)
    monkeypatch.setattr(sandbox.time, "sleep", lambda s: None)
    monkeypatch.setattr(sandbox.subprocess, "Popen", fake_vm)

    rep = sandbox.detonate(b"MZ", "x.exe", tmp_path / "runs", timeout=5, simulate=True,
                           tools_dir=tools, host_guard=False, safe_net=True)
    assert "<Networking>Enable</Networking>" in launched["wsb"]
    assert "-FakeNet" in launched["wsb"] and "-SafeNet" not in launched["wsb"] and "-ExpectNoNetwork" not in launched["wsb"]
    assert launched["staged"] == ["default.ini", "mallab.ini"]
    assert rep["network_mode"] == "simulated" and rep["host_guard"] is False
    fn = rep["fakenet"]
    assert fn["started"] and fn["died_at"] is None and "forged.example" not in fn["domains"]
    assert "http://c2.evil-example.com/gate.php?id=1" in [u["url"] for u in fn["urls"]]
    assert rep["dns"] == ["c2.evil-example.com", "cdn.bad-example.net"]
    assert "requested on the simulated network" in rep["verdict"] and "guard was off" in rep["verdict"]
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())   # run folder wiped


def test_fakenet_dying_mid_run_is_flagged():
    rep = {"detonated": True, "fakenet": {"died_at": 12.0, "domains": [], "urls": []}}
    assert "FakeNet-NG stopped 12.0s into the run" in sandbox._summarize(rep)


def test_simulated_iocs_reach_the_case(tmp_path, monkeypatch):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    s = lab.ingest(cid, b"MZ x", "x.exe")
    monkeypatch.setattr("mallab.sandbox.detonate", lambda *a, **kw: {
        "verdict": "x", "network_mode": "simulated",
        "fakenet": {"domains": ["c2.evil-example.com"], "urls": [{"url": "http://c2.evil-example.com/gate.php", "method": "POST"}],
                    "connections": [{"ip": "203.0.113.9"}, {"ip": "8.8.4.4"}, {"ip": "192.0.2.123"}]}})
    monkeypatch.setattr("mallab.fakenet.find", lambda d: tmp_path)
    monkeypatch.setattr(lab, "netguard_status", lambda: {"enabled": True})
    lab.detonate(s["id"], simulate=True)
    iocs = lab.case_iocs(cid)
    assert "c2.evil-example.com" in iocs["domains"]
    assert "http://c2.evil-example.com/gate.php" in iocs["urls"]
    assert "8.8.4.4" in iocs["ips"] and "192.0.2.123" not in iocs["ips"]   # FakeNet's own fake answer isn't an IOC


def test_netguard_route_and_state(tmp_path, monkeypatch):
    lab = MalLab(tmp_path)
    monkeypatch.setattr(netguard, "_probe", lambda: _probe([]))
    client = _client(lab)
    st = client.get("/api/lab/state").json()
    assert st["netguard"]["enabled"] is False and st["fakenet"]["ready"] is False
    monkeypatch.setattr(lab, "set_netguard", lambda enable: {"enabled": enable})
    assert client.post("/api/lab/netguard", json={"enable": True}).json() == {"enabled": True}
