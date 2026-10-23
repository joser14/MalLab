"""New investigation features: hardened interactive sandbox, threat-group tracking, free IOC
enrichment, YARA drafts, related samples, ATT&CK matrix, timeline and notes. No VM is started and
no network is used (providers and downloads are stubbed)."""

import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server
from mallab import MalLab, actors, ioc_intel, sandbox, signatures


# ---- interactive sandbox keeps the protections ------------------------------------------

def test_interactive_sandbox_is_hardened(tmp_path, monkeypatch):
    launched = []
    monkeypatch.setattr(sandbox, "available", lambda: (True, ""))
    monkeypatch.setattr(sandbox, "sandbox_running", lambda: False)
    monkeypatch.setattr(sandbox.subprocess, "Popen", lambda args, **k: launched.append(args))
    monkeypatch.setattr(sandbox.threading, "Thread", lambda **k: type("T", (), {"start": lambda self: None})())
    res = sandbox.open_interactive(tmp_path, (b"MZ sample", 'evil".exe'))
    wsb_path = Path(launched[0][1])
    wsb = wsb_path.read_text(encoding="utf-8")
    for setting in ("<vGPU>Disable</vGPU>", "<Networking>Disable</Networking>", "<ClipboardRedirection>Disable</ClipboardRedirection>",
                    "<AudioInput>Disable</AudioInput>", "<VideoInput>Disable</VideoInput>", "<PrinterRedirection>Disable</PrinterRedirection>",
                    "<ProtectedClient>Enable</ProtectedClient>", "<ReadOnly>true</ReadOnly>", "check.ps1"):
        assert setting in wsb
    assert "<ReadOnly>false</ReadOnly>" not in wsb               # nothing writable is shared with the host
    assert res["staged"] == "sample.exe" and (wsb_path.parent / "input" / "sample.exe").read_bytes() == b"MZ sample"
    assert "Stop-Computer -Force" in sandbox.INTERACTIVE_CHECK_PS1   # fail closed if isolation is broken


def test_interactive_sandbox_refuses_while_detonating(tmp_path):
    lab = MalLab(tmp_path)
    lab.detonating = True
    with pytest.raises(RuntimeError, match="detonation"):
        lab.open_sandbox()


# ---- threat groups ---------------------------------------------------------------------

MITRE = {"objects": [
    {"type": "intrusion-set", "id": "is--1", "name": "APT-Test", "aliases": ["APT-Test", "Fancy Test"],
     "description": "desc", "external_references": [{"source_name": "mitre-attack", "external_id": "G9999"}]},
    {"type": "intrusion-set", "id": "is--2", "name": "Old", "revoked": True},
    {"type": "malware", "id": "mw--1", "name": "TestRAT"},
    {"type": "attack-pattern", "id": "ap--1", "name": "PowerShell",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001"}]},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "is--1", "target_ref": "mw--1"},
    {"type": "relationship", "relationship_type": "uses", "source_ref": "is--1", "target_ref": "ap--1"},
]}
MISP = {"values": [{"value": "Fancy Test", "meta": {"synonyms": ["FT-1"], "country": "XX", "motive": "Espionage"}},
                   {"value": "Brand New Group", "meta": {}}]}
MALPEDIA = {"win.otherrat": {"common_name": "OtherRAT", "attribution": ["FT-1"]},
            "win.unattributed": {"common_name": "Lonely", "attribution": []}}


def test_mitre_misp_malpedia_merge():
    mitre = actors.parse_mitre(MITRE)
    assert [g["name"] for g in mitre] == ["APT-Test"]
    assert mitre[0]["families"] == ["TestRAT"] and mitre[0]["techniques"] == ["T1059.001"]
    existing = [{"id": "a1", "name": "APT-Test", "aliases": "", "mitre_id": "", "families": "MyFamily",
                 "techniques": "", "country": "", "motivation": "", "description": "", "notes": "keep me", "source": "analyst"}]
    updates, creates = actors.merge_catalog(existing, mitre, actors.parse_misp(MISP), actors.parse_malpedia(MALPEDIA))
    u = updates["a1"]
    assert u["mitre_id"] == "G9999" and u["country"] == "XX"
    assert {"MyFamily", "TestRAT", "OtherRAT"} <= set(actors.split_list(u["families"]))   # unioned, analyst's kept
    assert "FT-1" in u["aliases"] and "notes" not in u
    assert [c["name"] for c in creates] == ["Brand New Group"]


def test_suggestions_explain_themselves():
    rows = [{"id": "a", "name": "G1", "aliases": "", "families": "Emotet", "techniques": "T1059.001, T1547.001, T1105, T1071"},
            {"id": "b", "name": "G2", "aliases": "", "families": "", "techniques": "T1059.001"}]
    out = actors.suggest({"labels": ["Emotet epoch5"], "techniques": ["T1059.001", "T1547.001", "T1105"], "iocs": {"evil.top"}},
                         rows, {"b": {"evil.top"}})
    assert out[0]["id"] == "a" and out[0]["strength"] == "strong"
    assert any("Emotet" in w or "emotet" in w for w in out[0]["why"])
    assert out[1]["id"] == "b" and "shared" in out[1]["why"][0]


def test_group_links_profile_and_case_delete(tmp_path):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("c")["id"]
    s = lab.ingest(cid, b"MZ http://c2.evil.top/x", "x.exe")
    g = lab.save_actor(None, {"name": "G", "families": "TestRAT, Other", "techniques": "T1071"})
    prof = lab.link_actor(g["id"], "sample", s["id"], "medium")
    assert prof["samples"][0]["confidence"] == "medium"
    assert "c2.evil.top" in prof["iocs"]["domains"]
    assert "T1071" in prof["attck_known_and_observed"]
    lab.annotate_sample(s["id"], labels="testrat")
    sug = lab.suggest_actors(s["id"])
    assert sug["suggestions"][0]["id"] == g["id"]
    with pytest.raises(ValueError):
        lab.link_actor(g["id"], "case", "nope")
    lab.delete_case(cid)
    assert lab.store.actor_links(aid=g["id"]) == []


def test_catalog_import_is_merged_from_downloads(tmp_path, monkeypatch):
    import httpx
    lab = MalLab(tmp_path)
    data = {actors.MITRE_URL: MITRE, actors.MISP_URL: MISP, actors.MALPEDIA_URL: MALPEDIA}
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=data[str(req.url)]))
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=transport, **{k: v for k, v in kw.items() if k != "transport"}))
    res = lab.import_actor_catalog()
    assert res["created"] == 2 and not res["errors"]
    again = lab.import_actor_catalog()          # idempotent: nothing new the second time
    assert again["created"] == 0
    assert (tmp_path / "intel" / "actors.version").exists()   # what the installer checks


# ---- free IOC enrichment ----------------------------------------------------------------

def test_enrichment_aggregates_families_and_actors(tmp_path, monkeypatch):
    monkeypatch.setattr(ioc_intel, "feodo_list", lambda d: [{"ip_address": "8.8.4.4", "malware": "QakBot", "port": 443}])
    monkeypatch.setattr(ioc_intel, "otx", lambda ioc, kind, key: ioc_intel._r("OTX", found=True, verdict="malicious",
                                                                              actors=["APT-Test"], families=["TestRAT"]))
    for name in ("greynoise", "internetdb", "rdap"):
        monkeypatch.setattr(ioc_intel, name, lambda ip, n=name: ioc_intel._r(n))
    rows = ioc_intel.enrich(["8.8.4.4", "evil.top"], {}, tmp_path)
    ip = rows[0]
    assert ip["summary"]["verdict"] == "malicious"
    assert set(ip["summary"]["families"]) == {"QakBot", "TestRAT"} and ip["summary"]["actors"] == ["APT-Test"]
    assert [r["provider"] for r in rows[1]["results"]] == ["OTX"]      # no abuse.ch key: ThreatFox/URLhaus skipped
    assert ioc_intel.kind_of("http://x.y/") == "url" and ioc_intel.kind_of("::1") == "ipv6"


def test_provider_errors_are_contained():
    def boom(*a):
        raise RuntimeError("down")
    assert ioc_intel._safe(boom, "X", 1)["error"] == "RuntimeError: down"


# ---- YARA draft, related samples, matrix, timeline -------------------------------------

def test_generated_yara_rule_is_valid(tmp_path):
    lab = MalLab(tmp_path)
    s = lab.ingest(lab.store.create_case("t")["id"],
                   b"MZ\x00\x00" + b"\x00" * 64 + b"https://c2.evil.top/panel/gate.php\x00Global\\MyUniqueMutexName_7781\x00", "drop.exe")
    r = lab.generate_yara(s["id"])
    assert "c2.evil.top" in r["text"] and r["name"].endswith(".yar")
    try:
        import yara
    except ImportError:
        return
    yara.compile(source=r["text"]).match(data=lab.store.read_sample(s["sha256"]))


def test_related_samples_share_iocs(tmp_path):
    lab = MalLab(tmp_path)
    a = lab.ingest(lab.store.create_case("a")["id"], b"MZ one http://shared-c2.top/x", "a.exe")
    lab.ingest(lab.store.create_case("b")["id"], b"MZ two http://shared-c2.top/x", "b.exe")
    rel = lab.related_samples(a["id"])
    assert rel and rel[0]["filename"] == "b.exe" and "shared IOC" in rel[0]["why"][-1]


def test_attck_matrix_groups_by_tactic():
    m = signatures.attck_matrix([{"detections": [
        {"name": "Run key", "severity": "high", "attck": ["T1547.001"]},
        {"name": "PS", "severity": "medium", "attck": ["T1059.001", "T9999"]}]}])
    tactics = [c["tactic"] for c in m]
    assert tactics == ["Execution", "Persistence", "Other"]
    assert m[1]["techniques"][0]["severity"] == "high"


def test_timeline_and_notes_routes(tmp_path):
    c = TestClient(server.LocalOnly(server.build_app(MalLab(tmp_path), server.Hub())),
                   base_url="http://127.0.0.1:7860", client=("127.0.0.1", 5000))
    cid = c.post("/api/lab/case", json={"name": "t"}).json()["id"]
    sid = c.post(f"/api/lab/case/{cid}/upload", content=b"MZ x", headers={"X-Filename": "a.exe"}).json()["samples"][0]["id"]
    ev = c.get(f"/api/lab/case/{cid}/timeline").json()["events"]
    assert ev[0]["kind"] == "sample"
    r = c.post(f"/api/lab/sample/{sid}/annotate", json={"notes": "beacons every 60s", "labels": ["A", "a ", "B"]}).json()
    assert r["notes"] == "beacons every 60s" and r["labels"] == "A,a,B"
    assert c.get(f"/api/lab/case/{cid}/attck").status_code == 200
    assert c.get(f"/api/lab/case/{cid}/iocs/export?format=stix").headers["content-disposition"].endswith('.stix.json"')
    assert c.get("/api/lab/actors/nope").status_code == 404
