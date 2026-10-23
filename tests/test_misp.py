"""MISP push: event shape, tags, config gating, and the HTTP exchange (mocked)."""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab, misp

IOCS = {"hashes": [{"filename": "a.exe", "sha256": "a" * 64, "md5": "b" * 32, "sha1": None}],
        "urls": ["http://evil.top/x"], "ips": ["203.0.113.9"], "domains": ["evil.top"]}


def test_event_shape_and_tags():
    ev = misp.build_event("Case 1", IOCS, ["Emotet"], ["T1055", "T1547.001"], "malicious")["Event"]
    types = sorted(a["type"] for a in ev["Attribute"])
    assert types == ["domain", "ip-dst", "md5", "sha256", "url"]          # no sha1 when it's None
    assert ev["threat_level_id"] == "1" and ev["info"] == "MalLab: Case 1"
    names = {t["name"] for t in ev["Tag"]}
    assert {"tlp:amber", "mallab", 'malware_classification:malware-family="Emotet"',
            "mitre-attack-pattern:T1055", "mallab:verdict=malicious"} <= names
    assert all(a["to_ids"] for a in ev["Attribute"] if a["type"] != "ip-dst")


def test_push_requires_config(monkeypatch):
    monkeypatch.delenv("MISP_URL", raising=False)
    monkeypatch.delenv("MISP_API_KEY", raising=False)
    assert misp.configured() is False
    with pytest.raises(RuntimeError, match="configured"):
        misp.push("c", IOCS, [], [])


def test_push_posts_event_and_returns_link(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example/")
    monkeypatch.setenv("MISP_API_KEY", "k")
    seen = {}

    def handler(req):
        seen["url"] = str(req.url); seen["auth"] = req.headers.get("authorization")
        seen["body"] = req.read()
        return httpx.Response(200, json={"Event": {"id": "42"}})
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(handler),
                                                           **{k: v for k, v in kw.items() if k != "verify"}))
    r = misp.push("Case 1", IOCS, ["Emotet"], ["T1055"], "malicious")
    assert r["event_id"] == "42" and r["url"] == "https://misp.example/events/view/42" and r["attributes"] == 5
    assert seen["url"] == "https://misp.example/events" and seen["auth"] == "k"
    assert b'"sha256"' in seen["body"]


def test_push_rejects_bad_key(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example")
    monkeypatch.setenv("MISP_API_KEY", "bad")
    real = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: real(transport=httpx.MockTransport(lambda req: httpx.Response(403)),
                                                           **{k: v for k, v in kw.items() if k != "verify"}))
    with pytest.raises(RuntimeError, match="rejected"):
        misp.push("c", IOCS, [], [])


def test_empty_case_is_refused(monkeypatch):
    monkeypatch.setenv("MISP_URL", "https://misp.example")
    monkeypatch.setenv("MISP_API_KEY", "k")
    with pytest.raises(ValueError, match="no indicators"):
        misp.push("c", {"hashes": [], "urls": [], "ips": [], "domains": []}, [], [])


def test_service_wires_case_data(tmp_path, monkeypatch):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("Wired")["id"]
    lab.ingest(cid, b"MZ http://evil.top/gate", "x.exe")
    captured = {}
    monkeypatch.setattr(misp, "push", lambda name, iocs, fams, attck, verdict="": captured.update(
        name=name, n=len(iocs["hashes"]), urls=iocs["urls"], attck=attck) or {"ok": True})
    lab.push_to_misp(cid)
    assert captured["name"] == "Wired" and captured["n"] == 1 and captured["urls"] == ["http://evil.top/gate"]
    assert "T1071" in captured["attck"]
    assert "misp" in lab.state()
