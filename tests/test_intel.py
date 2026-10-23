"""Threat-intel tests: providers normalize responses, only the hash is sent, unconfigured
providers are skipped, failures are contained per provider, and results are cached."""

import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab, intel

SAMPLE = b"MZ harmless test blob, never executed"
H = "a" * 64
REAL_CLIENT = httpx.Client


def _mock(monkeypatch, handler):
    """Route every httpx.Client in the intel module through a MockTransport."""
    def client(*a, **kw):
        kw["transport"] = httpx.MockTransport(handler)
        return REAL_CLIENT(*a, **kw)
    monkeypatch.setattr(intel.httpx, "Client", client)


@pytest.fixture(autouse=True)
def no_env_keys(monkeypatch):
    for k in ("VT_API_KEY", "ABUSECH_API_KEY", "HA_API_KEY", "OTX_API_KEY"):
        monkeypatch.delenv(k, raising=False)


def test_unconfigured_keyed_providers_are_not_called(monkeypatch):
    calls = []
    _mock(monkeypatch, lambda req: calls.append(str(req.url)) or httpx.Response(404))
    ti = intel.ThreatIntel()
    res = {r["id"]: r for r in ti.lookup(H)}
    assert not res["vt"]["configured"] and not res["mb"]["configured"]
    assert all("otx.alienvault.com" in u for u in calls)  # only the keyless provider ran


def test_virustotal_normalized_and_only_hash_sent(monkeypatch):
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"data": {"attributes": {
            "last_analysis_stats": {"malicious": 40, "suspicious": 2, "undetected": 30},
            "popular_threat_classification": {"suggested_threat_label": "trojan.agenttesla"},
            "tags": ["peexe"]}}})
    _mock(monkeypatch, handler)
    vt = intel.VirusTotal(); vt.api_key = "k"
    r = vt.safe_lookup(H)
    assert r["found"] and r["verdict"] == "malicious" and r["score"] == "40/72"
    assert r["label"] == "trojan.agenttesla" and r["link"].endswith(H)
    assert seen[0].method == "GET" and seen[0].content == b""  # nothing but the hash in the URL


def test_abusech_not_found_and_hit(monkeypatch):
    _mock(monkeypatch, lambda req: httpx.Response(200, json={"query_status": "hash_not_found"}))
    mb = intel.MalwareBazaar(); mb.api_key = "k"
    assert mb.safe_lookup(H)["found"] is False

    _mock(monkeypatch, lambda req: httpx.Response(200, json={"query_status": "ok", "data": [
        {"signature": "AgentTesla", "tags": ["exe"], "first_seen": "2026-01-01 00:00:00"}]}))
    r = mb.safe_lookup(H)
    assert r["found"] and r["verdict"] == "malicious" and r["label"] == "AgentTesla"


def test_provider_errors_are_contained(monkeypatch):
    _mock(monkeypatch, lambda req: httpx.Response(429))
    ha = intel.HybridAnalysis(); ha.api_key = "k"
    r = ha.safe_lookup(H)
    assert r["error"] and "rate limited" in r["error"] and not r["found"]


def test_summary_takes_worst_verdict_and_merges_labels():
    p = intel.VirusTotal()
    rs = [intel._result(p, found=True, verdict="suspicious", label="Emotet"),
          intel._result(p, found=True, verdict="malicious", label="emotet, Heodo"),
          intel._result(p)]
    s = intel.summarize(rs)
    assert s["verdict"] == "malicious" and s["hits"] == 2 and s["labels"] == ["Emotet", "Heodo"]


def test_service_caches_and_requeries_newly_keyed(monkeypatch, tmp_path):
    calls = []

    def handler(req):
        calls.append(req.url.host)
        if "virustotal" in req.url.host:
            return httpx.Response(404)
        return httpx.Response(200, json={"query_status": "hash_not_found"})
    _mock(monkeypatch, handler)
    lab = MalLab(tmp_path)
    lab.intel.providers = [p for p in lab.intel.providers if p.id in ("vt", "mb")]
    s = lab.ingest(lab.store.create_case("t")["id"], SAMPLE, "x.exe")

    lab.set_keys(vt_key="k")
    lab.threat_intel(s["id"])
    assert calls == ["www.virustotal.com"]

    lab.threat_intel(s["id"])                       # cached: no new calls
    assert calls == ["www.virustotal.com"]

    lab.set_keys(abusech_key="k")                    # new key: only the new provider is queried
    out = lab.threat_intel(s["id"])
    assert calls == ["www.virustotal.com", "mb-api.abuse.ch"]
    assert {r["id"]: r["configured"] for r in out["providers"]} == {"vt": True, "mb": True}

    lab.threat_intel(s["id"], refresh=True)          # refresh re-queries everything
    assert len(calls) == 4


def test_blank_key_does_not_clear_existing(tmp_path):
    lab = MalLab(tmp_path)
    lab.set_keys(vt_key="k1")
    lab.set_keys(vt_key="", abusech_key="")
    assert lab.intel.by_id["vt"].api_key == "k1"
