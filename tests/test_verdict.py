"""The fused sample verdict: combines static risk, detections, intel, YARA, groups into one
answer. Key properties: strong evidence → malicious; absence of evidence → unknown, never clean."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab, verdict


def det(*names_sevs):
    return {"detections": [{"name": n, "severity": s, "attck": []} for n, s in names_sevs],
            "max_severity": max((s for _, s in names_sevs), key=lambda s: ["info", "low", "medium", "high"].index(s), default="info"),
            "attck": []}


def test_strong_detection_is_malicious():
    v = verdict.assess(static={"risk": 40}, detections=det(("LSASS memory access", "high")),
                       dynamic={"detonated": True})
    assert v["verdict"] == "malicious" and v["score"] >= 70


def test_intel_consensus_is_malicious_with_family():
    v = verdict.assess(static={"risk": 10}, intel={"verdict": "malicious", "hits": 4, "labels": ["Trojan.Win32.Emotet"]})
    assert v["verdict"] == "malicious" and v["family"] == "Emotet" and v["confidence"] == "high"


def test_no_evidence_is_unknown_not_clean():
    v = verdict.assess(static={"risk": 0}, detections=det(), dynamic={"detonated": False})
    assert v["verdict"] == "unknown"
    assert any("not detonated" in r for r in v["reasons"])


def test_clean_only_when_intel_says_so():
    v = verdict.assess(static={"risk": 5}, detections=det(), intel={"verdict": "clean", "hits": 3})
    assert v["verdict"] == "clean"


def test_medium_activity_is_suspicious():
    v = verdict.assess(static={"risk": 30}, detections=det(("Network download capability", "medium")))
    assert v["verdict"] == "suspicious"


def test_family_extraction_skips_generic_words():
    assert verdict._family_from_label("Trojan:Win32/Wacatac.B!ml") == "Wacatac"
    assert verdict._family_from_label("Backdoor.Linux.Mirai") == "Mirai"
    assert verdict._family_from_label("Trojan.Generic") is None


def test_yara_pack_family_but_not_generic_rules():
    static = {"yara": {"matches": [{"rule": "MAL_Ransom_LockBit_Nov22", "source": "yara-rules-core"},
                                   {"rule": "SUSP_Packed_Entropy", "source": "yara-rules-core"},
                                   {"rule": "MyOwnRule", "source": "rules"}]}}
    fams = verdict._families({}, {}, static, None, None)
    assert any("LockBit" in f or "Nov22" in f for f in fams)
    assert not any("SUSP" in f or "MyOwnRule" in f for f in fams)


def test_case_worst_rolls_up(tmp_path):
    a = verdict.assess(intel={"verdict": "malicious", "hits": 3, "labels": ["win.qakbot"]})
    b = verdict.assess(static={"risk": 20})
    w = verdict.worst([b, a])
    assert w["verdict"] == "malicious" and "Qakbot" in w["families"]


def test_service_verdict_end_to_end(tmp_path):
    lab = MalLab(tmp_path)
    cid = lab.store.create_case("t")["id"]
    # A PE importing the classic injection set gets static detections -> at least suspicious.
    s = lab.ingest(cid, b"MZ" + b"VirtualAllocEx WriteProcessMemory CreateRemoteThread " * 2, "x.exe")
    v = lab.sample_verdict(s["id"])
    assert v["verdict"] in ("suspicious", "malicious", "unknown")
    assert set(v) >= {"verdict", "score", "confidence", "family", "families", "reasons"}
    detail = lab.case_detail(cid)
    assert "verdict" in detail and detail["samples"][0].get("verdict")
