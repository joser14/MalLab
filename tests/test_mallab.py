"""MalLab tests: samples are quarantined (never stored runnable), static triage scores
risk, and the IOC rollup + report aggregate correctly. Nothing here executes a sample."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab
from mallab import static

# A harmless blob with an MZ header and a few fake IOCs as plain text. Never executed.
SAMPLE = b"MZ this is not a real program http://bad.example/x 198.51.100.9 nastysite.top HKCU\\Software\\Run"


@pytest.fixture
def lab(tmp_path):
    return MalLab(tmp_path)


def test_sample_is_quarantined_by_hash_not_extension(lab):
    case = lab.store.create_case("t")
    s = lab.ingest(case["id"], SAMPLE, "invoice.exe")
    stored = lab.store.sample_path(s["sha256"])
    assert stored.name == "sample.bin"          # never the real .exe extension
    assert stored.read_bytes() == SAMPLE
    assert s["sha256"] == static._hashes(SAMPLE)["sha256"]


def test_static_triage_finds_iocs_and_scores_risk(lab):
    case = lab.store.create_case("t")
    s = lab.ingest(case["id"], SAMPLE, "invoice.exe")
    rep = lab.static_report(s["id"])
    assert rep["iocs"]["urls"] == ["http://bad.example/x"]
    assert "198.51.100.9" in rep["iocs"]["ips"]
    assert rep["risk"] >= 0 and isinstance(rep["risk_reasons"], list)


def test_ioc_rollup_dedupes_across_samples(lab):
    case = lab.store.create_case("t")
    lab.ingest(case["id"], SAMPLE, "a.exe")
    lab.ingest(case["id"], SAMPLE + b" extra", "b.exe")
    iocs = lab.case_iocs(case["id"])
    assert "http://bad.example/x" in iocs["urls"]
    assert len(iocs["hashes"]) == 2
    assert iocs["urls"] == sorted(set(iocs["urls"]))  # de-duplicated & sorted


def test_report_is_markdown_with_sections(lab):
    case = lab.store.create_case("Phish", "email attachment")
    lab.ingest(case["id"], SAMPLE, "invoice.exe")
    md = lab.export_report(case["id"])
    assert md.startswith("# Malware analysis report: Phish")
    assert "Indicators of compromise" in md
    assert "invoice.exe" in md


def test_entropy_and_type_detection():
    assert static.detect_type(b"MZ\x90\x00", "x") == "PE executable (EXE/DLL)"
    assert static.detect_type(b"%PDF-1.7", "x") == "PDF document"
    assert static.shannon_entropy(b"") == 0.0
    assert static.shannon_entropy(b"aaaa") == 0.0  # no variety -> zero entropy


def test_detonate_refused_when_sandbox_unavailable(lab, monkeypatch):
    # Detonation must never fall back to running on the host.
    monkeypatch.setattr("mallab.sandbox.available", lambda: (False, "sandbox off"))
    case = lab.store.create_case("t")
    s = lab.ingest(case["id"], SAMPLE, "x.exe")
    with pytest.raises(RuntimeError):
        lab.detonate(s["id"])
