"""Regression tests for the code-review fixes: no macro false positives on plain files,
real IPs only, and deleting a case purges its quarantined bytes. Nothing here executes a sample."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import MalLab, static

TEXT_BLOB = b"MZ harmless text http://bad.example/x 198.51.100.9 999.1.2.3 127.0.0.1 version 10.0.19041.1"


def test_plain_file_is_not_reported_as_having_macros(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(TEXT_BLOB)
    rep = static.analyze(p, "a.exe")
    assert "office_macros" not in rep
    assert not any("macro" in r for r in rep["risk_reasons"])


def test_ip_extraction_keeps_real_addresses_only(tmp_path):
    p = tmp_path / "a.bin"
    p.write_bytes(TEXT_BLOB)
    ips = static.analyze(p, "a.exe")["iocs"]["ips"]
    assert "198.51.100.9" in ips
    assert "999.1.2.3" not in ips and "127.0.0.1" not in ips


def test_detonate_passes_a_compatible_emit_to_the_sandbox(tmp_path, monkeypatch):
    """sandbox.detonate calls emit(dict); the service used to pass a **kwargs-only function,
    so every detonation crashed with TypeError before the VM launched."""
    events = []
    lab = MalLab(tmp_path, emit=events.append)
    s = lab.ingest(lab.store.create_case("t")["id"], b"MZ harmless", "x.exe")

    def fake_detonate(data, name, runs_root, *, emit, **kw):
        emit({"type": "lab_log", "text": "launching"})
        return {"verdict": "no observable activity", "detonated": False}
    monkeypatch.setattr("mallab.sandbox.detonate", fake_detonate)

    run = lab.detonate(s["id"])
    assert run["status"] == "done"
    assert any(e.get("text") == "launching" and e["session"] == "lab" for e in events)


def test_deleting_a_case_purges_unshared_samples(tmp_path):
    lab = MalLab(tmp_path)
    a, b = lab.store.create_case("a")["id"], lab.store.create_case("b")["id"]
    only_a = lab.ingest(a, b"MZ only in case a", "x.exe")
    shared = lab.ingest(a, b"MZ in both cases", "y.exe")
    lab.ingest(b, b"MZ in both cases", "y.exe")

    lab.delete_case(a)
    assert not (tmp_path / "quarantine" / only_a["sha256"]).exists()
    assert not (tmp_path / "reports" / only_a["sha256"]).exists()
    assert lab.store.sample_path(shared["sha256"]).exists()        # still used by case b
    assert lab.store.get_case(a) is None
