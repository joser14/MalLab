"""The standalone server: only this computer may use it, uploads are size-capped, and the
core flow (create case, upload, read reports) works end to end. Nothing is executed."""

import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import server
from mallab import MalLab

LOCAL = ("127.0.0.1", 50000)


@pytest.fixture
def app(tmp_path):
    return server.LocalOnly(server.build_app(MalLab(tmp_path), server.Hub()))


def client(app, peer=LOCAL, host="127.0.0.1:7860"):
    return TestClient(app, base_url=f"http://{host}", client=peer)


def test_page_and_state_load_locally(app):
    c = client(app)
    assert c.get("/").status_code == 200
    s = c.get("/api/lab/state").json()
    assert "cases" in s and "sandbox" in s and "intel" in s


@pytest.mark.parametrize("peer,host,headers", [
    (("192.168.1.20", 5000), "127.0.0.1:7860", {}),                       # another machine
    (LOCAL, "evil.example:7860", {}),                                     # DNS rebinding
    (LOCAL, "127.0.0.1:7860", {"Origin": "https://evil.example"}),        # cross-site page
    (LOCAL, "127.0.0.1:7860", {"Sec-Fetch-Site": "cross-site"}),
])
def test_non_local_requests_are_refused(app, peer, host, headers):
    r = client(app, peer, host).post("/api/lab/case", json={"name": "x"}, headers=headers)
    assert r.status_code == 403


def test_upload_flow_and_size_cap(app, monkeypatch):
    c = client(app)
    cid = c.post("/api/lab/case", json={"name": "t"}).json()["id"]
    r = c.post(f"/api/lab/case/{cid}/upload", content=b"MZ harmless http://bad.example/x",
               headers={"X-Filename": "a.exe"}).json()
    sid = r["samples"][0]["id"]
    assert c.get(f"/api/lab/sample/{sid}/static").json()["iocs"]["urls"] == ["http://bad.example/x"]
    assert c.get(f"/api/lab/case/{cid}").json()["samples"][0]["id"] == sid

    monkeypatch.setattr(server, "MAX_UPLOAD_BYTES", 10)
    r = c.post(f"/api/lab/case/{cid}/upload", content=b"x" * 11, headers={"X-Filename": "big.bin"})
    assert r.status_code == 413


def test_bundled_fonts_are_served_and_nothing_else(app):
    c = client(app)
    r = c.get("/fonts/inter.woff2")
    assert r.status_code == 200 and r.headers["content-type"] == "font/woff2" and r.content[:4] == b"wOF2"
    for bad in ("/fonts/OFL-Inter.txt", "/fonts/..%2F..%2Fserver.py", "/fonts/missing.woff2"):
        assert c.get(bad).status_code == 404


def test_bad_numbers_do_not_crash(app):
    c = client(app)
    r = c.post("/api/lab/sample/nope/detonate", json={"timeout": "abc"})
    assert r.status_code == 200      # accepted; the background job reports "no such sample" over events
