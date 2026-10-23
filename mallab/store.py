"""Persistence for the lab: cases, samples and detonation runs in SQLite.

Layout under <lab_root>:
    mallab.db              the catalog
    quarantine/<sha256>    the raw sample bytes, stored as `sample.bin` (never the
                           original extension, so nothing on the host treats it as runnable)
    reports/<sha256>/      static.json and dynamic-<run_id>.json
"""

import hashlib
import json
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT DEFAULT '',
    created REAL NOT NULL, notes TEXT DEFAULT '', tags TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS samples (
    id TEXT PRIMARY KEY, case_id TEXT NOT NULL,
    filename TEXT NOT NULL, sha256 TEXT NOT NULL, sha1 TEXT, md5 TEXT,
    size INTEGER, file_type TEXT, source TEXT DEFAULT 'upload',
    added REAL NOT NULL, status TEXT DEFAULT 'quarantined',
    risk INTEGER DEFAULT 0, labels TEXT DEFAULT '',
    FOREIGN KEY(case_id) REFERENCES cases(id)
);
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY, sample_id TEXT NOT NULL,
    kind TEXT NOT NULL, started REAL, finished REAL,
    status TEXT DEFAULT 'queued', verdict TEXT DEFAULT '',
    report TEXT DEFAULT '', config TEXT DEFAULT '{}',
    FOREIGN KEY(sample_id) REFERENCES samples(id)
);
CREATE TABLE IF NOT EXISTS actors (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, aliases TEXT DEFAULT '', mitre_id TEXT DEFAULT '',
    families TEXT DEFAULT '', techniques TEXT DEFAULT '', country TEXT DEFAULT '',
    motivation TEXT DEFAULT '', description TEXT DEFAULT '', notes TEXT DEFAULT '',
    source TEXT DEFAULT 'analyst', created REAL NOT NULL, updated REAL
);
CREATE TABLE IF NOT EXISTS actor_links (
    actor_id TEXT NOT NULL, kind TEXT NOT NULL, target_id TEXT NOT NULL,
    confidence TEXT DEFAULT 'low', note TEXT DEFAULT '', added REAL,
    PRIMARY KEY(actor_id, kind, target_id)
);
CREATE INDEX IF NOT EXISTS idx_samples_case ON samples(case_id);
CREATE INDEX IF NOT EXISTS idx_runs_sample ON runs(sample_id);
"""


def _id() -> str:
    return uuid.uuid4().hex[:12]


class Store:
    def __init__(self, lab_root: Path):
        self.root = Path(lab_root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "quarantine").mkdir(exist_ok=True)
        (self.root / "reports").mkdir(exist_ok=True)
        self.db_path = self.root / "mallab.db"
        with self._conn() as c:
            c.executescript(SCHEMA)
            cols = {r["name"] for r in c.execute("PRAGMA table_info(samples)")}
            if "notes" not in cols:   # added after the first release
                c.execute("ALTER TABLE samples ADD COLUMN notes TEXT DEFAULT ''")

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    # ---- paths

    def quarantine_dir(self, sha256: str) -> Path:
        d = self.root / "quarantine" / sha256
        d.mkdir(parents=True, exist_ok=True)
        return d

    def sample_path(self, sha256: str) -> Path:
        return self.quarantine_dir(sha256) / "sample.bin"

    def read_sample(self, sha256: str) -> bytes:
        """Quarantined bytes, verified against their hash (chain of custody: a sample that was
        altered or swapped on disk is refused instead of analyzed as if it were the original)."""
        p = self.root / "quarantine" / sha256 / "sample.bin"
        if not p.is_file():
            raise ValueError("quarantined file is missing")
        data = p.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha256:
            raise ValueError(f"integrity check failed: {p} no longer matches SHA-256 {sha256[:16]}…")
        return data

    def report_dir(self, sha256: str) -> Path:
        d = self.root / "reports" / sha256
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ---- cases

    def create_case(self, name: str, description: str = "", tags: str = "") -> dict:
        cid = _id()
        with self._conn() as c:
            c.execute("INSERT INTO cases(id,name,description,created,tags) VALUES(?,?,?,?,?)",
                      (cid, name.strip() or "Untitled case", description, time.time(), tags))
        return self.get_case(cid)

    def get_case(self, cid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
            return dict(row) if row else None

    def list_cases(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM cases ORDER BY created DESC").fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["sample_count"] = c.execute(
                    "SELECT COUNT(*) FROM samples WHERE case_id=?", (r["id"],)).fetchone()[0]
                out.append(d)
            return out

    def update_case(self, cid: str, **fields) -> dict | None:
        allowed = {k: v for k, v in fields.items() if k in ("name", "description", "notes", "tags")}
        if allowed:
            sets = ", ".join(f"{k}=?" for k in allowed)
            with self._conn() as c:
                c.execute(f"UPDATE cases SET {sets} WHERE id=?", (*allowed.values(), cid))
        return self.get_case(cid)

    # ---- threat groups

    ACTOR_FIELDS = ("name", "aliases", "mitre_id", "families", "techniques", "country",
                    "motivation", "description", "notes", "source")

    def create_actor(self, **f) -> dict:
        aid = _id()
        vals = {k: str(f.get(k) or "") for k in self.ACTOR_FIELDS}
        vals["name"] = vals["name"].strip() or "Unnamed group"
        vals["source"] = vals["source"] or "analyst"
        with self._conn() as c:
            c.execute(f"INSERT INTO actors(id,{','.join(vals)},created,updated) VALUES(?{',?' * len(vals)},?,?)",
                      (aid, *vals.values(), time.time(), time.time()))
        return self.get_actor(aid)

    def get_actor(self, aid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM actors WHERE id=?", (aid,)).fetchone()
            return dict(row) if row else None

    def find_actor(self, mitre_id: str = "", name: str = "") -> dict | None:
        with self._conn() as c:
            row = None
            if mitre_id:
                row = c.execute("SELECT * FROM actors WHERE mitre_id=?", (mitre_id,)).fetchone()
            if not row and name:
                row = c.execute("SELECT * FROM actors WHERE lower(name)=lower(?)", (name,)).fetchone()
            return dict(row) if row else None

    def list_actors(self) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("""SELECT a.*, (SELECT COUNT(*) FROM actor_links l WHERE l.actor_id=a.id) AS link_count
                                FROM actors a ORDER BY link_count DESC, lower(a.name)""").fetchall()
            return [dict(r) for r in rows]

    def update_actor(self, aid: str, **f) -> dict | None:
        allowed = {k: str(v) for k, v in f.items() if k in self.ACTOR_FIELDS and v is not None}
        if allowed:
            sets = ", ".join(f"{k}=?" for k in allowed)
            with self._conn() as c:
                c.execute(f"UPDATE actors SET {sets}, updated=? WHERE id=?", (*allowed.values(), time.time(), aid))
        return self.get_actor(aid)

    def delete_actor(self, aid: str):
        with self._conn() as c:
            c.execute("DELETE FROM actor_links WHERE actor_id=?", (aid,))
            c.execute("DELETE FROM actors WHERE id=?", (aid,))

    def link_actor(self, aid: str, kind: str, target_id: str, confidence: str = "low", note: str = ""):
        with self._conn() as c:
            c.execute("""INSERT INTO actor_links(actor_id,kind,target_id,confidence,note,added) VALUES(?,?,?,?,?,?)
                         ON CONFLICT(actor_id,kind,target_id) DO UPDATE SET confidence=excluded.confidence,
                         note=excluded.note""", (aid, kind, target_id, confidence, note, time.time()))

    def unlink_actor(self, aid: str, kind: str, target_id: str):
        with self._conn() as c:
            c.execute("DELETE FROM actor_links WHERE actor_id=? AND kind=? AND target_id=?", (aid, kind, target_id))

    def actor_links(self, aid: str | None = None, kind: str | None = None, target_id: str | None = None) -> list[dict]:
        q, args = "SELECT l.*, a.name AS actor_name FROM actor_links l JOIN actors a ON a.id=l.actor_id WHERE 1=1", []
        for col, v in (("l.actor_id", aid), ("l.kind", kind), ("l.target_id", target_id)):
            if v is not None:
                q += f" AND {col}=?"
                args.append(v)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY l.added DESC", args)]

    def delete_case(self, cid: str):
        with self._conn() as c:
            c.execute("DELETE FROM actor_links WHERE kind='sample' AND target_id IN "
                      "(SELECT id FROM samples WHERE case_id=?)", (cid,))
            c.execute("DELETE FROM actor_links WHERE kind='case' AND target_id=?", (cid,))
            c.execute("DELETE FROM runs WHERE sample_id IN (SELECT id FROM samples WHERE case_id=?)", (cid,))
            c.execute("DELETE FROM samples WHERE case_id=?", (cid,))
            c.execute("DELETE FROM cases WHERE id=?", (cid,))

    # ---- samples

    def add_sample(self, case_id: str, filename: str, hashes: dict, size: int,
                   file_type: str, source: str) -> dict:
        existing = self.find_sample(case_id, hashes["sha256"])
        if existing:
            return existing
        sid = _id()
        with self._conn() as c:
            c.execute("""INSERT INTO samples(id,case_id,filename,sha256,sha1,md5,size,file_type,source,added)
                         VALUES(?,?,?,?,?,?,?,?,?,?)""",
                      (sid, case_id, filename, hashes["sha256"], hashes.get("sha1"),
                       hashes.get("md5"), size, file_type, source, time.time()))
        return self.get_sample(sid)

    def find_sample(self, case_id: str, sha256: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM samples WHERE case_id=? AND sha256=?",
                            (case_id, sha256)).fetchone()
            return dict(row) if row else None

    def sha256_in_use(self, sha256: str) -> bool:
        with self._conn() as c:
            return c.execute("SELECT 1 FROM samples WHERE sha256=? LIMIT 1", (sha256,)).fetchone() is not None

    def get_sample(self, sid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM samples WHERE id=?", (sid,)).fetchone()
            return dict(row) if row else None

    def list_samples(self, case_id: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM samples WHERE case_id=? ORDER BY added DESC",
                             (case_id,)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                d["run_count"] = c.execute(
                    "SELECT COUNT(*) FROM runs WHERE sample_id=?", (r["id"],)).fetchone()[0]
                out.append(d)
            return out

    def all_samples(self) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT s.*, c.name AS case_name FROM samples s JOIN cases c ON c.id = s.case_id")]

    def update_sample(self, sid: str, **fields):
        allowed = {k: v for k, v in fields.items()
                   if k in ("status", "risk", "labels", "file_type", "notes")}
        if allowed:
            sets = ", ".join(f"{k}=?" for k in allowed)
            with self._conn() as c:
                c.execute(f"UPDATE samples SET {sets} WHERE id=?", (*allowed.values(), sid))

    # ---- runs

    def create_run(self, sample_id: str, kind: str, config: dict) -> dict:
        rid = _id()
        with self._conn() as c:
            c.execute("INSERT INTO runs(id,sample_id,kind,started,status,config) VALUES(?,?,?,?,?,?)",
                      (rid, sample_id, kind, time.time(), "running", json.dumps(config)))
        return self.get_run(rid)

    def get_run(self, rid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM runs WHERE id=?", (rid,)).fetchone()
            return dict(row) if row else None

    def list_runs(self, sample_id: str) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM runs WHERE sample_id=? ORDER BY started DESC",
                             (sample_id,)).fetchall()
            return [dict(r) for r in rows]

    def finish_run(self, rid: str, status: str, verdict: str, report_rel: str):
        with self._conn() as c:
            c.execute("UPDATE runs SET status=?, verdict=?, report=?, finished=? WHERE id=?",
                      (status, verdict, report_rel, time.time(), rid))
