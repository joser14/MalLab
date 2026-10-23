"""MalLab service: orchestrates ingest -> static triage -> isolated detonation, plus sample
acquisition and threat-intel lookups. Holds no web concerns; server.py mounts HTTP routes over it.
"""

import csv
import hashlib
import io
import ipaddress
import json
import re
import shutil
import threading
import time
from pathlib import Path

from . import (actors, archives, defender, diffing, fakenet, intel, ioc_intel, netguard, sandbox, signatures,
               static, tooling, yara_rules)
from .samples import SampleSource, sha256_of
from .store import Store

QUICK_CASE_NAME = "Quick Detonate"
_SHOT_RE = re.compile(r"screenshot-[0-9a-f]{10}\.png")
_PCAP_RE = re.compile(r"capture-[0-9a-f]{10}\.pcapng")

# Domains every fresh Windows VM resolves on its own: not the sample's infrastructure.
NOISE_DOMAINS = re.compile(r"(^|\.)(microsoft\.com|windows\.com|windowsupdate\.com|msftncsi\.com|"
                           r"msftconnecttest\.com|live\.com|bing\.com|msn\.com|office\.com|office\.net|"
                           r"azureedge\.net|akamaitechnologies\.com|digicert\.com|"
                           r"skype\.com|xboxlive\.com|wpad|localhost|local)$", re.I)


endpoint_host = diffing.endpoint_host


def _public_ip(s: str) -> bool:
    try:
        return ipaddress.ip_address(s).is_global
    except ValueError:
        return False


def _stix_bundle(case: dict, rows: list[tuple[str, str, str]]) -> dict:
    """A STIX 2.1 bundle of indicators (one per IOC) for MISP / OpenCTI / a SIEM."""
    import uuid
    now = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())

    def esc(v):
        return v.replace("\\", "\\\\").replace("'", "\\'")
    patterns = {"sha256": "[file:hashes.'SHA-256' = '{}']", "md5": "[file:hashes.MD5 = '{}']",
                "url": "[url:value = '{}']", "domain": "[domain-name:value = '{}']"}
    objs = []
    for t, v, ctx in rows:
        if t == "ip":
            pat = f"[{'ipv6' if ':' in v else 'ipv4'}-addr:value = '{esc(v)}']"
        else:
            pat = patterns[t].format(esc(v))
        objs.append({"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}",
                     "created": now, "modified": now, "valid_from": now,
                     "name": f"{t}: {v}"[:200], "description": f"MalLab case {case['name']}" + (f" ({ctx})" if ctx else ""),
                     "indicator_types": ["malicious-activity"], "pattern": pat, "pattern_type": "stix"})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objs}


def PathName(p: str) -> str:
    return str(p).replace("/", "\\").rsplit("\\", 1)[-1] or "?"


def _iso_ts(s: str) -> float | None:
    import datetime
    try:
        # PowerShell's "o" format has 7 fractional digits; Python 3.11+ truncates past 6.
        return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def defang(v: str) -> str:
    """Make an indicator safe to paste into tickets/chat: hxxp://, [.] dots."""
    v = re.sub(r"^http", "hxxp", v, flags=re.I)
    return v.replace(".", "[.]")

# Compact Sysmon config: log the events that matter for triage without drowning the log.
# (An empty "exclude" logs everything; an empty "include" logs nothing.) ImageLoad is off
# because every DLL load would bury the interesting events; process access is limited to
# LSASS (credential dumping).
_DEFAULT_SYSMON_CONFIG = r"""<!-- mallab default -->
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <ProcessCreate onmatch="exclude"></ProcessCreate>
    <NetworkConnect onmatch="exclude"></NetworkConnect>
    <ImageLoad onmatch="include"></ImageLoad>
    <CreateRemoteThread onmatch="exclude"></CreateRemoteThread>
    <ProcessAccess onmatch="include"><TargetImage condition="end with">lsass.exe</TargetImage></ProcessAccess>
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">\CurrentVersion\Policies\Explorer\Run</TargetObject>
      <TargetObject condition="contains">\CurrentControlSet\Services\</TargetObject>
      <TargetObject condition="contains">\Winlogon\</TargetObject>
      <TargetObject condition="contains">\Image File Execution Options\</TargetObject>
      <TargetObject condition="contains">\Windows Defender\</TargetObject>
      <TargetObject condition="contains">\Explorer\Shell Folders</TargetObject>
      <TargetObject condition="contains">\Classes\CLSID\</TargetObject>
      <TargetObject condition="contains">\Environment\</TargetObject>
      <TargetObject condition="contains">\Schedule\TaskCache\</TargetObject>
      <TargetObject condition="contains">\AppInit_DLLs</TargetObject>
      <TargetObject condition="end with">\Shell\Open\Command\(Default)</TargetObject>
    </RegistryEvent>
    <FileCreate onmatch="exclude"></FileCreate>
    <FileDeleteDetected onmatch="exclude"></FileDeleteDetected>
    <DnsQuery onmatch="exclude"></DnsQuery>
    <WmiEvent onmatch="exclude"></WmiEvent>
  </EventFiltering>
</Sysmon>
"""


class MalLab:
    def __init__(self, lab_root: Path, emit=lambda e: None, yara_dir: Path | None = None):
        self.lab_root = Path(lab_root)
        self.store = Store(Path(lab_root))
        self.runs_root = Path(lab_root) / "runs"
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.emit = emit
        self.yara_dir = Path(yara_dir) if yara_dir else (Path(lab_root) / "yara")
        self.tools_dir = Path(lab_root) / "tools"
        self.tools_dir.mkdir(parents=True, exist_ok=True)
        self.intel_dir = Path(lab_root) / "intel"   # IOC-enrichment caches, Feodo blocklist
        self.intel_dir.mkdir(parents=True, exist_ok=True)
        self.source = SampleSource()
        self.intel = intel.ThreatIntel()
        self.detonate_lock = threading.Lock()  # one sandbox VM at a time
        self.detonating = False
        yara_rules.ensure_starter(self.yara_dir)  # ship a starter ruleset on first run
        try:
            self._refresh_sysmon_config()             # upgrades an older MalLab default in place
        except OSError:
            pass

    def _emit(self, **ev):
        self.emit({"session": "lab", **ev})

    # ---- ingest & static ------------------------------------------------

    def ingest(self, case_id: str, data: bytes, filename: str, source: str = "upload") -> dict:
        if not self.store.get_case(case_id):
            raise ValueError("no such case")
        digest = sha256_of(data)
        self.store.sample_path(digest).write_bytes(data)  # quarantined as .bin
        hashes = {"sha256": digest,
                  "sha1": hashlib.sha1(data).hexdigest(),
                  "md5": hashlib.md5(data).hexdigest()}
        ftype = static.detect_type(data, filename)
        sample = self.store.add_sample(case_id, filename, hashes, len(data), ftype, source)
        self._emit(type="lab_log", text=f"Quarantined {filename} ({len(data):,} bytes) — {ftype}")
        self.run_static(sample["id"])
        return self.store.get_sample(sample["id"])

    def ingest_any(self, case_id: str, data: bytes, filename: str, source: str = "upload",
                   unpack: bool = True, password: str | None = None) -> dict:
        """Ingest a file; if it's a zip/7z and unpack is on, quarantine each member instead
        (tries the given password, then "infected" and other sharing conventions).
        Returns {"samples": [...], "archive": {...} | None}, samples sorted riskiest first."""
        if not unpack or not archives.kind(data):
            return {"samples": [self.ingest(case_id, data, filename, source)], "archive": None}
        if not self.store.get_case(case_id):
            raise ValueError("no such case")
        try:
            res = archives.unpack(data, password)
        except archives.ArchiveError as e:
            if str(e) == "wrong password":
                raise ValueError(f"{filename}: wrong password — tried "
                                 f"{', '.join(repr(p) for p in archives._passwords(password) if p)}. "
                                 "Enter the archive's password and try again.") from e
            raise ValueError(f"{filename}: {e}") from e
        pw = f" (password {res['password']!r})" if res["password"] else ""
        self._emit(type="lab_log", text=f"Unpacked {filename}{pw}: {len(res['members'])} file(s)")
        samples = [self.ingest(case_id, blob, name, f"{source} ← {filename}")
                   for name, blob in res["members"]]
        samples.sort(key=lambda s: s.get("risk") or 0, reverse=True)
        return {"samples": samples, "archive": {"name": filename, "kind": res["kind"],
                                                "password": res["password"], "count": len(samples)}}

    def run_static(self, sample_id: str) -> dict:
        s = self.store.get_sample(sample_id)
        if not s:
            raise ValueError("no such sample")
        self._emit(type="lab_log", text=f"Static triage of {s['filename']}…")
        self.store.read_sample(s["sha256"])   # integrity check before trusting the bytes
        report = static.analyze(self.store.sample_path(s["sha256"]), s["filename"], self.yara_dir,
                                self.tools_dir)
        (self.store.report_dir(s["sha256"]) / "static.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8")
        self.store.update_sample(sample_id, risk=report["risk"], file_type=report["file_type"],
                                 status="analyzed")
        self._emit(type="lab_static_done", sample_id=sample_id, risk=report["risk"])
        return report

    def static_report(self, sample_id: str) -> dict | None:
        s = self.store.get_sample(sample_id)
        if not s:
            return None
        f = self.store.report_dir(s["sha256"]) / "static.json"
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None

    # ---- detonation -----------------------------------------------------

    def sandbox_status(self) -> dict:
        ok, msg = sandbox.available()
        return {"available": ok, "message": msg, "busy": self.detonating}

    def detonate(self, sample_id: str, *, timeout: int = 60, networking: bool = False,
                 memory_mb: int = 4096, do_detonate: bool = True, safe_net: bool = True,
                 simulate: bool = False) -> dict:
        s = self.store.get_sample(sample_id)
        if not s:
            raise ValueError("no such sample")
        if simulate and not fakenet.find(self.tools_dir):
            raise RuntimeError(fakenet.missing_message(self.tools_dir))
        if not self.detonate_lock.acquire(blocking=False):
            raise RuntimeError("A detonation is already running (one sandbox at a time).")
        self.detonating = True
        networking = networking or simulate
        cfg = {"timeout": timeout, "networking": networking, "memory_mb": memory_mb,
               "do_detonate": do_detonate, "safe_net": safe_net and not simulate, "simulate": simulate}
        run = self.store.create_run(sample_id, "dynamic", cfg)
        self._emit(type="lab_run_started", run_id=run["id"], sample_id=sample_id)
        try:
            guard = None
            if networking:
                guard = self.netguard_status().get("enabled") is True
                if not guard:
                    self._emit(type="lab_log", text="Warning: the host network guard is off, so the networked "
                                                    "sandbox can reach services on this PC. Turn it on in Settings.")
            data = self.store.read_sample(s["sha256"])
            report = sandbox.detonate(data, s["filename"], self.runs_root,
                                      timeout=timeout, networking=networking,
                                      memory_mb=memory_mb, do_detonate=do_detonate,
                                      emit=lambda ev: self._emit(**ev),
                                      artifact_dir=self.store.report_dir(s["sha256"]),
                                      tools_dir=self.tools_dir, safe_net=safe_net,
                                      simulate=simulate, host_guard=guard)
            dropped = report.pop("_dropped_blobs", None) or []
            rel = f"dynamic-{run['id']}.json"
            (self.store.report_dir(s["sha256"]) / rel).write_text(
                json.dumps(report, indent=2), encoding="utf-8")
            self.store.finish_run(run["id"], "done", report.get("verdict", ""), rel)
            self._ingest_dropped(s, dropped)
            self._emit(type="lab_run_done", run_id=run["id"], sample_id=sample_id,
                       verdict=report.get("verdict", ""))
            return self.store.get_run(run["id"])
        except Exception as e:
            self.store.finish_run(run["id"], "error", f"{type(e).__name__}: {e}", "")
            self._emit(type="lab_run_done", run_id=run["id"], sample_id=sample_id,
                       verdict=f"error: {e}")
            raise
        finally:
            self.detonating = False
            self.detonate_lock.release()

    def _ingest_dropped(self, parent: dict, blobs: list[tuple[str, bytes]]):
        """Add files the sample dropped to the parent's case as child samples (static triage only)."""
        for path, data in blobs:
            name = path.replace("/", "\\").rsplit("\\", 1)[-1][:200] or "dropped.bin"
            try:
                self.ingest(parent["case_id"], data, name, f"dropped by {parent['filename']}")
            except Exception as e:
                self._emit(type="lab_log", text=f"Could not ingest dropped file {name}: {e}")

    def open_sandbox(self, sample_id: str | None = None) -> dict:
        """Open a hardened, network-off Windows Sandbox for hands-on work, optionally with one
        sample staged read-only on its desktop."""
        if self.detonating:
            raise RuntimeError("A detonation is running; wait for it to finish.")
        sample = None
        if sample_id:
            s = self.store.get_sample(sample_id)
            if not s:
                raise ValueError("no such sample")
            sample = (self.store.read_sample(s["sha256"]), s["filename"])
        res = sandbox.open_interactive(self.runs_root, sample)
        self._emit(type="lab_log", text="Opened a hardened Windows Sandbox (networking off, no GPU, "
                                        "clipboard/audio/video/printer disconnected)"
                                        + (f" with {res['staged']} in Desktop\\input" if res["staged"] else "") + ".")
        return res

    def dynamic_report(self, sample_id: str, run_id: str) -> dict | None:
        s = self.store.get_sample(sample_id)
        run = self.store.get_run(run_id)
        if not s or not run or not run["report"] or run["sample_id"] != sample_id:
            return None
        f = self.store.report_dir(s["sha256"]) / run["report"]
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None

    # ---- quick detonate (no case setup, no walkthrough) -----------------

    def quick_case(self) -> dict:
        for c in self.store.list_cases():
            if c["name"] == QUICK_CASE_NAME:
                return c
        return self.store.create_case(QUICK_CASE_NAME, "Ad-hoc one-shot detonations.")

    def quick_detonate(self, data: bytes, filename: str, *, timeout: int = 60,
                       networking: bool = False, do_detonate: bool = True,
                       safe_net: bool = True, unpack: bool = True,
                       password: str | None = None, simulate: bool = False) -> dict:
        """Drop a file in, get static + dynamic analysis back. No setup, no guidance.
        An archive is unpacked; every member is triaged and the riskiest one is detonated."""
        if do_detonate and simulate and not fakenet.find(self.tools_dir):   # refuse before ingesting
            raise RuntimeError(fakenet.missing_message(self.tools_dir))
        case = self.quick_case()
        got = self.ingest_any(case["id"], data, filename, "quick", unpack, password)
        sample = got["samples"][0]
        run = None
        if do_detonate:
            run = self.detonate(sample["id"], timeout=timeout, networking=networking,
                                do_detonate=True, safe_net=safe_net, simulate=simulate)
        return {"sample": self.store.get_sample(sample["id"]),
                "static": self.static_report(sample["id"]),
                "run": run,
                "dynamic": self.dynamic_report(sample["id"], run["id"]) if run else None,
                "detections": self.detections(sample["id"]),
                "archive": got["archive"],
                "siblings": [{"id": s["id"], "filename": s["filename"], "risk": s.get("risk"),
                              "file_type": s.get("file_type")} for s in got["samples"][1:]]}

    # ---- acquisition ----------------------------------------------------

    def acquire_hash(self, case_id: str, sha256: str, unpack: bool = True,
                     password: str | None = None) -> dict:
        self._emit(type="lab_log", text=f"Fetching {sha256[:16]}… from repository")
        data, name = self.source.fetch_by_hash(sha256)
        return self.ingest_any(case_id, data, name, "vx-underground", unpack, password)

    def acquire_url(self, case_id: str, url: str, unpack: bool = True,
                    password: str | None = None) -> dict:
        self._emit(type="lab_log", text=f"Downloading {url}")
        data, name = self.source.fetch_url(url)
        return self.ingest_any(case_id, data, name, "url", unpack, password)

    def search_repo(self, query: str, limit: int = 25) -> list[dict]:
        return self.source.search(query, limit)

    # ---- signatures / ATT&CK / process tree ----------------------------

    def detections(self, sample_id: str) -> dict:
        """Named behavioral/static detections with MITRE ATT&CK tags, over the latest reports."""
        static_rep = self.static_report(sample_id)
        runs = self.store.list_runs(sample_id)
        dyn = None
        for run in runs:  # newest first; use the most recent completed detonation
            dyn = self.dynamic_report(sample_id, run["id"])
            if dyn:
                break
        result = signatures.evaluate(static_rep, dyn)
        result["process_tree"] = signatures.process_tree(dyn)
        return result

    def screenshot_path(self, sample_id: str, run_id: str) -> Path | None:
        s = self.store.get_sample(sample_id)
        run = self.store.get_run(run_id)
        if not s or not run:
            return None
        return self._artifact(s, (self.dynamic_report(sample_id, run_id) or {}).get("screenshot"),
                              _SHOT_RE)

    def pcap_path(self, sample_id: str, run_id: str) -> Path | None:
        s = self.store.get_sample(sample_id)
        if not s:
            return None
        return self._artifact(s, (self.dynamic_report(sample_id, run_id) or {}).get("pcap"), _PCAP_RE)

    def _artifact(self, s: dict, name, pattern) -> Path | None:
        """Resolve a run artifact by its host-assigned name only; anything else (e.g. a forged
        path from an old report) is refused rather than served from the host's disk."""
        if not isinstance(name, str) or not pattern.fullmatch(name):
            return None
        d = self.store.report_dir(s["sha256"]).resolve()
        p = (d / name).resolve()
        return p if p.parent == d and p.is_file() else None

    def beacon_timeline(self, sample_id: str, run_id: str) -> dict:
        return diffing.beacon_timeline(self.dynamic_report(sample_id, run_id) or {})

    # ---- diffing / comparison ------------------------------------------

    def diff_runs(self, sample_id: str, run_a: str, run_b: str) -> dict:
        a = self.dynamic_report(sample_id, run_a)
        b = self.dynamic_report(sample_id, run_b)
        if not a or not b:
            raise ValueError("both runs need a saved report to diff")
        return diffing.diff_runs(a, b)

    def related_samples(self, sample_id: str, limit: int = 25) -> list[dict]:
        """Other samples anywhere in the lab that look related: same imphash (same import table,
        often same builder/family), TLSH distance <= 100 (similar bytes), or shared network IOCs."""
        s = self.store.get_sample(sample_id)
        if not s:
            raise ValueError("no such sample")
        me = self.static_report(sample_id) or {}
        my_imp = (me.get("pe") or {}).get("imphash")
        my_tlsh = (me.get("hashes") or {}).get("tlsh")
        my_iocs = set(sum(((me.get("iocs") or {}).get(k, []) for k in ("urls", "ips", "domains")), []))
        out, seen = [], {s["sha256"]}
        for o in self.store.all_samples():
            if o["sha256"] in seen:
                continue
            st = self.static_report(o["id"]) or {}
            why = []
            if my_imp and (st.get("pe") or {}).get("imphash") == my_imp:
                why.append("same imphash")
            dist = static.tlsh_distance(my_tlsh, (st.get("hashes") or {}).get("tlsh"))
            if dist is not None and dist <= 100:
                why.append(f"TLSH distance {dist}")
            sim = static.minhash_similarity(me.get("strings_minhash"), st.get("strings_minhash"))
            if sim is not None and sim >= 0.5:
                why.append(f"~{round(sim * 100)}% of strings shared")
                if dist is None:   # rank by string overlap when TLSH isn't available
                    dist = round((1 - sim) * 200)
            shared = my_iocs & set(sum(((st.get("iocs") or {}).get(k, []) for k in ("urls", "ips", "domains")), []))
            if shared:
                why.append(f"{len(shared)} shared IOC(s): {', '.join(sorted(shared)[:3])}")
            if why:
                seen.add(o["sha256"])
                out.append({"id": o["id"], "filename": o["filename"], "sha256": o["sha256"],
                            "case_id": o["case_id"], "case_name": o["case_name"], "risk": o.get("risk"),
                            "why": why, "tlsh_distance": dist})
        out.sort(key=lambda r: (r["tlsh_distance"] if r["tlsh_distance"] is not None else 999, -len(r["why"])))
        return out[:limit]

    def generate_yara(self, sample_id: str) -> dict:
        s = self.store.get_sample(sample_id)
        st = self.static_report(sample_id) if s else None
        if not st:
            raise ValueError("no static report for this sample")
        stem = re.sub(r"\W", "_", s["filename"].rsplit(".", 1)[0])[:30] or "sample"
        return {"name": f"auto_{stem}_{s['sha256'][:8]}.yar", "text": yara_rules.generate(st, stem)}

    def case_attck(self, case_id: str) -> list[dict]:
        return signatures.attck_matrix([self.detections(s["id"]) for s in self.store.list_samples(case_id)])

    def case_timeline(self, case_id: str, limit: int = 2000) -> list[dict]:
        """Everything that happened in a case, oldest first: samples added, detonations, and the
        Sysmon events of each run (process starts, connections, DNS, persistence writes)."""
        ev = []
        for s in self.store.list_samples(case_id):
            ev.append({"t": s["added"], "kind": "sample", "sample": s["filename"],
                       "text": f"Added {s['filename']} ({s.get('source')}) risk {s.get('risk')}"})
            for run in self.store.list_runs(s["id"]):
                ev.append({"t": run["started"], "kind": "run", "sample": s["filename"],
                           "text": f"Detonation: {run.get('verdict') or run.get('status')}"})
                beh = (self.dynamic_report(s["id"], run["id"]) or {}).get("behavior") or {}
                for p in beh.get("processes", []):
                    ev.append({"iso": p["time"], "kind": "process", "sample": s["filename"],
                               "text": f"{p['name']} started: {p['cmd'][:200]}"})
                for n in beh.get("network", []):
                    ev.append({"iso": n["time"], "kind": "network", "sample": s["filename"],
                               "text": f"{PathName(n['image'])} -> {n['dst_host'] or n['dst_ip']}:{n['dst_port']}"})
                for q in beh.get("dns", []):
                    ev.append({"iso": q["time"], "kind": "dns", "sample": s["filename"],
                               "text": f"DNS {q['query']}"})
                for r in beh.get("registry", []):
                    if "\\run" in r["key"].lower() or "\\services\\" in r["key"].lower():
                        ev.append({"iso": r["time"], "kind": "persistence", "sample": s["filename"],
                                   "text": f"{r['event']} {r['key']}"})
        for e in ev:
            if "iso" in e:
                e["t"] = _iso_ts(e.pop("iso"))
        ev.sort(key=lambda e: e["t"] or 0)
        return ev[:limit]

    def compare_case(self, case_id: str) -> dict:
        items = []
        for s in self.store.list_samples(case_id):
            items.append({"filename": s["filename"], "sha256": s["sha256"],
                          "static": self.static_report(s["id"]),
                          "detections": self.detections(s["id"])})
        return diffing.compare_samples(items)

    # ---- YARA rule management ------------------------------------------

    def yara_list(self) -> list[dict]:
        return yara_rules.list_rules(self.yara_dir)

    def yara_read(self, name: str) -> str:
        return yara_rules.read_rule(self.yara_dir, name)

    def yara_write(self, name: str, text: str) -> dict:
        return yara_rules.write_rule(self.yara_dir, name, text)

    def yara_delete(self, name: str):
        yara_rules.delete_rule(self.yara_dir, name)

    # ---- Sysmon setup --------------------------------------------------

    def sysmon_status(self) -> dict:
        return {"ready": (self.tools_dir / "Sysmon64.exe").exists(),
                "has_config": (self.tools_dir / "sysmon-config.xml").exists(),
                "tools_dir": str(self.tools_dir)}

    def setup_pending(self) -> list[str]:
        """Installer steps that failed (written by MalLab.exe --setup-*), for Settings to offer a retry."""
        f = self.lab_root / "setup-pending.txt"
        return [l.strip() for l in f.read_text(encoding="utf-8").splitlines() if l.strip()] if f.exists() else []

    def clear_setup_pending(self):
        (self.lab_root / "setup-pending.txt").unlink(missing_ok=True)

    def tools_status(self) -> dict:
        try:
            import tlsh  # noqa: F401
            has_tlsh = True
        except ImportError:
            has_tlsh = False
        return {"capa": {"ready": bool(static.find_capa(self.tools_dir)),
                         "version": tooling.installed_version("capa", self.tools_dir)},
                "fakenet": {"ready": bool(fakenet.find(self.tools_dir)),
                            "version": tooling.installed_version("fakenet", self.tools_dir)},
                "sysmon": {"ready": (self.tools_dir / "Sysmon64.exe").exists()},
                "tlsh": {"ready": has_tlsh}}

    def setup_tool(self, tool: str) -> dict:
        """Download capa / FakeNet-NG from the official GitHub release, or Sysmon from Sysinternals."""
        if tool == "sysmon":
            return self.setup_sysmon()
        name = tooling.TOOLS.get(tool, {}).get("name", tool)
        self._emit(type="lab_log", text=f"Downloading {name} from its official GitHub release…")
        try:
            res = tooling.install(tool, self.tools_dir)
        except PermissionError as e:
            raise RuntimeError(f"Could not write {name} into {self.tools_dir} ({e}). If Defender quarantined "
                               "it, allow it in Windows Security or exclude the tools folder, then retry.") from e
        self._emit(type="lab_log", text=f"{name} {res['version']} installed.")
        return res

    def _refresh_sysmon_config(self):
        """Write the default Sysmon config if there is none, and replace older MalLab defaults
        (the first logged every DLL load; later ones logged every registry write, which filled
        the event cap). A config the analyst wrote is never touched."""
        cfg = self.tools_dir / "sysmon-config.xml"
        old = cfg.read_text(encoding="utf-8", errors="replace") if cfg.exists() else ""
        ours = old.lstrip().startswith("<!-- mallab default -->") or (
            '<ImageLoad onmatch="exclude"></ImageLoad>' in old and '<ProcessAccess onmatch="exclude"></ProcessAccess>' in old)
        if (not old and (self.tools_dir / "Sysmon64.exe").exists()) or (ours and old != _DEFAULT_SYSMON_CONFIG):
            cfg.write_text(_DEFAULT_SYSMON_CONFIG, encoding="utf-8")

    def setup_sysmon(self) -> dict:
        """Download Sysmon from Microsoft Sysinternals into the lab's tools dir (explicit action).
        Also writes a compact default config if none is present."""
        import io
        import zipfile

        import httpx
        self._emit(type="lab_log", text="Downloading Sysmon from Microsoft Sysinternals…")
        with httpx.Client(timeout=120, follow_redirects=True) as c:
            r = c.get("https://download.sysinternals.com/files/Sysmon.zip")
            r.raise_for_status()
            with zipfile.ZipFile(io.BytesIO(r.content)) as z:
                for member in z.namelist():
                    if member.lower().endswith("sysmon64.exe"):
                        (self.tools_dir / "Sysmon64.exe").write_bytes(z.read(member))
        cfg = self.tools_dir / "sysmon-config.xml"
        # Replace our own older default (it logged every DLL load); never touch a custom config.
        self._refresh_sysmon_config()
        self._emit(type="lab_log", text="Sysmon ready.")
        return self.sysmon_status()

    def defender_status(self) -> dict:
        return defender.status(self.lab_root, self.tools_dir)

    def set_defender_exclusion(self, exclude: bool) -> dict:
        """Add/remove the Defender exclusion for quarantine + runs (UAC prompt on this PC)."""
        self._emit(type="lab_log", text=("Requesting" if exclude else "Removing") +
                   " Defender exclusion for the lab's sample folders (approve the Windows prompt)…")
        st = defender.set_excluded(self.lab_root, self.tools_dir, exclude)
        self._emit(type="lab_log", text=f"Defender exclusion {'on' if st['excluded'] else 'off'} (verified).")
        return st

    def netguard_status(self) -> dict:
        return netguard.status(self.tools_dir)

    def set_netguard(self, enable: bool) -> dict:
        """Create/remove the host firewall rules that block the sandbox's switch from reaching
        this PC (UAC prompt on this PC)."""
        self._emit(type="lab_log", text=("Turning on" if enable else "Turning off") +
                   " the host network guard (approve the Windows prompt)…")
        st = netguard.set_enabled(self.tools_dir, enable)
        self._emit(type="lab_log", text=f"Host network guard {'on' if st['enabled'] else 'off'} (verified).")
        return st

    def fakenet_status(self) -> dict:
        d = fakenet.find(self.tools_dir)
        return {"ready": bool(d), "path": str(d) if d else None, "tools_dir": str(self.tools_dir)}

    def threat_intel(self, sample_id: str, refresh: bool = False) -> dict:
        """Hash lookups across every configured intel provider (lookup only — the sample is
        never uploaded). Cached per provider: a cached hit or miss is reused, while providers
        that errored, or were unconfigured last time but have a key now, are queried again."""
        s = self.store.get_sample(sample_id)
        if not s:
            raise ValueError("no such sample")
        cache = self.store.report_dir(s["sha256"]) / "intel.json"
        old = {}
        if cache.exists() and not refresh:
            old = {r["id"]: r for r in json.loads(cache.read_text(encoding="utf-8")).get("providers", [])}
        stale = [p.id for p in self.intel.providers
                 if p.configured() and (p.id not in old or old[p.id]["error"] or not old[p.id]["configured"])]
        fresh = {r["id"]: r for r in self.intel.lookup(s["sha256"], only=stale)} if stale else {}
        results = []
        for p in self.intel.providers:
            r = fresh.get(p.id) or old.get(p.id)
            if r is None or (r["configured"] and not p.configured()):
                r = intel._result(p, link=p.link(s["sha256"]))
            results.append(r)
        out = {"sha256": s["sha256"], "providers": results, "summary": intel.summarize(results)}
        cache.write_text(json.dumps(out, indent=2), encoding="utf-8")
        return out

    def set_keys(self, vx_key: str | None = None, vx_url: str | None = None,
                 vt_key: str | None = None, abusech_key: str | None = None,
                 ha_key: str | None = None, otx_key: str | None = None):
        """Set repository / reputation credentials at runtime (no restart needed).
        None or "" leaves a key unchanged."""
        if vx_key:
            self.source.api_key = vx_key.strip()
        if vx_url:
            self.source.api_url = vx_url.strip().rstrip("/")
        for env, key in (("VT_API_KEY", vt_key), ("ABUSECH_API_KEY", abusech_key),
                         ("HA_API_KEY", ha_key), ("OTX_API_KEY", otx_key)):
            if key:
                self.intel.set_key(env, key)

    # ---- cases ----------------------------------------------------------

    # ---- IOC enrichment (free online sources) ---------------------------

    def enrich_case_iocs(self, case_id: str, refresh: bool = False, limit: int = 40) -> dict:
        """Look up the case's public IPs, domains and URLs in free sources (see ioc_intel).
        Cached per case; refresh re-queries. Only indicators are sent, never samples."""
        if not self.store.get_case(case_id):
            raise ValueError("no such case")
        cache = self.intel_dir / f"case-{case_id}.json"
        if cache.exists() and not refresh:
            return json.loads(cache.read_text(encoding="utf-8"))
        iocs = self.case_iocs(case_id)
        todo = (iocs["ips"] + iocs["domains"] + iocs["urls"])[:limit]
        self._emit(type="lab_log", text=f"Enriching {len(todo)} indicator(s) from free intel sources…")
        keys = {"abusech": self.intel.by_id["mb"].api_key, "otx": self.intel.by_id["otx"].api_key}
        rows = ioc_intel.enrich(todo, keys, self.intel_dir) if todo else []
        out = {"case_id": case_id, "checked": time.time(), "indicators": rows,
               "skipped": max(0, len(iocs["ips"]) + len(iocs["domains"]) + len(iocs["urls"]) - limit),
               "families": sorted({f for r in rows for f in r["summary"]["families"]}),
               "actors": sorted({a for r in rows for a in r["summary"]["actors"]}),
               "abusech_configured": bool(keys["abusech"])}
        cache.write_text(json.dumps(out, indent=2), encoding="utf-8")
        return out

    # ---- threat groups --------------------------------------------------

    def actors(self) -> list[dict]:
        return self.store.list_actors()

    def save_actor(self, actor_id: str | None, fields: dict) -> dict:
        f = {k: (", ".join(actors.split_list(v)) if k in ("aliases", "families", "techniques") else v)
             for k, v in fields.items() if k in self.store.ACTOR_FIELDS and k != "source"}
        if actor_id:
            if not self.store.get_actor(actor_id):
                raise ValueError("no such group")
            return self.store.update_actor(actor_id, **f)
        return self.store.create_actor(**f, source="analyst")

    def delete_actor(self, actor_id: str):
        self.store.delete_actor(actor_id)

    def link_actor(self, actor_id: str, kind: str, target_id: str, confidence: str = "low",
                   note: str = "", unlink: bool = False) -> dict:
        if kind not in ("case", "sample"):
            raise ValueError("kind must be case or sample")
        if not self.store.get_actor(actor_id):
            raise ValueError("no such group")
        if not (self.store.get_case(target_id) if kind == "case" else self.store.get_sample(target_id)):
            raise ValueError(f"no such {kind}")
        if unlink:
            self.store.unlink_actor(actor_id, kind, target_id)
        else:
            if confidence not in ("low", "medium", "high"):
                confidence = "low"
            self.store.link_actor(actor_id, kind, target_id, confidence, str(note)[:2000])
        return self.actor_profile(actor_id)

    def _actor_samples(self, actor_id: str) -> list[dict]:
        """Samples linked to a group directly, plus every sample in a linked case."""
        out = {}
        for l in self.store.actor_links(aid=actor_id):
            if l["kind"] == "sample":
                s = self.store.get_sample(l["target_id"])
                if s:
                    out[s["id"]] = {**s, "link": l}
            else:
                for s in self.store.list_samples(l["target_id"]):
                    out.setdefault(s["id"], {**s, "link": l})
        return list(out.values())

    def actor_profile(self, actor_id: str) -> dict:
        a = self.store.get_actor(actor_id)
        if not a:
            raise ValueError("no such group")
        links = self.store.actor_links(aid=actor_id)
        samples = self._actor_samples(actor_id)
        dets = [self.detections(s["id"]) for s in samples]
        observed = sorted({t for d in dets for t in d["attck"]})
        known = set(actors.split_list(a["techniques"]))
        iocs = {"urls": set(), "ips": set(), "domains": set()}
        for case_id in {s["case_id"] for s in samples}:
            ci = self.case_iocs(case_id)
            for k in iocs:
                iocs[k].update(ci[k])
        cases = []
        for l in links:
            if l["kind"] == "case":
                c = self.store.get_case(l["target_id"])
                if c:
                    cases.append({**c, "link": l})
        return {"actor": a, "cases": cases,
                "samples": [{"id": s["id"], "filename": s["filename"], "sha256": s["sha256"], "case_id": s["case_id"],
                             "risk": s.get("risk"), "confidence": s["link"]["confidence"]} for s in samples],
                "attck_observed": observed,
                "attck_known_and_observed": sorted(known & set(observed)),
                "attck_matrix": signatures.attck_matrix(dets),
                "iocs": {k: sorted(v) for k, v in iocs.items()}}

    def suggest_actors(self, sample_id: str) -> dict:
        """Leads for which tracked group a sample may belong to (analyst confirms)."""
        s = self.store.get_sample(sample_id)
        if not s:
            raise ValueError("no such sample")
        labels = actors.split_list(s.get("labels"))
        cache = self.store.report_dir(s["sha256"]) / "intel.json"
        if cache.exists():
            summ = json.loads(cache.read_text(encoding="utf-8")).get("summary") or {}
            labels += summ.get("labels") or []
        enr = self.intel_dir / f"case-{s['case_id']}.json"
        if enr.exists():
            e = json.loads(enr.read_text(encoding="utf-8"))
            labels += e.get("families", []) + e.get("actors", [])
        st = self.static_report(sample_id) or {}
        labels += [m["rule"] for m in (st.get("yara") or {}).get("matches") or []]
        my_iocs = set(sum(((st.get("iocs") or {}).get(k, []) for k in ("urls", "ips", "domains")), []))
        ci = self.case_iocs(s["case_id"])
        my_iocs |= set(ci["ips"]) | set(ci["domains"]) | set(ci["urls"])
        rows = self.store.list_actors()
        linked = {}
        for a in rows:
            if a["link_count"]:
                ioc_set = set()
                for case_id in {x["case_id"] for x in self._actor_samples(a["id"]) if x["case_id"] != s["case_id"]}:
                    c = self.case_iocs(case_id)
                    ioc_set |= set(c["ips"]) | set(c["domains"]) | set(c["urls"])
                linked[a["id"]] = ioc_set
        signals = {"labels": labels, "techniques": self.detections(sample_id)["attck"], "iocs": my_iocs}
        return {"signals": {"labels": sorted(set(labels)), "techniques": signals["techniques"]},
                "suggestions": actors.suggest(signals, rows, linked),
                "linked": self.store.actor_links(kind="sample", target_id=sample_id)
                          + self.store.actor_links(kind="case", target_id=s["case_id"]),
                "catalog_size": len(rows)}

    def import_actor_catalog(self) -> dict:
        """Download MITRE ATT&CK groups, the MISP Galaxy threat-actor list and Malpedia's
        family attributions, and merge them into the tracked groups (analyst edits are kept)."""
        import httpx
        got, errors = {}, []
        with httpx.Client(timeout=180, follow_redirects=True, headers={"User-Agent": "mallab/1.0"}) as c:
            for key, url in (("mitre", actors.MITRE_URL), ("misp", actors.MISP_URL), ("malpedia", actors.MALPEDIA_URL)):
                self._emit(type="lab_log", text=f"Downloading {key} threat-group data…")
                try:
                    r = c.get(url)
                    r.raise_for_status()
                    got[key] = r.json()
                except Exception as e:
                    errors.append(f"{key}: {type(e).__name__}: {e}")
        if not got:
            raise RuntimeError("could not download any threat-group source: " + "; ".join(errors))
        updates, creates = actors.merge_catalog(
            self.store.list_actors(), actors.parse_mitre(got.get("mitre") or {}),
            actors.parse_misp(got.get("misp") or {}), actors.parse_malpedia(got.get("malpedia") or {}))
        for aid, f in updates.items():
            f.pop("source", None)
            self.store.update_actor(aid, **f)
        for f in creates:
            self.store.create_actor(**f)
        res = {"created": len(creates), "updated": len(updates), "sources": sorted(got), "errors": errors,
               "total": len(self.store.list_actors())}
        self._emit(type="lab_log", text=f"Threat groups: {res['created']} added, {res['updated']} updated "
                                        f"from {', '.join(res['sources'])}" + (f" (failed: {'; '.join(errors)})" if errors else ""))
        return res

    def annotate_sample(self, sample_id: str, notes: str | None = None, labels=None) -> dict:
        """Analyst notes and labels (e.g. family names, "false positive") on a sample."""
        if not self.store.get_sample(sample_id):
            raise ValueError("no such sample")
        fields = {}
        if notes is not None:
            fields["notes"] = str(notes)[:20000]
        if labels is not None:
            items = labels if isinstance(labels, list) else str(labels).split(",")
            fields["labels"] = ",".join(dict.fromkeys(str(x).strip()[:60] for x in items if str(x).strip()))[:1000]
        self.store.update_sample(sample_id, **fields)
        return self.store.get_sample(sample_id)

    def delete_case(self, case_id: str):
        """Delete a case and purge the quarantined bytes and reports of any sample that no
        other case still references (otherwise live malware would linger on disk)."""
        hashes = {s["sha256"] for s in self.store.list_samples(case_id)}
        self.store.delete_case(case_id)
        (self.intel_dir / f"case-{case_id}.json").unlink(missing_ok=True)
        for h in hashes:
            if not self.store.sha256_in_use(h):
                for d in (self.lab_root / "quarantine" / h, self.lab_root / "reports" / h):
                    shutil.rmtree(d, ignore_errors=True)

    # ---- state for the UI ----------------------------------------------

    def state(self) -> dict:
        return {
            "cases": self.store.list_cases(),
            "sandbox": self.sandbox_status(),
            "repo_configured": self.source.configured(),
            "repo_url": self.source.api_url,
            "intel": self.intel.status(),
            "defender": self.defender_status(),
            "netguard": self.netguard_status(),
            "fakenet": self.fakenet_status(),
            "yara_dir": str(self.yara_dir),
            "yara_present": self.yara_dir.exists(),
            "yara_rules": len(self.yara_list()),
            "sysmon": self.sysmon_status(),
            "capa": bool(static.find_capa(self.tools_dir)),
            "tools": self.tools_status(),
            "setup_pending": self.setup_pending(),
            "actor_count": len(self.store.list_actors()),
        }

    # ---- reporting / IOC rollup ----------------------------------------

    def case_iocs(self, case_id: str) -> dict:
        """Aggregate IOCs across every sample in a case: hashes (static), plus URLs/IPs/domains
        from static strings and any detonation network/DNS observations. De-duplicated."""
        urls, ips, domains, hashes = set(), set(), set(), []
        for s in self.store.list_samples(case_id):
            hashes.append({"filename": s["filename"], "sha256": s["sha256"],
                           "md5": s.get("md5"), "sha1": s.get("sha1")})
            static = self.static_report(s["id"]) or {}
            ioc = static.get("iocs") or {}
            urls.update(ioc.get("urls", []))
            ips.update(ioc.get("ips", []))
            domains.update(ioc.get("domains", []))
            for run in self.store.list_runs(s["id"]):
                dyn = self.dynamic_report(s["id"], run["id"]) or {}
                ips.update(endpoint_host(e) for e in dyn.get("network", []))
                domains.update(dyn.get("dns", []))
                beh = dyn.get("behavior") or {}
                ips.update(n.get("dst_ip", "") for n in beh.get("network", []))
                domains.update(n.get("dst_host", "") for n in beh.get("network", []))
                domains.update(q.get("query", "") for q in beh.get("dns", []))
                sim = dyn.get("fakenet") if isinstance(dyn.get("fakenet"), dict) else {}
                domains.update(str(d) for d in sim.get("domains") or [])
                urls.update(str(u.get("url", "")) for u in sim.get("urls") or [] if isinstance(u, dict))
                ips.update(str(c.get("ip", "")) for c in sim.get("connections") or [] if isinstance(c, dict))
        # Sandbox-internal and private addresses, and the VM's own Windows chatter, aren't IOCs.
        return {"hashes": hashes, "urls": sorted(urls), "ips": sorted(i for i in ips if _public_ip(i)),
                "domains": sorted(d for d in domains if d and "." in d and not NOISE_DOMAINS.search(d))}

    def export_iocs(self, case_id: str, fmt: str = "csv") -> tuple[str, str, str]:
        """IOCs as (body, media_type, extension). fmt: csv | stix | txt (defanged, for tickets)."""
        case = self.store.get_case(case_id)
        if not case:
            raise ValueError("no such case")
        iocs = self.case_iocs(case_id)
        rows = ([("sha256", h["sha256"], h["filename"]) for h in iocs["hashes"]]
                + [("md5", h["md5"], h["filename"]) for h in iocs["hashes"] if h.get("md5")]
                + [("url", u, "") for u in iocs["urls"]]
                + [("ip", i, "") for i in iocs["ips"]]
                + [("domain", d, "") for d in iocs["domains"]])
        if fmt == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["type", "value", "context", "case"])
            for t, v, ctx in rows:
                # A leading =,+,-,@ would run as a formula when the CSV is opened in Excel.
                w.writerow([t, *(("'" + x) if x[:1] in "=+-@" else x for x in (v, ctx, case["name"]))])
            return buf.getvalue(), "text/csv; charset=utf-8", "csv"
        if fmt == "txt":
            lines = [f"# IOCs: {case['name']} (defanged)"]
            lines += [f"{t}\t{defang(v) if t in ('url', 'ip', 'domain') else v}\t{ctx}".rstrip() for t, v, ctx in rows]
            return "\n".join(lines) + "\n", "text/plain; charset=utf-8", "txt"
        if fmt == "stix":
            return json.dumps(_stix_bundle(case, rows), indent=2), "application/json", "stix.json"
        raise ValueError("format must be csv, txt or stix")

    def export_report(self, case_id: str) -> str:
        """A Markdown triage report for the whole case: per-sample static + dynamic findings and
        a consolidated IOC appendix. A reading aid and record, not an authoritative verdict."""
        detail = self.case_detail(case_id)
        if not detail:
            raise ValueError("no such case")
        case, samples = detail["case"], detail["samples"]
        when = time.strftime("%Y-%m-%d %H:%M")
        out = [f"# Malware analysis report: {case['name']}", "",
               f"*Generated {when}. Defensive analysis record — findings are a reading aid, not a verdict.*", ""]
        if case.get("description"):
            out += [case["description"], ""]
        out += [f"**Samples:** {len(samples)}", ""]

        for s in samples:
            out += [f"## {s['filename']}", "",
                    f"- SHA-256: `{s['sha256']}`",
                    f"- Type: {s.get('file_type') or 'unknown'} · {s.get('size', 0):,} bytes · "
                    f"risk score {s.get('risk', 0)}/100 · source {s.get('source')}"]
            static = self.static_report(s["id"]) or {}
            for reason in static.get("risk_reasons", []):
                out.append(f"  - {reason}")
            det = self.detections(s["id"])
            if det["detections"]:
                out.append(f"- Detections (max severity {det['max_severity']}, "
                           f"ATT&CK {', '.join(det['attck'])}):")
                for d in det["detections"]:
                    out.append(f"  - [{d['severity']}] {d['name']} ({', '.join(d['attck'])})")
            pe = static.get("pe") or {}
            if s.get("labels"):
                out.append(f"- Labels: {s['labels']}")
            if pe.get("imphash"):
                out.append(f"- imphash `{pe['imphash']}`" + (" · .NET" if pe.get("dotnet") else "")
                           + (" · has Authenticode signature (unverified)" if pe.get("signed") else ""))
            if pe.get("suspicious_imports"):
                out.append(f"- Notable imports: {', '.join(pe['suspicious_imports'][:20])}")
            macros = static.get("office_macros") or {}
            if macros.get("autoexec"):
                out.append(f"- Auto-executing macros: {', '.join(macros['autoexec'])}")
            for run in self.store.list_runs(s["id"]):
                verdict = run.get("verdict") or run.get("status")
                out.append(f"- Detonation ({run.get('kind')}): {verdict}")
                dyn = self.dynamic_report(s["id"], run["id"]) or {}
                if dyn.get("new_processes"):
                    out.append(f"  - {len(dyn['new_processes'])} new process(es)")
                if dyn.get("new_runkeys") or dyn.get("new_tasks"):
                    out.append("  - persistence: "
                               + "; ".join(dyn.get("new_runkeys", []) + dyn.get("new_tasks", []))[:300])
                if dyn.get("network"):
                    out.append(f"  - network: {', '.join(dyn['network'][:15])}")
                cnt = (dyn.get("behavior") or {}).get("counts") or {}
                if cnt:
                    out.append("  - Sysmon: " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in cnt.items() if v))
                for d in dyn.get("dropped") or []:
                    out.append(f"  - dropped `{d['path']}` (SHA-256 `{d['sha256']}`)")
            if s.get("notes"):
                out += ["", "**Analyst notes:**", "", s["notes"]]
            out.append("")

        iocs = self.case_iocs(case_id)
        out += ["## Indicators of compromise (consolidated)", ""]
        for label, key in [("URLs", "urls"), ("IPs", "ips"), ("Domains", "domains")]:
            if iocs[key]:
                out += [f"### {label}", "```", *iocs[key], "```", ""]
        out += ["### File hashes", "", "| File | SHA-256 |", "|---|---|"]
        out += [f"| {h['filename']} | `{h['sha256']}` |" for h in iocs["hashes"]]
        return "\n".join(out) + "\n"

    def case_detail(self, case_id: str) -> dict | None:
        case = self.store.get_case(case_id)
        if not case:
            return None
        samples = self.store.list_samples(case_id)
        for s in samples:
            s["runs"] = self.store.list_runs(s["id"])
        return {"case": case, "samples": samples}
