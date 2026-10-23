"""Threat-intel hash lookups across several providers, queried in parallel.

Lookup only: every provider is sent the SHA-256 and nothing else. The sample itself is never
uploaded (uploading to a public service shares it with that service's subscribers and tips
off whoever is tracking submissions).

Keys come from the environment (or ⚙ Settings at runtime):
    VT_API_KEY        VirusTotal
    ABUSECH_API_KEY   abuse.ch Auth-Key — MalwareBazaar, ThreatFox and URLhaus share it
    HA_API_KEY        Hybrid Analysis
    OTX_API_KEY       AlienVault OTX (optional; anonymous lookups work with lower limits)

Every provider returns the same normalized shape:
    {id, name, link, configured, found, verdict, score, label, tags, first_seen, details, error}
where verdict is one of "malicious" | "suspicious" | "clean" | "unknown".
"""

import os
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

UA = "mallab/1.0"
TIMEOUT = 25
VERDICT_RANK = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}


def _result(p, **kw) -> dict:
    base = {"id": p.id, "name": p.name, "link": None, "configured": p.configured(), "found": False,
            "verdict": "unknown", "score": None, "label": None, "tags": [], "first_seen": None,
            "details": {}, "error": None}
    base.update(kw)
    return base


class Provider:
    id = name = env = ""
    key_required = True

    def __init__(self):
        self.api_key = os.environ.get(self.env, "") if self.env else ""

    def configured(self) -> bool:
        return bool(self.api_key) or not self.key_required

    def link(self, h: str) -> str:
        return ""

    def lookup(self, h: str) -> dict:
        raise NotImplementedError

    def safe_lookup(self, h: str) -> dict:
        if not self.configured():
            return _result(self, link=self.link(h))
        try:
            r = self.lookup(h)
            r["link"] = r.get("link") or self.link(h)
            return r
        except httpx.HTTPStatusError as e:
            code = e.response.status_code
            msg = {401: "API key rejected", 403: "API key rejected or not permitted",
                   429: "rate limited — try again shortly"}.get(code, f"HTTP {code}")
            return _result(self, link=self.link(h), error=msg)
        except Exception as e:
            return _result(self, link=self.link(h), error=f"{type(e).__name__}: {e}")


class VirusTotal(Provider):
    id, name, env = "vt", "VirusTotal", "VT_API_KEY"

    def link(self, h):
        return f"https://www.virustotal.com/gui/file/{h}"

    def lookup(self, h):
        with httpx.Client(timeout=TIMEOUT, headers={"x-apikey": self.api_key, "User-Agent": UA}) as c:
            r = c.get(f"https://www.virustotal.com/api/v3/files/{h}")
            if r.status_code == 404:
                return _result(self)
            r.raise_for_status()
            attr = r.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {}) or {}
        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        total = sum(v for v in stats.values() if isinstance(v, int))
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal or sus) else "clean"
        ptc = attr.get("popular_threat_classification") or {}
        return _result(self, found=True, verdict=verdict, score=f"{mal}/{total}",
                       label=ptc.get("suggested_threat_label"),
                       tags=(attr.get("tags") or [])[:10],
                       first_seen=attr.get("first_submission_date"),
                       details={"malicious": mal, "suspicious": sus, "total": total,
                                "reputation": attr.get("reputation"),
                                "names": (attr.get("names") or [])[:8],
                                "type": attr.get("type_description")})


class _AbuseCh(Provider):
    env = "ABUSECH_API_KEY"

    def _client(self):
        return httpx.Client(timeout=TIMEOUT, headers={"Auth-Key": self.api_key, "User-Agent": UA})


class MalwareBazaar(_AbuseCh):
    id, name = "mb", "MalwareBazaar"

    def link(self, h):
        return f"https://bazaar.abuse.ch/sample/{h}/"

    def lookup(self, h):
        with self._client() as c:
            r = c.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": h})
            r.raise_for_status()
            j = r.json()
        if j.get("query_status") != "ok" or not j.get("data"):
            return _result(self)
        d = j["data"][0]
        return _result(self, found=True, verdict="malicious", label=d.get("signature"),
                       tags=(d.get("tags") or [])[:10], first_seen=d.get("first_seen"),
                       details={"file_name": d.get("file_name"), "file_type": d.get("file_type"),
                                "delivery": d.get("delivery_method"), "reporter": d.get("reporter")})


class ThreatFox(_AbuseCh):
    id, name = "tf", "ThreatFox"

    def link(self, h):
        return f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{h}"

    def lookup(self, h):
        with self._client() as c:
            r = c.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_hash", "hash": h})
            r.raise_for_status()
            j = r.json()
        rows = j.get("data") if j.get("query_status") == "ok" else None
        if not rows or not isinstance(rows, list):
            return _result(self)
        fams = sorted({x.get("malware_printable") for x in rows if x.get("malware_printable")})
        return _result(self, found=True, verdict="malicious", label=", ".join(fams) or None,
                       score=f"{len(rows)} IOC{'s' if len(rows) != 1 else ''}",
                       tags=sorted({t for x in rows for t in (x.get("tags") or [])})[:10],
                       first_seen=min((x.get("first_seen") or "" for x in rows), default=None) or None,
                       details={"iocs": [{"ioc": x.get("ioc"), "type": x.get("ioc_type"),
                                          "threat": x.get("threat_type"),
                                          "confidence": x.get("confidence_level")} for x in rows[:25]]})


class URLhaus(_AbuseCh):
    id, name = "uh", "URLhaus"

    def link(self, h):
        return f"https://urlhaus.abuse.ch/browse.php?search={h}"

    def lookup(self, h):
        with self._client() as c:
            r = c.post("https://urlhaus-api.abuse.ch/v1/payload/", data={"sha256_hash": h})
            r.raise_for_status()
            j = r.json()
        if j.get("query_status") != "ok":
            return _result(self)
        urls = j.get("urls") or []
        return _result(self, found=True, verdict="malicious", label=j.get("signature"),
                       score=f"{j.get('url_count', len(urls))} URL{'s' if len(urls) != 1 else ''}",
                       first_seen=j.get("firstseen"),
                       details={"urls": [{"url": u.get("url"), "status": u.get("url_status")}
                                         for u in urls[:25]]})


class HybridAnalysis(Provider):
    id, name, env = "ha", "Hybrid Analysis", "HA_API_KEY"

    def link(self, h):
        return f"https://www.hybrid-analysis.com/sample/{h}"

    def lookup(self, h):
        headers = {"api-key": self.api_key, "User-Agent": "Falcon Sandbox", "Accept": "application/json"}
        with httpx.Client(timeout=TIMEOUT, headers=headers) as c:
            r = c.get(f"https://hybrid-analysis.com/api/v2/overview/{h}")
            if r.status_code == 404:
                return _result(self)
            r.raise_for_status()
            d = r.json()
        v = (d.get("verdict") or "").lower()
        verdict = ("malicious" if v == "malicious" else "suspicious" if v == "suspicious"
                   else "clean" if v in ("no specific threat", "whitelisted") else "unknown")
        score = d.get("threat_score")
        return _result(self, found=True, verdict=verdict,
                       score=f"{score}/100" if score is not None else None,
                       label=d.get("vx_family"), tags=(d.get("tags") or [])[:10],
                       details={"verdict": d.get("verdict"), "av_detect": d.get("multiscan_result"),
                                "file_name": d.get("last_file_name"), "type": d.get("type")})


class OTX(Provider):
    id, name, env = "otx", "AlienVault OTX", "OTX_API_KEY"
    key_required = False

    def link(self, h):
        return f"https://otx.alienvault.com/indicator/file/{h}"

    def lookup(self, h):
        headers = {"User-Agent": UA}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        with httpx.Client(timeout=TIMEOUT, headers=headers) as c:
            r = c.get(f"https://otx.alienvault.com/api/v1/indicators/file/{h}/general")
            if r.status_code == 404:
                return _result(self)
            r.raise_for_status()
            d = r.json()
        pi = d.get("pulse_info") or {}
        pulses = pi.get("pulses") or []
        n = pi.get("count", len(pulses))
        if not n:
            return _result(self)
        fams = sorted({f.get("display_name") for p in pulses for f in (p.get("malware_families") or [])
                       if isinstance(f, dict) and f.get("display_name")})
        return _result(self, found=True, verdict="malicious" if n >= 2 else "suspicious",
                       score=f"{n} pulse{'s' if n != 1 else ''}", label=", ".join(fams[:4]) or None,
                       tags=sorted({t for p in pulses for t in (p.get("tags") or [])})[:10],
                       details={"pulses": [p.get("name") for p in pulses[:10]]})


class ThreatIntel:
    def __init__(self):
        self.providers = [VirusTotal(), MalwareBazaar(), ThreatFox(), URLhaus(), HybridAnalysis(), OTX()]
        self.by_id = {p.id: p for p in self.providers}

    def status(self) -> list[dict]:
        return [{"id": p.id, "name": p.name, "env": p.env, "configured": p.configured(),
                 "key_set": bool(p.api_key), "key_required": p.key_required} for p in self.providers]

    def set_key(self, env: str, key: str):
        for p in self.providers:
            if p.env == env:
                p.api_key = key.strip()

    def lookup(self, sha256: str, only: list[str] | None = None) -> list[dict]:
        h = sha256.strip().lower()
        todo = [p for p in self.providers if not only or p.id in only]
        with ThreadPoolExecutor(max_workers=len(todo) or 1) as ex:
            return list(ex.map(lambda p: p.safe_lookup(h), todo))


def summarize(results: list[dict]) -> dict:
    hits = [r for r in results if r["found"]]
    worst = max((r["verdict"] for r in hits), key=VERDICT_RANK.get, default="unknown")
    labels = []
    for r in hits:
        for part in (r.get("label") or "").split(","):
            part = part.strip()
            if part and part.lower() not in (x.lower() for x in labels):
                labels.append(part)
    return {"verdict": worst, "hits": len(hits),
            "queried": sum(1 for r in results if r["configured"] and not r["error"]),
            "configured": sum(1 for r in results if r["configured"]),
            "labels": labels[:8], "checked": time.time()}
