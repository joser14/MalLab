"""Enrich network IOCs (IPs, domains, URLs) from free sources, for triage and for threat-group
identification.

    AlienVault OTX       ip/domain/url: pulses, and often the ADVERSARY they're attributed to (no key needed)
    ThreatFox            ip/domain/url: malware family, threat type, confidence (free abuse.ch key)
    URLhaus              domain/ip/url: malware-distribution history (free abuse.ch key)
    Feodo Tracker        ip: botnet C2 blocklist with family (no key; list cached for 6 h)
    GreyNoise Community  ip: internet-wide scanner / benign service vs. not seen (no key)
    Shodan InternetDB    ip: open ports, hostnames, tags, CVEs (no key)
    RDAP                 ip: network owner and country (no key)

OPSEC: a lookup tells that service you are interested in the indicator. Only the indicator
is sent, never a sample, and lookups only run when the analyst asks for them.
"""

import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import httpx

UA = "mallab/1.0"
TIMEOUT = 20
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
RANK = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}


def kind_of(ioc: str) -> str:
    if ioc.lower().startswith(("http://", "https://")):
        return "url"
    try:
        return "ipv6" if ipaddress.ip_address(ioc).version == 6 else "ipv4"
    except ValueError:
        return "domain"


def _r(provider, **kw) -> dict:
    base = {"provider": provider, "found": False, "verdict": "unknown", "families": [], "actors": [],
            "tags": [], "details": {}, "link": None, "error": None}
    base.update(kw)
    return base


def otx(ioc: str, kind: str, key: str = "") -> dict:
    section = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url"}[kind]
    link = f"https://otx.alienvault.com/indicator/{'ip' if kind.startswith('ip') else kind}/{quote(ioc, safe='')}"
    headers = {"User-Agent": UA, **({"X-OTX-API-KEY": key} if key else {})}
    with httpx.Client(timeout=TIMEOUT, headers=headers) as c:
        r = c.get(f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(ioc, safe='')}/general")
        if r.status_code in (400, 404):
            return _r("OTX", link=link)
        r.raise_for_status()
        d = r.json()
    pulses = (d.get("pulse_info") or {}).get("pulses") or []
    if not pulses:
        return _r("OTX", link=link)
    fams = sorted({f.get("display_name") for p in pulses for f in p.get("malware_families") or []
                   if isinstance(f, dict) and f.get("display_name")})
    actors = sorted({p.get("adversary").strip() for p in pulses if (p.get("adversary") or "").strip()})
    return _r("OTX", found=True, verdict="malicious" if len(pulses) >= 2 else "suspicious", link=link,
              families=fams[:10], actors=actors[:10],
              tags=sorted({t for p in pulses for t in p.get("tags") or []})[:15],
              details={"pulses": len(pulses), "names": [p.get("name") for p in pulses[:8]]})


def threatfox(ioc: str, kind: str, key: str) -> dict:
    link = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(ioc, safe='')}"
    with httpx.Client(timeout=TIMEOUT, headers={"Auth-Key": key, "User-Agent": UA}) as c:
        r = c.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ioc})
        r.raise_for_status()
        j = r.json()
    rows = j.get("data") if j.get("query_status") == "ok" and isinstance(j.get("data"), list) else []
    if not rows:
        return _r("ThreatFox", link=link)
    return _r("ThreatFox", found=True, verdict="malicious", link=link,
              families=sorted({x.get("malware_printable") for x in rows if x.get("malware_printable")}),
              tags=sorted({t for x in rows for t in x.get("tags") or []})[:15],
              details={"threat": sorted({x.get("threat_type_desc") or x.get("threat_type") or "" for x in rows} - {""}),
                       "confidence": max((x.get("confidence_level") or 0) for x in rows),
                       "first_seen": min((x.get("first_seen") or "" for x in rows), default="")})


def urlhaus(ioc: str, kind: str, key: str) -> dict:
    link = f"https://urlhaus.abuse.ch/browse.php?search={quote(ioc, safe='')}"
    ep, data = (("url", {"url": ioc}) if kind == "url" else ("host", {"host": ioc}))
    with httpx.Client(timeout=TIMEOUT, headers={"Auth-Key": key, "User-Agent": UA}) as c:
        r = c.post(f"https://urlhaus-api.abuse.ch/v1/{ep}/", data=data)
        r.raise_for_status()
        j = r.json()
    if j.get("query_status") != "ok":
        return _r("URLhaus", link=link)
    urls = j.get("urls") or []
    tags = set(j.get("tags") or []) | {t for u in urls for t in (u.get("tags") or [])}
    return _r("URLhaus", found=True, verdict="malicious", link=link, tags=sorted(tags)[:15],
              details={"threat": j.get("threat"), "url_count": j.get("url_count", len(urls)),
                       "status": j.get("url_status"), "first_seen": j.get("firstseen")})


def greynoise(ip: str) -> dict:
    link = f"https://viz.greynoise.io/ip/{ip}"
    with httpx.Client(timeout=TIMEOUT, headers={"User-Agent": UA}) as c:
        r = c.get(f"https://api.greynoise.io/v3/community/{ip}")
        if r.status_code == 404:
            return _r("GreyNoise", link=link, details={"note": "not seen scanning the internet (targeted, or quiet)"})
        r.raise_for_status()
        d = r.json()
    cls = d.get("classification") or "unknown"
    verdict = {"malicious": "malicious", "benign": "clean"}.get(cls, "unknown")
    return _r("GreyNoise", found=True, verdict=verdict, link=link,
              details={"classification": cls, "name": d.get("name"), "noise": d.get("noise"),
                       "riot": d.get("riot"), "last_seen": d.get("last_seen")})


def internetdb(ip: str) -> dict:
    link = f"https://www.shodan.io/host/{ip}"
    with httpx.Client(timeout=TIMEOUT, headers={"User-Agent": UA}) as c:
        r = c.get(f"https://internetdb.shodan.io/{ip}")
        if r.status_code == 404:
            return _r("Shodan InternetDB", link=link)
        r.raise_for_status()
        d = r.json()
    return _r("Shodan InternetDB", found=True, link=link, tags=(d.get("tags") or [])[:15],
              details={"ports": d.get("ports") or [], "hostnames": (d.get("hostnames") or [])[:10],
                       "vulns": (d.get("vulns") or [])[:15], "cpes": (d.get("cpes") or [])[:10]})


def rdap(ip: str) -> dict:
    with httpx.Client(timeout=TIMEOUT, headers={"User-Agent": UA, "Accept": "application/rdap+json"},
                      follow_redirects=True) as c:
        r = c.get(f"https://rdap.org/ip/{ip}")
        if r.status_code == 404:
            return _r("RDAP")
        r.raise_for_status()
        d = r.json()
    orgs = []
    for e in d.get("entities") or []:
        for item in (e.get("vcardArray") or [None, []])[1]:
            if isinstance(item, list) and item[:1] == ["fn"] and len(item) > 3:
                orgs.append(str(item[3]))
    return _r("RDAP", found=True, details={"network": d.get("name"), "country": d.get("country"),
                                            "range": f"{d.get('startAddress')} – {d.get('endAddress')}",
                                            "org": orgs[:3]})


def feodo_list(cache_dir: Path, max_age: int = 6 * 3600) -> list[dict]:
    """abuse.ch Feodo Tracker C2 blocklist, cached on disk so lookups stay offline-fast."""
    f = Path(cache_dir) / "feodo-ipblocklist.json"
    if not f.exists() or f.stat().st_mtime < time.time() - max_age:
        with httpx.Client(timeout=60, headers={"User-Agent": UA}) as c:
            r = c.get(FEODO_URL)
            r.raise_for_status()
            f.write_bytes(r.content)
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
    except ValueError:
        return []
    return data if isinstance(data, list) else []


def feodo(ip: str, rows: list[dict]) -> dict:
    hits = [x for x in rows if x.get("ip_address") == ip]
    if not hits:
        return _r("Feodo Tracker")
    h = hits[0]
    return _r("Feodo Tracker", found=True, verdict="malicious", families=[h.get("malware")] if h.get("malware") else [],
              link=f"https://feodotracker.abuse.ch/browse/host/{ip}/",
              details={"port": h.get("port"), "status": h.get("status"), "as": h.get("as_name"),
                       "country": h.get("country"), "last_online": h.get("last_online")})


def _safe(fn, provider, *a) -> dict:
    try:
        return fn(*a)
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        return _r(provider, error={401: "key rejected", 403: "key rejected", 429: "rate limited"}.get(code, f"HTTP {code}"))
    except Exception as e:
        return _r(provider, error=f"{type(e).__name__}: {e}")


def enrich(iocs: list[str], keys: dict, cache_dir: Path) -> list[dict]:
    """Look up each indicator in every applicable free source, in parallel.
    keys: {"abusech": ..., "otx": ...}. Returns [{value, type, results, summary}]."""
    try:
        feodo_rows = feodo_list(cache_dir) if any(kind_of(i).startswith("ip") for i in iocs) else []
        feodo_err = None
    except Exception as e:
        feodo_rows, feodo_err = [], f"{type(e).__name__}: {e}"
    ab, ok = keys.get("abusech") or "", keys.get("otx") or ""
    jobs = []
    for ioc in iocs:
        k = kind_of(ioc)
        plan = [(otx, "OTX", ioc, k, ok)]
        if ab:
            plan += [(threatfox, "ThreatFox", ioc, k, ab), (urlhaus, "URLhaus", ioc, k, ab)]
        if k.startswith("ip"):
            plan += [(greynoise, "GreyNoise", ioc), (internetdb, "Shodan InternetDB", ioc), (rdap, "RDAP", ioc)]
        jobs.append((ioc, k, plan))
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [(ioc, k, [ex.submit(_safe, fn, prov, *args) for fn, prov, *args in plan]) for ioc, k, plan in jobs]
        out = []
        for ioc, k, futs in futures:
            results = [f.result() for f in futs]
            if k.startswith("ip"):
                results.append(_r("Feodo Tracker", error=feodo_err) if feodo_err else feodo(ioc, feodo_rows))
            out.append({"value": ioc, "type": k, "results": results, "summary": summarize(results)})
    return out


def summarize(results: list[dict]) -> dict:
    found = [r for r in results if r["found"]]
    verdict = max((r["verdict"] for r in found), key=RANK.get, default="unknown")
    return {"verdict": verdict, "hits": sum(1 for r in found if r["verdict"] in ("malicious", "suspicious")),
            "families": sorted({f for r in found for f in r["families"]}),
            "actors": sorted({a for r in found for a in r["actors"]})}
