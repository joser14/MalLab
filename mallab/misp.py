"""Push a case's findings to a MISP instance as an Event.

MISP (https://www.misp-project.org) is the de-facto open threat-intel sharing platform. This
sends a case's consolidated IOCs (hashes, URLs, IPs, domains) as a new MISP Event with the family
and ATT&CK tags, over MISP's REST API. Credentials come from settings/env:

    MISP_URL        e.g. https://misp.example.org
    MISP_API_KEY    an automation key from the MISP user profile
    MISP_VERIFY     "0" to skip TLS verification (self-signed MISP certs); default verify on

Nothing is sent unless the analyst clicks "Push to MISP"; only indicators go, never the sample.
"""

import os

import httpx

# MISP attribute type for each IOC kind, and the category it lands in.
_TYPES = {"md5": ("md5", "Payload delivery"), "sha1": ("sha1", "Payload delivery"),
          "sha256": ("sha256", "Payload delivery"), "url": ("url", "Network activity"),
          "ip": ("ip-dst", "Network activity"), "domain": ("domain", "Network activity")}


def configured() -> bool:
    return bool(os.environ.get("MISP_URL") and os.environ.get("MISP_API_KEY"))


def status() -> dict:
    return {"configured": configured(), "url": os.environ.get("MISP_URL", ""),
            "verify": os.environ.get("MISP_VERIFY", "1") != "0"}


def _attr(kind: str, value: str, comment: str = "") -> dict:
    t, cat = _TYPES[kind]
    return {"type": t, "category": cat, "value": value, "to_ids": kind in ("md5", "sha1", "sha256", "url", "domain"),
            "comment": comment[:200], "distribution": "5"}


def build_event(case_name: str, iocs: dict, families: list[str], attck: list[str],
                verdict: str = "", tlp: str = "amber") -> dict:
    """Build the MISP Event payload from a case's IOCs and classification."""
    attrs = []
    for h in iocs.get("hashes", []):
        for kind in ("sha256", "sha1", "md5"):
            if h.get(kind):
                attrs.append(_attr(kind, h[kind], h.get("filename", "")))
    for kind, key in (("url", "urls"), ("ip", "ips"), ("domain", "domains")):
        for v in iocs.get(key, []):
            attrs.append(_attr(kind, v))
    tags = [{"name": f"tlp:{tlp}"}, {"name": "mallab"}]
    for fam in families[:8]:
        tags.append({"name": f'malware_classification:malware-family="{fam}"'})
    for t in attck[:30]:
        tags.append({"name": f'mitre-attack-pattern:{t}'})
    if verdict:
        tags.append({"name": f"mallab:verdict={verdict}"})
    # threat_level_id: 1 high, 2 medium, 3 low, 4 undefined. analysis: 0 initial,1 ongoing,2 complete.
    level = {"malicious": "1", "suspicious": "2", "clean": "3"}.get(verdict, "4")
    return {"Event": {"info": f"MalLab: {case_name}"[:255], "distribution": "0", "threat_level_id": level,
                      "analysis": "2", "Attribute": attrs, "Tag": tags}}


def push(case_name: str, iocs: dict, families: list[str], attck: list[str], verdict: str = "") -> dict:
    """Create the MISP Event. Returns {ok, event_id, url, attributes}. Raises on failure."""
    url = (os.environ.get("MISP_URL") or "").rstrip("/")
    key = os.environ.get("MISP_API_KEY") or ""
    if not url or not key:
        raise RuntimeError("MISP isn't configured. Set the MISP URL and API key in Settings.")
    verify = os.environ.get("MISP_VERIFY", "1") != "0"
    event = build_event(case_name, iocs, families, attck, verdict)
    n_attr = len(event["Event"]["Attribute"])
    if not n_attr:
        raise ValueError("this case has no indicators to push")
    headers = {"Authorization": key, "Accept": "application/json", "Content-Type": "application/json"}
    with httpx.Client(timeout=60, verify=verify, headers=headers) as c:
        r = c.post(f"{url}/events", json=event)
        if r.status_code in (401, 403):
            raise RuntimeError("MISP rejected the API key (check it has event-creation rights).")
        r.raise_for_status()
        data = r.json()
    ev = (data.get("Event") or {})
    eid = ev.get("id")
    return {"ok": True, "event_id": eid, "attributes": n_attr,
            "url": f"{url}/events/view/{eid}" if eid else url}


def set_config(misp_url: str | None = None, misp_key: str | None = None, misp_verify=None):
    if misp_url is not None and misp_url.strip():
        os.environ["MISP_URL"] = misp_url.strip().rstrip("/")
    if misp_key:
        os.environ["MISP_API_KEY"] = misp_key.strip()
    if misp_verify is not None:
        os.environ["MISP_VERIFY"] = "1" if misp_verify else "0"
