"""Threat-group tracking: parse MITRE ATT&CK groups, and score which tracked groups a sample
resembles.

Attribution is the analyst's call. suggest() only surfaces leads (a known family name matching
an intel label, overlapping techniques, IOCs shared with samples already linked to a group),
each with the reason it fired, so the analyst can confirm or dismiss the link.
"""

import re

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def split_list(v) -> list[str]:
    if isinstance(v, list):
        items = v
    else:
        items = re.split(r"[,\n;]", str(v or ""))
    return list(dict.fromkeys(s.strip()[:120] for s in items if str(s).strip()))


def parse_mitre(bundle: dict) -> list[dict]:
    """intrusion-set objects + their 'uses' relationships -> [{mitre_id, name, aliases,
    description, families, techniques}]. Revoked/deprecated entries are skipped."""
    items = [o for o in (bundle or {}).get("objects", []) if isinstance(o, dict)]
    objs = {o["id"]: o for o in items if o.get("id")}

    def ext_id(o):
        for r in o.get("external_references") or []:
            if r.get("source_name") == "mitre-attack" and r.get("external_id"):
                return r["external_id"]
        return None

    live = lambda o: not o.get("revoked") and not o.get("x_mitre_deprecated")
    groups = {oid: {"mitre_id": ext_id(o), "name": o.get("name", "?"),
                    "aliases": [a for a in o.get("aliases") or [] if a != o.get("name")],
                    "description": (o.get("description") or "")[:4000],
                    "families": [], "techniques": []}
              for oid, o in objs.items() if o.get("type") == "intrusion-set" and live(o)}
    for o in items:
        if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or not live(o):
            continue
        g, tgt = groups.get(o.get("source_ref")), objs.get(o.get("target_ref"))
        if not g or not tgt or not live(tgt):
            continue
        if tgt.get("type") in ("malware", "tool"):
            g["families"].append(tgt.get("name"))
        elif tgt.get("type") == "attack-pattern" and ext_id(tgt):
            g["techniques"].append(ext_id(tgt))
    out = []
    for g in groups.values():
        g["families"] = sorted(set(filter(None, g["families"])))
        g["techniques"] = sorted(set(g["techniques"]))
        out.append(g)
    return sorted(out, key=lambda g: g["name"].lower())


MISP_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json"
MALPEDIA_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/families"


def parse_misp(doc: dict) -> list[dict]:
    """MISP Galaxy threat-actor cluster -> [{name, aliases, country, motivation, description}]."""
    out = []
    for v in (doc or {}).get("values") or []:
        if not isinstance(v, dict) or not v.get("value"):
            continue
        meta = v.get("meta") or {}
        motive = meta.get("motive") or meta.get("cfr-type-of-incident") or []
        out.append({"name": str(v["value"])[:120],
                    "aliases": split_list(meta.get("synonyms") or []),
                    "country": str(meta.get("country") or "")[:10],
                    "motivation": ", ".join(split_list(motive))[:200],
                    "description": str(v.get("description") or "")[:4000]})
    return out


def parse_malpedia(doc: dict) -> dict[str, list[str]]:
    """Malpedia families -> {actor name: [family names]} from each family's 'attribution'."""
    out: dict[str, list[str]] = {}
    for fam_id, f in (doc or {}).items():
        if not isinstance(f, dict):
            continue
        fam = f.get("common_name") or fam_id
        for actor in f.get("attribution") or []:
            out.setdefault(str(actor), []).append(str(fam))
    return out


def merge_catalog(existing: list[dict], mitre: list[dict], misp: list[dict],
                  malpedia: dict[str, list[str]]) -> tuple[dict[str, dict], list[dict]]:
    """Fold the three public datasets into the tracked groups without losing analyst edits:
    lists (aliases, families, techniques) are unioned, scalar fields are only filled when empty,
    and notes are never touched. Returns ({actor_id: changed fields}, [new actors])."""
    rows = [dict(r, _new=False) for r in existing]
    index: dict[str, dict] = {}

    def keys(r):
        return {_norm(x) for x in [r.get("name", "")] + split_list(r.get("aliases")) if len(_norm(x)) >= 3}

    def reindex(r):
        for k in keys(r):
            index.setdefault(k, r)

    for r in rows:
        reindex(r)

    def find(name, aliases=(), mitre_id=""):
        if mitre_id:
            for r in rows:
                if r.get("mitre_id") == mitre_id:
                    return r
        k = _norm(name)
        if len(k) >= 3 and k in index:
            return index[k]
        # Alias-only match: accept it only when every alias hit points at the same group. Vendor
        # synonym lists overlap, and folding two different groups together would mislead attribution.
        hits = {id(index[a]): index[a] for a in (_norm(x) for x in aliases) if len(a) >= 3 and a in index}
        return next(iter(hits.values())) if len(hits) == 1 else None

    def union(r, field, items):
        cur = split_list(r.get(field))
        add = [i for i in split_list(items) if i.lower() not in {c.lower() for c in cur}]
        if add:
            r[field] = ", ".join(cur + add)
            r["_dirty"] = True

    def fill(r, field, value):
        if value and not r.get(field):
            r[field] = value
            r["_dirty"] = True

    def upsert(name, aliases, source, mitre_id=""):
        r = find(name, aliases, mitre_id)
        if not r:
            r = {"name": name, "aliases": "", "mitre_id": "", "families": "", "techniques": "",
                 "country": "", "motivation": "", "description": "", "notes": "",
                 "source": source, "_new": True}
            rows.append(r)
        union(r, "aliases", [a for a in aliases if _norm(a) != _norm(r["name"])])
        reindex(r)
        return r

    for g in mitre:
        r = upsert(g["name"], g["aliases"], "mitre", g.get("mitre_id") or "")
        fill(r, "mitre_id", g.get("mitre_id") or "")
        fill(r, "description", g.get("description"))
        union(r, "families", g["families"])
        union(r, "techniques", g["techniques"])
    for g in misp:
        r = upsert(g["name"], g["aliases"], "misp")
        fill(r, "country", g.get("country"))
        fill(r, "motivation", g.get("motivation"))
        fill(r, "description", g.get("description"))
    for actor, fams in malpedia.items():
        r = find(actor)
        if r:   # only enrich groups we know by name; don't invent groups from a bare label
            union(r, "families", fams)

    fields = ("name", "aliases", "mitre_id", "families", "techniques", "country",
              "motivation", "description", "source")
    updates = {r["id"]: {f: r.get(f, "") for f in fields} for r in rows if not r["_new"] and r.get("_dirty")}
    creates = [{f: r.get(f, "") for f in fields} for r in rows if r["_new"]]
    return updates, creates


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


def suggest(signals: dict, actors: list[dict], linked_iocs: dict[str, set] | None = None,
            limit: int = 5) -> list[dict]:
    """signals: {labels: [family/label strings], techniques: [ATT&CK IDs], iocs: set}.
    actors: rows with families/aliases/techniques as comma lists. Returns ranked leads."""
    labels = {_norm(l) for l in signals.get("labels") or [] if len(_norm(l)) >= 4}
    techs = set(signals.get("techniques") or [])
    iocs = set(signals.get("iocs") or [])
    out = []
    for a in actors:
        score, why = 0, []
        names = {_norm(x) for x in split_list(a.get("families")) if len(_norm(x)) >= 4}
        hit = sorted(l for l in labels if any(l == n or (len(n) >= 5 and n in l) for n in names))
        if hit:
            score += 50
            why.append(f"known malware family matches label: {', '.join(hit[:3])}")
        alias = {_norm(x) for x in [a.get("name", "")] + split_list(a.get("aliases")) if len(_norm(x)) >= 4}
        if labels & alias:
            score += 40
            why.append("an intel label names this group")
        shared_iocs = iocs & (linked_iocs or {}).get(a["id"], set())
        if shared_iocs:
            score += 40
            why.append(f"{len(shared_iocs)} IOC(s) shared with samples already linked to this group: "
                       + ", ".join(sorted(shared_iocs)[:3]))
        known = set(split_list(a.get("techniques")))
        overlap = techs & known
        # Technique overlap alone is weak evidence (many groups use the same techniques).
        if len(overlap) >= 3:
            pts = min(25, round(100 * len(overlap) / max(len(techs), 1) / 4))
            score += pts
            why.append(f"{len(overlap)} of {len(techs)} observed techniques are in its known TTPs")
        if score:
            out.append({"id": a["id"], "name": a["name"], "mitre_id": a.get("mitre_id"),
                        "score": min(score, 100), "why": why,
                        "strength": "strong" if score >= 50 else "moderate" if score >= 30 else "weak"})
    out.sort(key=lambda r: -r["score"])
    return out[:limit]
