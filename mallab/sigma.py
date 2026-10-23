"""Sigma rules over a detonation's Sysmon events.

SigmaHQ (https://github.com/SigmaHQ/sigma, Detection Rule License 1.1) publishes thousands of
community detections for Windows. Their field names are Sysmon's own (Image, CommandLine,
TargetObject, ...), so they run directly on the events the monitor already exports. This is a
small matcher for the parts of the Sigma spec those rules use: selections (maps and lists, with
contains / startswith / endswith / all / re / cidr / windash / exists / cased modifiers and
* ? wildcards) and conditions (and, or, not, parentheses, "1 of x*", "all of them").
Rules using anything else (aggregations, base64 transforms, field references) are skipped and
counted, never half-matched.

Only events from the sample's own process lineage are matched (see sysmon.py), so Windows'
background activity in the VM doesn't produce hits.
"""

import fnmatch
import ipaddress
import re
from pathlib import Path

# Sigma logsource category -> Sysmon event IDs it covers.
CATEGORY_EIDS = {
    "process_creation": {1}, "network_connection": {3}, "process_termination": {5},
    "driver_load": {6}, "image_load": {7}, "create_remote_thread": {8}, "raw_access_thread": {9},
    "process_access": {10}, "file_event": {11}, "registry_add": {12}, "registry_delete": {12},
    "registry_set": {13}, "registry_rename": {14}, "registry_event": {12, 13, 14},
    "create_stream_hash": {15}, "pipe_created": {17, 18}, "wmi_event": {19, 20, 21},
    "dns_query": {22}, "file_delete": {23, 26}, "file_delete_detected": {26},
}
LEVEL_SEVERITY = {"informational": "info", "low": "low", "medium": "medium", "high": "high", "critical": "high"}
SUPPORTED_MODS = {"contains", "startswith", "endswith", "all", "re", "cidr", "windash", "exists", "cased",
                  "i", "m", "s"}   # i/m/s are regex flags
MAX_HITS_PER_RULE = 10


class Unsupported(Exception):
    pass


def _glob_rx(value: str, mode: str, cased: bool) -> re.Pattern:
    """Sigma wildcards: * and ? (\\* and \\? are literals). mode: equals/contains/startswith/endswith."""
    out, i = [], 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if ch == "*" else "." if ch == "?" else re.escape(ch))
        i += 1
    body = "".join(out)
    if mode in ("contains", "endswith"):
        body = ".*" + body
    if mode in ("contains", "startswith"):
        body = body + ".*"
    return re.compile(r"\A(?:" + body + r")\Z", re.S | (0 if cased else re.I))


def _windash(v: str) -> list[str]:
    out = {v}
    for a in ("-", "/", "–", "—", "―"):
        out.add(re.sub(r"(^|\s)[-/–—―]", lambda m: m.group(1) + a, v))
    return list(out)


def _field_matcher(spec: str, values):
    """Compile one 'Field|mod|mod: value(s)' entry into a predicate over an event's data."""
    field, *mods = spec.split("|")
    bad = [m for m in mods if m not in SUPPORTED_MODS]
    if bad:
        raise Unsupported(f"modifier {bad[0]}")
    vals = values if isinstance(values, list) else [values]
    cased = "cased" in mods
    if "exists" in mods:
        want = bool(vals[0])
        return lambda d: (bool(d.get(field)) if field else False) == want
    if "windash" in mods:
        vals = [w for v in vals for w in (_windash(str(v)) if v is not None else [None])]
    preds = []
    for v in vals:
        if v is None:
            preds.append(lambda s: s == "")
        elif "re" in mods:
            flags = (re.I if "i" in mods else 0) | (re.M if "m" in mods else 0) | (re.S if "s" in mods else 0)
            rx = re.compile(str(v), flags)
            preds.append(lambda s, rx=rx: bool(rx.search(s)))
        elif "cidr" in mods:
            net = ipaddress.ip_network(str(v), strict=False)

            def in_net(s, net=net):
                try:
                    return ipaddress.ip_address(s) in net
                except ValueError:
                    return False
            preds.append(in_net)
        else:
            mode = next((m for m in ("contains", "startswith", "endswith") if m in mods), "equals")
            rx = _glob_rx(str(v), mode, cased)
            preds.append(lambda s, rx=rx: bool(rx.match(s)))
    combine = all if "all" in mods else any

    if not field:   # keyword search over every value of the event
        return lambda d: combine(any(p(str(x)) for x in d.values()) for p in preds)
    return lambda d: combine(p(str(d.get(field, "") or "")) for p in preds)


def _selection(sel):
    """A selection is a map (all fields must match), a list of maps (any), or a list of keywords."""
    if isinstance(sel, dict):
        parts = [_field_matcher(k, v) for k, v in sel.items()]
        return lambda d: all(p(d) for p in parts)
    if isinstance(sel, list) and sel and all(isinstance(x, dict) for x in sel):
        alts = [_selection(x) for x in sel]
        return lambda d: any(a(d) for a in alts)
    if isinstance(sel, list) and all(isinstance(x, (str, int)) for x in sel):
        return _field_matcher("", [str(x) for x in sel])
    raise Unsupported("selection shape")


_TOK = re.compile(r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[\w*.-]+)\s*", re.I)


def _condition(text: str, sels: dict):
    """Recursive-descent parser for Sigma conditions -> predicate."""
    if "|" in text:
        raise Unsupported("aggregation")
    toks, pos = [], 0
    while pos < len(text):
        m = _TOK.match(text, pos)
        if not m or m.end() == pos:
            raise Unsupported(f"condition syntax: {text!r}")
        toks.append(m.group(1))
        pos = m.end()
    toks.append(None)
    i = 0

    def peek():
        return toks[i].lower() if toks[i] else None

    def take():
        nonlocal i
        i += 1
        return toks[i - 1]

    def names(pattern):
        if pattern.lower() == "them":
            return [s for n, s in sels.items() if not n.startswith("_")]
        got = [s for n, s in sels.items() if fnmatch.fnmatchcase(n, pattern)]
        if not got:
            raise Unsupported(f"unknown selection {pattern}")
        return got

    def atom():
        t = peek()
        if t == "(":
            take()
            p = expr()
            if take() != ")":
                raise Unsupported("unbalanced parentheses")
            return p
        if t == "not":
            take()
            p = atom()
            return lambda d: not p(d)
        if t in ("1 of", "all of"):
            take()
            group = names(take())
            return (lambda d: any(s(d) for s in group)) if t == "1 of" else (lambda d: all(s(d) for s in group))
        name = take()
        if name is None or name not in sels:
            raise Unsupported(f"unknown selection {name}")
        return sels[name]

    def conj():
        p = atom()
        while peek() == "and":
            take()
            q, a = atom(), p
            p = lambda d, a=a, q=q: a(d) and q(d)
        return p

    def expr():
        p = conj()
        while peek() == "or":
            take()
            q, a = conj(), p
            p = lambda d, a=a, q=q: a(d) or q(d)
        return p

    pred = expr()
    if toks[i] is not None:
        raise Unsupported("trailing tokens")
    return pred


def compile_rule(doc: dict) -> dict | None:
    """Compile a Sigma rule document, or return None if it isn't for Windows Sysmon data."""
    if not isinstance(doc, dict) or not isinstance(doc.get("detection"), dict):
        return None
    ls = doc.get("logsource") or {}
    product, category, service = ls.get("product"), ls.get("category"), ls.get("service")
    if product not in (None, "windows"):
        return None
    if category in CATEGORY_EIDS:
        eids = CATEGORY_EIDS[category]
    elif service == "sysmon" and not category:
        eids = None            # the rule filters on EventID itself
    else:
        return None
    det = dict(doc["detection"])
    cond = det.pop("condition", None)
    det.pop("timeframe", None)
    if not cond:
        return None
    sels = {name: _selection(sel) for name, sel in det.items()}
    conds = cond if isinstance(cond, list) else [cond]
    preds = [_condition(str(c), sels) for c in conds]
    tags = [str(t) for t in doc.get("tags") or []]
    attck = sorted({t[len("attack."):].upper() for t in tags
                    if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t, re.I)})
    return {"id": str(doc.get("id") or ""), "title": str(doc.get("title") or "Sigma rule")[:200],
            "level": str(doc.get("level") or "medium").lower(), "description": str(doc.get("description") or "")[:600],
            "attck": attck, "eids": eids, "match": lambda d: any(p(d) for p in preds),
            "falsepositives": [str(x) for x in doc.get("falsepositives") or []][:5]}


def load_rules(rules_dir: Path) -> dict:
    """Compile every applicable .yml under rules_dir. Returns {rules, skipped, errors}."""
    import yaml
    rules, skipped, errors = [], 0, 0
    root = Path(rules_dir)
    if not root.is_dir():
        return {"rules": [], "skipped": 0, "errors": 0}
    for f in sorted(root.rglob("*.yml")):
        try:
            for doc in yaml.safe_load_all(f.read_text(encoding="utf-8", errors="replace")):
                try:
                    r = compile_rule(doc)
                except Unsupported:
                    skipped += 1
                    continue
                except (re.error, ValueError, TypeError):
                    errors += 1
                    continue
                if r:
                    r["file"] = f.name
                    rules.append(r)
        except yaml.YAMLError:
            errors += 1
    return {"rules": rules, "skipped": skipped, "errors": errors}


_CACHE: dict = {}


def cached_rules(rules_dir: Path) -> dict:
    """Rules compiled once per folder state (the newest file's mtime and the file count)."""
    root = Path(rules_dir)
    files = list(root.rglob("*.yml")) if root.is_dir() else []
    key = (str(root), len(files), max((f.stat().st_mtime for f in files), default=0))
    if _CACHE.get("key") != key:
        _CACHE.update(key=key, value=load_rules(root))
    return _CACHE["value"]


def _summary(eid, d: dict) -> str:
    img = d.get("Image") or d.get("SourceImage") or ""
    what = (d.get("CommandLine") or d.get("TargetObject") or d.get("TargetFilename") or d.get("QueryName")
            or d.get("DestinationHostname") or d.get("DestinationIp") or d.get("TargetImage") or "")
    return f"[{eid}] {Path(img.replace(chr(92), '/')).name}: {what}"[:400]


def match(events: list, compiled: dict, is_mine) -> list[dict]:
    """Run compiled rules over the events is_mine(event) accepts. Returns hits grouped per rule."""
    by_eid: dict = {}
    for r in compiled.get("rules") or []:
        for e in (r["eids"] or [None]):
            by_eid.setdefault(e, []).append(r)
    any_eid = by_eid.get(None, [])
    hits: dict = {}
    for ev in events or []:
        if not isinstance(ev, dict) or not isinstance(ev.get("data"), dict) or not is_mine(ev):
            continue
        try:
            eid = int(ev.get("id"))
        except (TypeError, ValueError):
            continue
        d = {**{k: str(v) for k, v in ev["data"].items()}, "EventID": str(eid)}
        for r in by_eid.get(eid, []) + any_eid:
            try:
                ok = r["match"](d)
            except re.error:
                ok = False
            if ok:
                h = hits.setdefault(r["id"] or r["title"], {
                    "id": r["id"], "title": r["title"], "level": r["level"], "description": r["description"],
                    "attck": r["attck"], "falsepositives": r["falsepositives"], "count": 0, "evidence": []})
                h["count"] += 1
                if len(h["evidence"]) < MAX_HITS_PER_RULE:
                    h["evidence"].append(_summary(eid, d))
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    return sorted(hits.values(), key=lambda h: -order.get(h["level"], 0))


def lineage_filter(behavior: dict):
    """is_mine(event) for the sample's lineage; everything is 'mine' when the lineage is unknown."""
    lin = (behavior or {}).get("lineage") or {}
    guids, pids = set(lin.get("guids") or []), set(lin.get("pids") or [])
    if not (behavior or {}).get("lineage_known"):
        return lambda ev: True

    def is_mine(ev):
        d = ev.get("data") or {}
        g = d.get("ProcessGuid") or d.get("SourceProcessGuid") or d.get("SourceProcessGUID")
        if g:
            return g in guids
        try:
            return int(d.get("ProcessId") or d.get("SourceProcessId")) in pids
        except (TypeError, ValueError):
            return False
    return is_mine
