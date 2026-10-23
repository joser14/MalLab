"""Fuse every piece of evidence about a sample into one verdict, score, family and confidence.

Commercial sandboxes lead with a single answer: malicious / suspicious / clean, a 0-100 score,
and the family if known. MalLab gathers the parts (static risk, behaviour detections, threat
intel, YARA, Sigma, memory implants, group leads); this turns them into that one answer, with the
reasons that drove it so the analyst can see why. Pure logic over dicts — no I/O.

The verdict is deliberately conservative about "clean": absence of evidence (nothing detonated,
no intel hit) is reported as "unknown / not enough signal", never as "clean".
"""

import re

VERDICTS = ("malicious", "suspicious", "clean", "unknown")
_RANK = {"unknown": 0, "clean": 1, "suspicious": 2, "malicious": 3}

# Detection names that, on their own, make a sample malicious (not just suspicious).
STRONG = {
    "Process injection capability": 0, "Remote thread injection": 0, "Code implanted in memory": 0,
    "LSASS memory access": 0, "Persistence via Run key": 0, "Persistence via scheduled task": 0,
    "Persistence via service": 0, "Recovery inhibition": 0, "Security tool tampering": 0,
    "Mass file activity": 0, "Mass file deletion": 0, "Ransom_Note_Indicators": 0,
}

# Strings in a YARA pack rule name that name a family rather than a generic trait.
_GENERIC_RULE = re.compile(r"(?i)^(SUSP|SUSPICIOUS|INDICATOR|PE_|Windows_|Generic|Anomaly|Hunting|"
                           r"Mono_|Base64|Hex_|Big_Numbers|Embedded_|Packer|UPX|NETexecutableMicrosoft|"
                           r"IDDQD|SEH__|Misc_|Check_|contentis_base64|PowerShell_)")
_CLEAN_FAMILY = re.compile(r"[^A-Za-z0-9._\- ]+")


def _family_from_label(label: str) -> str | None:
    """Pull a family out of an AV / intel label like 'Trojan.Win32.Emotet' or 'win.qakbot'."""
    if not label:
        return None
    parts = re.split(r"[.:/\\]", label)
    skip = {"win", "win32", "win64", "trojan", "backdoor", "worm", "virus", "ransom", "ransomware",
            "downloader", "dropper", "pua", "pup", "hacktool", "riskware", "generic", "gen", "a", "b",
            "malware", "agent", "heur", "ml", "script", "msil", "elf", "html", "ne", "o", "corrupt",
            "linux", "osx", "macos", "android", "unix", "multi", "java", "python", "perl", "vbs", "js",
            "bat", "ps1", "doc", "x97m", "w97m", "o97m", "exe", "dll", "behaveslike", "application"}
    cands = [p for p in parts if p and p.lower() not in skip and not re.fullmatch(r"[0-9a-fx]+", p.lower())
             and len(p) >= 3]
    return cands[0].strip().title() if cands else None


def _families(intel, enrich, static, detections, groups) -> list[str]:
    seen, out = set(), []

    def add(name):
        if not name:
            return
        name = _CLEAN_FAMILY.sub("", str(name)).strip()[:40]
        if name and name.lower() not in seen and len(name) >= 3:
            seen.add(name.lower())
            out.append(name)

    for lbl in (intel or {}).get("labels", []):
        add(_family_from_label(lbl))
    for f in (enrich or {}).get("families", []):
        add(f)
    for m in ((static or {}).get("yara") or {}).get("matches", []):
        if m.get("source") not in (None, "rules") and not _GENERIC_RULE.search(m.get("rule", "")):
            add(m["rule"].split("_")[-1] if "_" in m["rule"] else m["rule"])
    for g in groups or []:
        for fam in (g.get("families") or "").split(","):
            add(fam)
    return out[:6]


def assess(static=None, detections=None, intel=None, enrich=None, groups=None, dynamic=None) -> dict:
    """Return {verdict, score, confidence, family, families, reasons, sources}.

    static: static report; detections: signatures.evaluate() result; intel: threat_intel summary
    (its 'summary' sub-dict); enrich: case IOC-enrichment summary; groups: linked actor rows;
    dynamic: the latest dynamic report (for 'did it actually run')."""
    static = static or {}
    detections = detections or {}
    intel = intel or {}
    reasons, sources, score = [], set(), 0

    # --- static risk (0-100) contributes up to ~45
    risk = int(static.get("risk") or 0)
    if risk:
        score += min(45, round(risk * 0.45))
        if risk >= 25:
            reasons.append(f"static risk {risk}/100")
            sources.add("static")

    # --- behaviour / signature detections
    dets = detections.get("detections") or []
    sev_counts = {s: 0 for s in ("info", "low", "medium", "high")}
    strong_hit = []
    for d in dets:
        sev_counts[d.get("severity", "info")] = sev_counts.get(d.get("severity", "info"), 0) + 1
        if d["name"] in STRONG or any(d["name"].startswith(p) for p in ("Sigma: ",)) and d.get("severity") == "high":
            strong_hit.append(d["name"])
    score += min(30, sev_counts["high"] * 12 + sev_counts["medium"] * 5 + sev_counts["low"] * 1)
    if sev_counts["high"]:
        reasons.append(f"{sev_counts['high']} high-severity detection(s)")
        sources.add("behaviour")
    if strong_hit:
        sources.add("behaviour")

    # --- threat intel
    intel_verdict = intel.get("verdict", "unknown")
    hits = int(intel.get("hits") or 0)
    if intel_verdict == "malicious" and hits:
        score += 40
        reasons.append(f"flagged malicious by {hits} intel source(s)")
        sources.add("intel")
    elif intel_verdict == "suspicious" and hits:
        score += 18
        reasons.append("suspicious to threat intel")
        sources.add("intel")
    elif intel_verdict == "clean" and hits:
        reasons.append("intel sources report clean")
        sources.add("intel")

    # --- enrichment (named families / actors from IOC lookups)
    enrich = enrich or {}
    if enrich.get("actors"):
        score += 12
        reasons.append("IOCs tie to a tracked actor")
        sources.add("intel")

    # --- named family from any source is itself strong evidence
    families = _families(intel, enrich, static, dets and detections, groups)
    if families:
        score += 15
        sources.add("family")

    score = max(0, min(100, score))

    # --- verdict decision
    executed = bool((dynamic or {}).get("detonated"))
    if intel_verdict == "malicious" and hits or strong_hit or (families and (sources & {"intel", "behaviour"})) or score >= 70:
        verdict = "malicious"
    elif score >= 35 or intel_verdict == "suspicious" or sev_counts["medium"]:
        verdict = "suspicious"
    elif intel_verdict == "clean" and hits and not dets and score < 15:
        verdict = "clean"
    else:
        verdict = "unknown"

    # --- confidence from how many independent sources agree
    n = len(sources)
    if verdict == "malicious" and ("intel" in sources or "family" in sources) and n >= 2:
        confidence = "high"
    elif n >= 2:
        confidence = "medium"
    elif n == 1:
        confidence = "low"
    else:
        confidence = "low"

    # Keep the headline score in step with the verdict, so the gauge never disagrees with the word.
    if verdict == "malicious":
        score = max(score, 72)
    elif verdict == "suspicious":
        score = max(score, 38)
    elif verdict == "clean":
        score = min(score, 10)

    if verdict == "unknown" and not dets and not hits:
        reasons.append("not enough signal yet" + ("" if executed else " (not detonated)"))

    return {"verdict": verdict, "score": score, "confidence": confidence,
            "family": families[0] if families else None, "families": families,
            "reasons": reasons[:8], "sources": sorted(sources),
            "max_severity": detections.get("max_severity", "info"),
            "attck": detections.get("attck", [])}


def worst(assessments: list[dict]) -> dict:
    """Roll several sample verdicts into one case-level verdict (the most severe)."""
    if not assessments:
        return {"verdict": "unknown", "score": 0, "confidence": "low", "families": []}
    top = max(assessments, key=lambda a: (_RANK[a["verdict"]], a["score"]))
    fams = []
    for a in assessments:
        for f in a.get("families") or []:
            if f not in fams:
                fams.append(f)
    return {"verdict": top["verdict"], "score": max(a["score"] for a in assessments),
            "confidence": top["confidence"], "families": fams[:8]}
