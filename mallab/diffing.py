"""Comparisons: diff two detonation runs, compare samples across a case, and derive a
network / C2 beacon timeline from the per-poll connection snapshots.
"""


def endpoint_host(ep: str) -> str:
    """'1.2.3.4:443 [Established]' -> '1.2.3.4'; '2001:db8::1:443 [x]' -> '2001:db8::1'."""
    ep = str(ep).split(" ", 1)[0]
    if ep.startswith("["):
        return ep[1:].split("]", 1)[0]
    return ep.rsplit(":", 1)[0] if ":" in ep else ep


def _set(d, key):
    return set(str(x) for x in (d.get(key) or []))


def _proc_names(d):
    return set((p.get("name") or "") + " " + (p.get("cmd") or "") for p in (d.get("new_processes") or []))


def diff_runs(a: dict, b: dict) -> dict:
    """What changed between run A and run B (B relative to A)."""
    out = {}
    for label, key in [("files", "new_files"), ("runkeys", "new_runkeys"),
                       ("tasks", "new_tasks"), ("services", "new_services"),
                       ("network", "network"), ("dns", "dns")]:
        sa, sb = _set(a, key), _set(b, key)
        out[label] = {"only_a": sorted(sa - sb), "only_b": sorted(sb - sa),
                      "shared": sorted(sa & sb)}
    pa, pb = _proc_names(a), _proc_names(b)
    out["processes"] = {"only_a": sorted(pa - pb), "only_b": sorted(pb - pa),
                        "shared": sorted(pa & pb)}
    return out


def compare_samples(samples: list[dict]) -> dict:
    """Find overlap across samples. Each item: {filename, sha256, static, detections}.
    Returns shared IOCs, shared suspicious imports and shared detection names."""
    per = []
    for s in samples:
        st = s.get("static") or {}
        io = st.get("iocs") or {}
        pe = st.get("pe") or {}
        per.append({
            "filename": s["filename"], "sha256": s["sha256"],
            "iocs": set(io.get("urls", []) + io.get("ips", []) + io.get("domains", [])),
            "imports": set(pe.get("suspicious_imports", [])),
            "detections": set(d["name"] for d in (s.get("detections") or {}).get("detections", [])),
        })

    def shared(key):
        if not per:
            return []
        inter = set(per[0][key])
        for p in per[1:]:
            inter &= p[key]
        return sorted(inter)

    # Pairwise IOC overlaps (which samples share which indicator).
    ioc_map = {}
    for p in per:
        for ioc in p["iocs"]:
            ioc_map.setdefault(ioc, []).append(p["filename"])
    shared_iocs = {k: v for k, v in ioc_map.items() if len(v) > 1}

    return {"count": len(per),
            "shared_iocs_all": shared("iocs"),
            "shared_imports_all": shared("imports"),
            "shared_detections_all": shared("detections"),
            "ioc_overlap": shared_iocs}


def beacon_timeline(dyn: dict) -> dict:
    """From the timestamped connection polls, list each endpoint's contact times and flag
    regular intervals that look like C2 beaconing."""
    samples = dyn.get("net_timeline") or []  # [{t: seconds, endpoints: [...]}]
    if not samples:
        return {"endpoints": [], "note": "no timeline captured"}
    first = samples[0]["t"]
    seen: dict[str, list[float]] = {}
    for snap in samples:
        rel = round(snap["t"] - first, 1)
        for ep in snap.get("endpoints", []):
            host = endpoint_host(ep)
            seen.setdefault(host, [])
            if not seen[host] or seen[host][-1] != rel:
                seen[host].append(rel)
    endpoints = []
    for host, times in seen.items():
        intervals = [round(t2 - t1, 1) for t1, t2 in zip(times, times[1:])]
        beacon = None
        if len(intervals) >= 3:
            avg = sum(intervals) / len(intervals)
            jitter = (max(intervals) - min(intervals))
            if avg > 0 and jitter <= max(2.0, 0.4 * avg):
                beacon = {"interval_s": round(avg, 1), "beats": len(times)}
        endpoints.append({"host": host, "contacts": len(times),
                          "first_s": times[0], "last_s": times[-1], "beacon": beacon})
    endpoints.sort(key=lambda e: e["contacts"], reverse=True)
    return {"endpoints": endpoints,
            "beaconing": [e for e in endpoints if e["beacon"]]}
