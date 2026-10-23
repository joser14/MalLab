"""Turn raw Sysmon events from a detonation into structured behaviour.

The monitor exports each event as {id, time, data: {Image, CommandLine, ...}}. Sysmon sees
processes that started and exited between the monitor's snapshots, so this is the more
complete record. The monitor's own tooling (pktmon, Sysmon, WMI helpers) is filtered out.
Pure logic over dicts, no I/O. Every field came from inside the VM, so everything is
treated as an untrusted string.
"""

from pathlib import PureWindowsPath

TOOLING = {"pktmon.exe", "sysmon64.exe", "sysmon.exe", "wmiprvse.exe", "conhost.exe", "fakenet.exe"}
LSASS = "lsass.exe"
CAP = 1000


def _s(v, n: int = 2000) -> str:
    return str(v or "")[:n]


def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _name(image: str) -> str:
    return PureWindowsPath(image).name.lower() if image else ""


KINDS = ("processes", "network", "dns", "files", "registry", "remote_threads", "lsass_access", "file_deletes")


def parse(events: list, monitor_pid=None, launcher_pid=None) -> dict:
    """Return {processes, network, dns, files, registry, remote_threads, lsass_access,
    file_deletes, counts, lineage_known, background}.

    Only the sample's lineage counts as its behaviour: the process the monitor launched, every
    process descended from it, and any process it injected a thread into. A fresh Windows VM
    has plenty going on by itself (SmartScreen, update helpers, Defender touching LSASS), and
    that goes into 'background' instead of the sample's detections. Older reports without a
    launcher PID keep every event, as before."""
    monitor_pid, launcher_pid = _int(monitor_pid), _int(launcher_pid)
    out = {k: [] for k in KINDS}
    bg = {k: [] for k in KINDS}
    tooling_pids, lineage, lineage_pids = set(), set(), set()   # lineage holds ProcessGuids
    lineage_known = False

    def add(kind, rec, guid, pid=None):
        # Match by ProcessGuid; fall back to the PID when an event carries no GUID.
        mine = not lineage_known or (guid in lineage if guid else pid in lineage_pids)
        (out if mine else bg)[kind].append(rec)

    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        eid, d, t = _int(ev.get("id")), ev.get("data"), _s(ev.get("time"), 40)
        if not isinstance(d, dict):
            continue
        pid, image = _int(d.get("ProcessId")), _s(d.get("Image"), 500)
        guid = _s(d.get("ProcessGuid"), 60)

        if eid == 1:
            ppid = _int(d.get("ParentProcessId"))
            # Children of the monitor are our own tooling, except the launcher we started.
            if (monitor_pid is not None and ppid == monitor_pid and pid != launcher_pid) or _name(image) in TOOLING:
                tooling_pids.add(pid)
                continue
            if ppid in tooling_pids:
                tooling_pids.add(pid)
                continue
            parent_guid = _s(d.get("ParentProcessGuid"), 60)
            if launcher_pid is not None and pid == launcher_pid:
                lineage_known = True
                lineage.add(guid)
                lineage_pids.add(pid)
            elif (parent_guid and parent_guid in lineage) or (not parent_guid and ppid in lineage_pids):
                lineage.add(guid)
                lineage_pids.add(pid)
            add("processes", {
                "time": t, "pid": pid, "ppid": ppid, "guid": guid,
                "parent_guid": parent_guid, "image": image,
                "name": PureWindowsPath(image).name if image else "?",
                "cmd": _s(d.get("CommandLine")), "parent_image": _s(d.get("ParentImage"), 500),
                "user": _s(d.get("User"), 200), "integrity": _s(d.get("IntegrityLevel"), 30),
                "hashes": _s(d.get("Hashes"), 400), "launcher": pid == launcher_pid}, guid, pid)
            continue

        if (monitor_pid is not None and pid == monitor_pid) or pid in tooling_pids or _name(image) in TOOLING:
            continue
        if eid == 3:
            add("network", {
                "time": t, "pid": pid, "image": image, "proto": _s(d.get("Protocol"), 10),
                "dst_ip": _s(d.get("DestinationIp"), 64), "dst_port": _int(d.get("DestinationPort")),
                "dst_host": _s(d.get("DestinationHostname"), 255)}, guid, pid)
        elif eid == 22:
            add("dns", {"time": t, "pid": pid, "image": image, "query": _s(d.get("QueryName"), 255),
                        "results": _s(d.get("QueryResults"), 500)}, guid, pid)
        elif eid == 11:
            add("files", {"time": t, "pid": pid, "image": image, "path": _s(d.get("TargetFilename"), 500)}, guid, pid)
        elif eid in (23, 26):
            add("file_deletes", {"time": t, "pid": pid, "image": image,
                                 "path": _s(d.get("TargetFilename"), 500)}, guid, pid)
        elif eid in (12, 13, 14):
            add("registry", {"time": t, "pid": pid, "image": image, "event": _s(d.get("EventType"), 30),
                             "key": _s(d.get("TargetObject"), 500), "details": _s(d.get("Details"), 500)}, guid, pid)
        elif eid == 8:
            src_guid = _s(d.get("SourceProcessGuid") or d.get("SourceProcessGUID"), 60)
            if lineage_known and src_guid in lineage:   # injected code acts for the sample from now on
                tgt = _s(d.get("TargetProcessGuid") or d.get("TargetProcessGUID"), 60)
                if tgt:
                    lineage.add(tgt)
            add("remote_threads", {"time": t, "source": _s(d.get("SourceImage"), 500),
                                   "target": _s(d.get("TargetImage"), 500),
                                   "source_pid": _int(d.get("SourceProcessId")),
                                   "target_pid": _int(d.get("TargetProcessId"))}, src_guid,
                _int(d.get("SourceProcessId")))
        elif eid == 10 and _name(_s(d.get("TargetImage"))) == LSASS:
            src = _s(d.get("SourceImage"), 500)
            if _name(src) not in TOOLING:
                add("lsass_access", {"time": t, "source": src, "access": _s(d.get("GrantedAccess"), 20)},
                    _s(d.get("SourceProcessGUID") or d.get("SourceProcessGuid"), 60), _int(d.get("SourceProcessId")))

    for k in KINDS:
        out[k] = out[k][:CAP]
    out["dns"] = list({(x["query"]): x for x in out["dns"] if x["query"]}.values())
    out["counts"] = {k: len(out[k]) for k in KINDS}
    out["lineage_known"] = lineage_known
    out["background"] = {"counts": {k: len(v) for k, v in bg.items()},
                         "processes": [{"name": p["name"], "cmd": p["cmd"][:300]} for p in bg["processes"][:100]],
                         "lsass_access": bg["lsass_access"][:20]}
    return out


def lineage_files(behavior: dict) -> set[str] | None:
    """Lower-cased paths the sample's lineage created (Sysmon FileCreate), or None when the
    lineage isn't known and callers should fall back to the noise filter."""
    if not (behavior or {}).get("lineage_known"):
        return None
    return {f["path"].lower() for f in behavior.get("files") or [] if f.get("path")}


def process_tree(behavior: dict) -> list[dict]:
    """Parent/child forest from Sysmon process-create events, linked by ProcessGuid."""
    procs = (behavior or {}).get("processes") or []
    nodes = {p["guid"] or f"pid:{p['pid']}": {**p, "children": []} for p in procs}
    roots = []
    for key, node in nodes.items():
        parent = nodes.get(node.get("parent_guid") or "")
        (parent["children"] if parent and parent is not node else roots).append(node)
    return roots
