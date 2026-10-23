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


def parse(events: list, monitor_pid=None, launcher_pid=None) -> dict:
    """Return {processes, network, dns, files, registry, remote_threads, lsass_access,
    file_deletes, counts}. Empty lists when there were no events."""
    monitor_pid, launcher_pid = _int(monitor_pid), _int(launcher_pid)
    out = {k: [] for k in ("processes", "network", "dns", "files", "registry",
                           "remote_threads", "lsass_access", "file_deletes")}
    tooling_pids = set()

    for ev in events or []:
        if not isinstance(ev, dict):
            continue
        eid, d, t = _int(ev.get("id")), ev.get("data"), _s(ev.get("time"), 40)
        if not isinstance(d, dict):
            continue
        pid, image = _int(d.get("ProcessId")), _s(d.get("Image"), 500)

        if eid == 1:
            ppid = _int(d.get("ParentProcessId"))
            # Children of the monitor are our own tooling, except the launcher we started.
            if (ppid == monitor_pid and pid != launcher_pid) or _name(image) in TOOLING:
                tooling_pids.add(pid)
                continue
            if ppid in tooling_pids:
                tooling_pids.add(pid)
                continue
            out["processes"].append({
                "time": t, "pid": pid, "ppid": ppid, "guid": _s(d.get("ProcessGuid"), 60),
                "parent_guid": _s(d.get("ParentProcessGuid"), 60), "image": image,
                "name": PureWindowsPath(image).name if image else "?",
                "cmd": _s(d.get("CommandLine")), "parent_image": _s(d.get("ParentImage"), 500),
                "user": _s(d.get("User"), 200), "integrity": _s(d.get("IntegrityLevel"), 30),
                "hashes": _s(d.get("Hashes"), 400), "launcher": pid == launcher_pid})
            continue

        if pid == monitor_pid or pid in tooling_pids or _name(image) in TOOLING:
            continue
        if eid == 3:
            out["network"].append({
                "time": t, "pid": pid, "image": image, "proto": _s(d.get("Protocol"), 10),
                "dst_ip": _s(d.get("DestinationIp"), 64), "dst_port": _int(d.get("DestinationPort")),
                "dst_host": _s(d.get("DestinationHostname"), 255)})
        elif eid == 22:
            out["dns"].append({"time": t, "pid": pid, "image": image,
                               "query": _s(d.get("QueryName"), 255),
                               "results": _s(d.get("QueryResults"), 500)})
        elif eid == 11:
            out["files"].append({"time": t, "pid": pid, "image": image,
                                 "path": _s(d.get("TargetFilename"), 500)})
        elif eid in (23, 26):
            out["file_deletes"].append({"time": t, "pid": pid, "image": image,
                                        "path": _s(d.get("TargetFilename"), 500)})
        elif eid in (12, 13, 14):
            out["registry"].append({"time": t, "pid": pid, "image": image,
                                    "event": _s(d.get("EventType"), 30),
                                    "key": _s(d.get("TargetObject"), 500),
                                    "details": _s(d.get("Details"), 500)})
        elif eid == 8:
            out["remote_threads"].append({"time": t, "source": _s(d.get("SourceImage"), 500),
                                          "target": _s(d.get("TargetImage"), 500),
                                          "source_pid": _int(d.get("SourceProcessId")),
                                          "target_pid": _int(d.get("TargetProcessId"))})
        elif eid == 10 and _name(_s(d.get("TargetImage"))) == LSASS:
            src = _s(d.get("SourceImage"), 500)
            if _name(src) not in TOOLING:
                out["lsass_access"].append({"time": t, "source": src,
                                            "access": _s(d.get("GrantedAccess"), 20)})

    for k in out:
        out[k] = out[k][:CAP]
    out["dns"] = list({(x["query"]): x for x in out["dns"] if x["query"]}.values())
    out["counts"] = {k: len(v) for k, v in out.items() if isinstance(v, list)}
    return out


def process_tree(behavior: dict) -> list[dict]:
    """Parent/child forest from Sysmon process-create events, linked by ProcessGuid."""
    procs = (behavior or {}).get("processes") or []
    nodes = {p["guid"] or f"pid:{p['pid']}": {**p, "children": []} for p in procs}
    roots = []
    for key, node in nodes.items():
        parent = nodes.get(node.get("parent_guid") or "")
        (parent["children"] if parent and parent is not node else roots).append(node)
    return roots
