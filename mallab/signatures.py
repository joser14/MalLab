"""Behavioral & static signature engine with MITRE ATT&CK mapping.

Turns raw static/dynamic findings into named detections, the way a professional sandbox
does ("Process Injection", "Persistence via Run key", …), each tagged with ATT&CK technique
IDs and the concrete evidence that fired it. Pure logic over the report dicts — no I/O.
"""

from pathlib import Path

from . import sysmon

SEV_ORDER ={"info": 0, "low": 1, "medium": 2, "high": 3}

# Living-off-the-land / script interpreters worth flagging when spawned or dropped.
LOLBINS = ("powershell", "cmd.exe", "wscript", "cscript", "mshta", "rundll32",
           "regsvr32", "certutil", "bitsadmin", "msiexec", "installutil", "schtasks")


# Every technique the rules can emit: ID -> (name, tactic). Tactics in kill-chain order below.
TECHNIQUES = {
    "T1055": ("Process Injection", "Defense Evasion"), "T1056.001": ("Keylogging", "Collection"),
    "T1622": ("Debugger Evasion", "Defense Evasion"), "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1573": ("Encrypted Channel", "Command and Control"), "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1543.003": ("Windows Service", "Persistence"), "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1620": ("Reflective Code Loading", "Defense Evasion"), "T1027.002": ("Software Packing", "Defense Evasion"),
    "T1027.009": ("Embedded Payloads", "Defense Evasion"), "T1137": ("Office Application Startup", "Persistence"),
    "T1059.005": ("Visual Basic", "Execution"), "T1140": ("Deobfuscate/Decode Files", "Defense Evasion"),
    "T1071": ("Application Layer Protocol", "Command and Control"), "T1106": ("Native API", "Execution"),
    "T1059": ("Command and Scripting Interpreter", "Execution"), "T1059.001": ("PowerShell", "Execution"),
    "T1547.001": ("Registry Run Keys", "Persistence"), "T1053.005": ("Scheduled Task", "Persistence"),
    "T1036": ("Masquerading", "Defense Evasion"), "T1071.004": ("DNS", "Command and Control"),
    "T1490": ("Inhibit System Recovery", "Impact"), "T1562.001": ("Disable or Modify Tools", "Defense Evasion"),
    "T1562": ("Impair Defenses", "Defense Evasion"), "T1082": ("System Information Discovery", "Discovery"),
    "T1033": ("System Owner/User Discovery", "Discovery"), "T1016": ("System Network Configuration Discovery", "Discovery"),
    "T1003.001": ("LSASS Memory", "Credential Access"), "T1485": ("Data Destruction", "Impact"),
    "T1070.004": ("File Deletion", "Defense Evasion"),
    "T1497": ("Virtualization/Sandbox Evasion", "Defense Evasion"), "T1055.012": ("Process Hollowing", "Defense Evasion"),
    "T1574": ("Hijack Execution Flow", "Persistence"), "T1056.004": ("Credential API Hooking", "Collection"),
}
TACTICS = ("Execution", "Persistence", "Defense Evasion", "Credential Access", "Discovery",
           "Collection", "Command and Control", "Impact")


def attck_matrix(detection_sets: list[dict]) -> list[dict]:
    """Group techniques from one or more evaluate() results by tactic:
    [{tactic, techniques: [{id, name, detections: [...], severity}]}] in kill-chain order."""
    by_id: dict[str, dict] = {}
    for res in detection_sets:
        for d in (res or {}).get("detections", []):
            for t in d["attck"]:
                e = by_id.setdefault(t, {"id": t, "name": TECHNIQUES.get(t, (t, ""))[0],
                                         "detections": [], "severity": "info"})
                if d["name"] not in e["detections"]:
                    e["detections"].append(d["name"])
                if SEV_ORDER[d["severity"]] > SEV_ORDER[e["severity"]]:
                    e["severity"] = d["severity"]
    out = []
    for tactic in TACTICS + ("Other",):
        techs = [e for t, e in sorted(by_id.items())
                 if TECHNIQUES.get(t, ("", "Other"))[1] == tactic]
        if techs:
            out.append({"tactic": tactic, "techniques": techs})
    return out


def _det(name, severity, attck, description, evidence):
    return {"name": name, "severity": severity, "attck": attck,
            "description": description, "evidence": evidence[:12]}


def _static_rules(st: dict) -> list[dict]:
    out = []
    pe = st.get("pe") or {}
    imps = set(pe.get("suspicious_imports") or [])

    def has(*names):
        return [i for i in imps if any(n.lower() in i.lower() for n in names)]

    inj = has("VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
              "NtUnmapViewOfSection", "QueueUserAPC")
    if len(inj) >= 2:
        out.append(_det("Process injection capability", "high", ["T1055"],
                        "Imports the classic allocate/write/create-thread set used to inject code "
                        "into other processes.", inj))
    keylog = has("GetAsyncKeyState", "SetWindowsHookEx", "GetKeyState")
    if keylog:
        out.append(_det("Keylogging capability", "medium", ["T1056.001"],
                        "Imports APIs used to capture keystrokes.", keylog))
    anti = has("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess")
    if anti:
        out.append(_det("Anti-debugging checks", "low", ["T1622"],
                        "Imports APIs used to detect a debugger.", anti))
    crypto = has("CryptEncrypt", "CryptDecrypt", "CryptGenKey", "BCryptEncrypt")
    if crypto:
        out.append(_det("Cryptographic API use", "medium", ["T1486", "T1573"],
                        "Uses cryptographic APIs (seen in ransomware and in C2 obfuscation).", crypto))
    dl = has("URLDownloadToFile", "InternetReadFile", "WinHttp", "HttpSendRequest", "InternetOpen")
    if dl:
        out.append(_det("Network download capability", "medium", ["T1105"],
                        "Imports APIs to download content from the network.", dl))
    svc = has("CreateService", "OpenSCManager")
    if svc:
        out.append(_det("Service installation capability", "medium", ["T1543.003"],
                        "Imports APIs to create or control Windows services.", svc))
    dynld = has("GetProcAddress", "LoadLibrary", "VirtualProtect")
    if dynld:
        out.append(_det("Dynamic API resolution", "low", ["T1027", "T1620"],
                        "Resolves APIs at runtime / changes memory protection (common in packed or "
                        "injecting code).", dynld))

    if pe.get("packed_hint") or st.get("entropy", 0) > 7.2:
        ev = [f"overall entropy {st.get('entropy')}"]
        ev += [f"{s['name']} entropy {s['entropy']}" for s in pe.get("sections", []) if s.get("suspicious")]
        out.append(_det("Packed / obfuscated", "medium", ["T1027.002"],
                        "High-entropy sections or very few imports suggest packing.", ev))

    emb = [f"{r['type']} resource ({r['size']:,} bytes)" for r in pe.get("resources") or [] if r.get("embedded_pe")]
    if emb:
        out.append(_det("Executable embedded in resources", "medium", ["T1027.009"],
                        "Carries a second PE inside its resources (typical dropper layout).", emb))
    if pe.get("tls_callbacks"):
        out.append(_det("TLS callbacks", "low", ["T1622"],
                        "Code that runs before the entry point; often used for anti-debugging.",
                        [f"{pe['tls_callbacks']} callback(s)"]))
    ov = pe.get("overlay") or {}
    if ov.get("size", 0) > 64 * 1024 and not pe.get("signed"):
        out.append(_det("Large overlay", "low", ["T1027"],
                        "Data appended after the last section (payloads and configs hide here).",
                        [f"{ov['size']:,} bytes at offset {ov['offset']:#x}"]))

    caps = (st.get("capa") or {}).get("capabilities") or []
    if caps:
        out.append(_det("Capabilities identified by capa", "low",
                        sorted({t for c in caps for t in c["attck"]}),
                        f"capa matched {len(caps)} capability rule(s) in the code.",
                        [c["name"] for c in caps]))

    macros = st.get("office_macros") or {}
    if macros.get("has_macros"):
        sev = "high" if macros.get("autoexec") else "medium"
        out.append(_det("Office document macros", sev, ["T1137", "T1059.005"],
                        "Document contains VBA macros"
                        + (f" with auto-exec: {', '.join(macros['autoexec'])}" if macros.get("autoexec") else "")
                        + ".", macros.get("autoexec") or ["VBA present"]))

    arch = st.get("archive") or {}
    if arch.get("encrypted"):
        out.append(_det("Password-protected archive", "medium", ["T1027", "T1140"],
                        "Encrypted archive — a common way to bypass scanners during delivery.",
                        ["encrypted zip"]))
    if arch.get("risky_members"):
        out.append(_det("Executable bundled in archive", "medium", ["T1105"],
                        "Archive contains executable/script members.", arch["risky_members"]))

    io = st.get("iocs") or {}
    if io.get("urls") or io.get("ips"):
        out.append(_det("Embedded network indicators", "low", ["T1071"],
                        "Hard-coded URLs/IPs found in the file.",
                        (io.get("urls") or []) + (io.get("ips") or [])))
    return out


def _cmdlines(dyn: dict) -> list[str]:
    """'name cmdline' for every process the sample started: snapshot processes plus Sysmon's
    (which also has short-lived ones), minus the interpreter the monitor used to launch it."""
    launcher = dyn.get("launcher_pid")
    procs = [p for p in (dyn.get("new_processes") or []) if p.get("pid") != launcher or launcher is None]
    procs += [p for p in ((dyn.get("behavior") or {}).get("processes") or []) if not p.get("launcher")]
    return list(dict.fromkeys(f"{(p.get('name') or '').lower()} {(p.get('cmd') or '').lower()}"
                              for p in procs))


def _dynamic_rules(dyn: dict) -> list[dict]:
    out = []
    procs = dyn.get("new_processes") or []
    beh = dyn.get("behavior") or {}
    names = _cmdlines(dyn)

    shown = beh.get("processes") or procs
    if shown:
        out.append(_det("Child process execution", "info", ["T1106"],
                        f"{len(shown)} new process(es) created during detonation.",
                        [p.get("name", "?") for p in shown]))
    lol = [n for n in names if any(b in n for b in LOLBINS)]
    if lol:
        out.append(_det("Living-off-the-land binary spawned", "high", ["T1059"],
                        "Launched a script interpreter or LOLBin — a hallmark of fileless/staged attacks.", lol))
    enc = [n for n in names if "-enc" in n or "frombase64" in n or "-nop" in n or "-w hidden" in n or "bypass" in n]
    if enc:
        out.append(_det("Suspicious PowerShell flags", "high", ["T1059.001", "T1027"],
                        "Encoded/hidden/execution-policy-bypass command line observed.", enc))

    if dyn.get("new_runkeys"):
        out.append(_det("Persistence via Run key", "high", ["T1547.001"],
                        "Added an autostart entry under a Run key.", dyn["new_runkeys"]))
    if dyn.get("new_tasks"):
        out.append(_det("Persistence via scheduled task", "high", ["T1053.005"],
                        "Created a scheduled task.", dyn["new_tasks"]))
    if dyn.get("new_services"):
        out.append(_det("Persistence via service", "high", ["T1543.003"],
                        "Installed a new service.", dyn["new_services"]))

    files = dyn.get("new_files") or []
    dropped_exec = [f for f in files if str(f).lower().endswith(
        (".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".lnk"))]
    if dropped_exec:
        out.append(_det("Dropped executable payload", "medium", ["T1105", "T1036"],
                        "Wrote executable/script files to disk during execution.", dropped_exec))
    if len(files) >= 200:
        out.append(_det("Mass file activity", "high", ["T1486"],
                        f"Touched {len(files)} files — consistent with ransomware or a dropper.",
                        files[:8]))

    if dyn.get("network"):
        out.append(_det("Network communication", "medium", ["T1071"],
                        "Opened outbound network connections during detonation.", dyn["network"]))
    if dyn.get("dns"):
        out.append(_det("DNS resolution", "low", ["T1071.004"],
                        "Resolved domain names during detonation.", dyn["dns"]))

    def cmd_has(*needles):
        return [n for n in names if any(x in n for x in needles)]

    shadow = cmd_has("delete shadows", "shadowcopy delete", "resize shadowstorage",
                     "recoveryenabled no", "bootstatuspolicy ignoreallfailures", "wbadmin delete")
    if shadow:
        out.append(_det("Recovery inhibition", "high", ["T1490"],
                        "Deleted shadow copies / disabled recovery: a strong ransomware indicator.", shadow))
    tamper = cmd_has("disablerealtimemonitoring", "add-mppreference", "set-mppreference",
                     "disableantispyware", "netsh advfirewall set", "sc stop windefend")
    if tamper:
        out.append(_det("Security tool tampering", "high", ["T1562.001"],
                        "Tried to disable or add exclusions to Defender / the firewall.", tamper))
    disco = cmd_has("whoami", "systeminfo", "ipconfig", "net user", "net group", "nltest",
                    "net view", "tasklist", "quser")
    if disco:
        out.append(_det("System / account discovery", "low", ["T1082", "T1033", "T1016"],
                        "Ran reconnaissance commands.", disco))

    if beh.get("remote_threads"):
        out.append(_det("Remote thread injection", "high", ["T1055"],
                        "Created a thread inside another process (observed by Sysmon).",
                        [f"{r['source']} -> {r['target']}" for r in beh["remote_threads"]]))
    if beh.get("lsass_access"):
        out.append(_det("LSASS memory access", "high", ["T1003.001"],
                        "Opened lsass.exe, the usual first step of credential dumping.",
                        [f"{r['source']} (access {r['access']})" for r in beh["lsass_access"]]))
    run_writes = [r for r in beh.get("registry") or []
                  if "\\currentversion\\run" in r["key"].lower() and r["event"].lower() == "setvalue"]
    if run_writes and not dyn.get("new_runkeys"):
        out.append(_det("Persistence via Run key", "high", ["T1547.001"],
                        "Wrote an autostart Run value (Sysmon saw it even if it was later removed).",
                        [f"{r['key']} = {r['details']}" for r in run_writes]))
    raw_ip = [f"{n['image']} -> {n['dst_ip']}:{n['dst_port']}" for n in beh.get("network") or []
              if n["dst_ip"] and not n["dst_host"]]
    if raw_ip:
        out.append(_det("Connection to raw IP address", "medium", ["T1071"],
                        "Connected to an IP without a hostname (common for hard-coded C2).", raw_ip))
    if len(beh.get("file_deletes") or []) >= 50:
        out.append(_det("Mass file deletion", "high", ["T1485", "T1070.004"],
                        f"Deleted {len(beh['file_deletes'])} files.",
                        [d["path"] for d in beh["file_deletes"][:8]]))
    if dyn.get("dropped"):
        out.append(_det("Dropped files collected", "info", ["T1105"],
                        "Files written by the sample were copied out and added to the case.",
                        [f"{d['path']} ({d['sha256'][:16]}…)" for d in dyn["dropped"]]))
    implants = [m for m in dyn.get("memory") or []
                if (m.get("modified") or {}).get("replaced") or (m.get("modified") or {}).get("implanted_pe")
                or (m.get("modified") or {}).get("implanted_shc")]
    if implants:
        out.append(_det("Code implanted in memory", "high", ["T1055", "T1055.012"],
                        "hollows_hunter found injected code, a hollowed image or shellcode in the sample's processes; "
                        "the dumps were added to the case as samples.",
                        [f"{Path(m['image'].replace(chr(92), '/')).name or '?'} (pid {m['pid']}): "
                         + ", ".join(f"{k} {v}" for k, v in m["modified"].items() if v) for m in implants]))
    hooks = [m for m in dyn.get("memory") or [] if m not in implants and any((m.get("modified") or {}).values())]
    if hooks:
        out.append(_det("Patched / hooked modules in memory", "medium", ["T1574", "T1056.004"],
                        "Modules in the sample's processes were patched or had their import table hooked.",
                        [f"{Path(m['image'].replace(chr(92), '/')).name or '?'} (pid {m['pid']}): "
                         + ", ".join(f"{k} {v}" for k, v in m["modified"].items() if v) for m in hooks]))

    for h in dyn.get("sigma") or []:
        sev = {"critical": "high", "high": "high", "medium": "medium", "low": "low"}.get(h.get("level"), "info")
        desc = (h.get("description") or "Matched a SigmaHQ community rule.").strip()
        if h.get("falsepositives"):
            desc += " Known false positives: " + "; ".join(h["falsepositives"][:3]) + "."
        out.append(_det(f"Sigma: {h['title']}", sev, h.get("attck") or [], desc + " (SigmaHQ, DRL 1.1)",
                        h.get("evidence") or []))

    if dyn.get("early_finish"):
        out.append(_det("Monitor tampering suspected", "medium", ["T1562"],
                        "The report arrived before the observation window ended; the sample may have "
                        "interfered with the monitor, so treat this run's results with care.",
                        ["early report"]))
    return out


EVASION_HINTS = ("anti-vm", "anti-analysis", "anti-debugging", "sandbox", "virtual machine", "sleep", "delay execution",
                 "check if process is running under wine", "timing")


def _evasion_rule(st: dict, dyn: dict) -> list[dict]:
    """The sample's code shows anti-VM / anti-debug / long-sleep tricks, yet the detonation showed
    next to nothing: it probably noticed the sandbox and played dead. A visibility warning, not
    a safety one: try a longer run, or a dedicated dirty machine (DANGER MODE)."""
    if not dyn.get("detonated"):
        return []
    beh = dyn.get("behavior") or {}
    procs = [p for p in beh.get("processes") or [] if not p.get("launcher")] if beh else (dyn.get("new_processes") or [])
    activity = (len(procs) + len(dyn.get("new_files") or []) + len(dyn.get("new_runkeys") or [])
                + len(dyn.get("new_tasks") or []) + len(dyn.get("network") or []) + len(beh.get("registry") or [])
                + len(beh.get("network") or []))
    if activity > 2:
        return []
    caps = [c["name"] for c in ((st.get("capa") or {}).get("capabilities") or [])
            if any(h in (c.get("namespace", "") + " " + c["name"]).lower() for h in EVASION_HINTS)]
    imps = [i for i in (st.get("pe") or {}).get("suspicious_imports") or []
            if any(x in i for x in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"))]
    evidence = caps + imps
    if not evidence:
        return []
    return [_det("Sandbox evasion suspected", "medium", ["T1497", "T1622"],
                 "The code contains anti-analysis checks, but the run showed almost no behaviour. The sample may have "
                 "detected the sandbox and stayed quiet. Your PC was never at risk; the run just saw less. Try a longer "
                 "run time, or a dedicated dirty machine in DANGER MODE.", evidence)]


def evaluate(static_report: dict | None, dynamic_report: dict | None) -> dict:
    """Return {detections, attck, max_severity}. Detections are sorted most-severe first."""
    dets = []
    if static_report:
        dets += _static_rules(static_report)
    if dynamic_report:
        dets += _dynamic_rules(dynamic_report)
        dets += _evasion_rule(static_report or {}, dynamic_report)
    dets.sort(key=lambda d: SEV_ORDER.get(d["severity"], 0), reverse=True)
    attck = sorted({t for d in dets for t in d["attck"]})
    max_sev = max((d["severity"] for d in dets), key=lambda s: SEV_ORDER[s], default="info")
    return {"detections": dets, "attck": attck, "max_severity": max_sev}


def process_tree(dynamic_report: dict | None) -> list[dict]:
    """Build a parent/child forest from the detonation's processes: Sysmon's when available
    (includes short-lived processes), otherwise the end-of-run snapshot (pid/ppid)."""
    beh = (dynamic_report or {}).get("behavior") or {}
    if beh.get("processes"):
        return sysmon.process_tree(beh)
    procs = (dynamic_report or {}).get("new_processes") or []
    nodes = {p.get("pid"): {"pid": p.get("pid"), "ppid": p.get("ppid"),
                            "name": p.get("name"), "cmd": p.get("cmd"), "children": []}
             for p in procs if p.get("pid") is not None}
    roots = []
    for pid, node in nodes.items():
        parent = nodes.get(node["ppid"])
        (parent["children"] if parent else roots).append(node)
    return roots
