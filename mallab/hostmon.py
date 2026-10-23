"""BLU MODE: blue-team live host observation for incident responders, on a machine with no Windows Sandbox.

This module NEVER executes a sample. It runs the same observation the sandbox monitor does, but
against THIS computer: a before snapshot, an observation window, an after snapshot, and (if Sysmon
is installed) the Sysmon events from the window. Any execution is the analyst's own, done
deliberately and outside MalLab. The result is a behaviour report in the same shape a detonation
produces, so every existing signature, the process tree and the whole UI work unchanged.

It is meant only for a dedicated analysis machine or a host already under IR investigation, where
the responder accepts that this computer is the analysis environment. The service gates it behind
an explicit, typed confirmation; nothing here runs without that.
"""

import json
import subprocess
import time
import uuid
from pathlib import Path

from . import sysmon

_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

# Runs on the host. Observation only: snapshot, wait, snapshot, collect. It launches nothing and
# opens no sample. Mirrors the sandbox monitor's Snapshot so diffs come out identically shaped.
OBSERVE_PS1 = r'''
param([int]$Seconds = 60, [string]$OutDir, [string]$SysmonDir = "", [string]$StartIso)

$ErrorActionPreference = "SilentlyContinue"
$report = @{ started = (Get-Date).ToString("o"); host_observation = $true; detonated = $false }

function Snapshot {
    @{
        procs = (Get-CimInstance Win32_Process | ForEach-Object {
                    @{ pid = $_.ProcessId; name = $_.Name; ppid = $_.ParentProcessId; cmd = $_.CommandLine } })
        files = (Get-ChildItem -Path $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "C:\Users\Public" `
                    -Recurse -File -ErrorAction SilentlyContinue |
                    Select-Object -First 8000 -ExpandProperty FullName)
        runkeys = (@("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                     "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                     "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
                        $k = $_; (Get-Item $k).Property | ForEach-Object { "$k :: $_ = $((Get-ItemProperty $k).$_)" } })
        tasks = (Get-ScheduledTask | Select-Object -ExpandProperty TaskName)
        services = (Get-Service | Select-Object -ExpandProperty Name)
    }
}

$before = Snapshot
$start = Get-Date
$deadline = $start.AddSeconds($Seconds)
$net = @(); $timeline = @()
while ((Get-Date) -lt $deadline) {
    $eps = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
             Where-Object { $_.RemoteAddress -notin "0.0.0.0","127.0.0.1","::","::1" } |
             ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) [$($_.State)]" })
    $net += $eps
    $timeline += @{ t = [math]::Round(((Get-Date) - $start).TotalSeconds, 1); endpoints = @($eps | Select-Object -Unique) }
    Start-Sleep -Seconds 3
}
$after = Snapshot

$beforeProcs = $before.procs | ForEach-Object { $_.pid }
$report.new_processes = @($after.procs | Where-Object { $beforeProcs -notcontains $_.pid })
$report.new_files     = @(Compare-Object $before.files $after.files | Where-Object { $_.SideIndicator -eq "=>" } |
                          Select-Object -First 2000 -ExpandProperty InputObject)
$report.new_runkeys   = @(Compare-Object $before.runkeys $after.runkeys | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject })
$report.new_tasks     = @(Compare-Object $before.tasks $after.tasks | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject })
$report.new_services  = @(Compare-Object $before.services $after.services | Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject })
$report.network       = @($net | Select-Object -Unique)
$report.net_timeline  = $timeline
$report.dns           = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Entry -Unique)

if ($SysmonDir -and (Test-Path (Join-Path $SysmonDir "Sysmon64.exe"))) {
    try {
        $filter = @{ LogName = "Microsoft-Windows-Sysmon/Operational" }
        if ($StartIso) { $filter.StartTime = [DateTime]::Parse($StartIso) }
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 20000 -Oldest -ErrorAction SilentlyContinue | ForEach-Object {
            $d = @{}
            foreach ($n in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
            @{ id = $_.Id; time = $_.TimeCreated.ToString("o"); data = $d } })
        $report.sysmon = $true
        $report.sysmon_events = $events
        $report.sysmon_event_count = $events.Count
    } catch { $report.sysmon_error = $_.Exception.Message }
}

$report.finished = (Get-Date).ToString("o")
$report | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $OutDir "observation.json") -Encoding utf8
'''


def available() -> tuple[bool, str]:
    """Host observation needs only PowerShell, which is always present on Windows."""
    import sys
    if sys.platform != "win32":
        return False, "BLU MODE host observation is only available on Windows."
    return True, "Host observation is available (no sample is ever executed)."


def observe(runs_root: Path, *, seconds: int = 60, sysmon_dir: Path | None = None,
            emit=lambda e: None) -> dict:
    """Watch THIS host for `seconds`, then return a behaviour report. Executes nothing.

    The report has the same shape a detonation produces, so signatures/process-tree/UI all apply.
    It is tagged host_observation so the UI makes clear this ran on the host, not in a sandbox.
    """
    seconds = max(10, min(int(seconds), 1800))
    run_id = uuid.uuid4().hex[:10]
    base = Path(runs_root) / f"observe-{run_id}"
    base.mkdir(parents=True, exist_ok=True)
    script = base / "observe.ps1"
    script.write_text(OBSERVE_PS1, encoding="utf-8")
    out_json = base / "observation.json"
    staged_sysmon = sysmon_dir if (sysmon_dir and (Path(sysmon_dir) / "Sysmon64.exe").is_file()) else ""
    start_iso = time.strftime("%Y-%m-%dT%H:%M:%S")
    emit({"type": "lab_log", "text": f"DANGER MODE: observing this host for {seconds}s. "
                                     "No sample is executed — MalLab only records what happens."})
    args = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script),
            "-Seconds", str(seconds), "-OutDir", str(base), "-SysmonDir", str(staged_sysmon), "-StartIso", start_iso]
    try:
        subprocess.run(args, capture_output=True, text=True, timeout=seconds + 300, creationflags=_NO_WINDOW)
        if not out_json.exists():
            raise RuntimeError("the host observation produced no report")
        report = _sanitize(json.loads(out_json.read_text(encoding="utf-8-sig", errors="replace")))
    finally:
        emit({"type": "lab_log", "text": "Host observation finished."})

    report["network_mode"] = "host"
    report["new_processes"] = [p for p in report.get("new_processes") or []
                               if str(p.get("name", "")).lower() not in ("powershell.exe", "conhost.exe", "wmiprvse.exe")]
    if report.get("sysmon_events"):
        # No launcher on the host, so lineage is unknown: parse keeps everything, as before Sysmon lineage.
        report["behavior"] = sysmon.parse(report["sysmon_events"], None, None)
        report["sysmon_events"] = report["sysmon_events"][:200]
    report["verdict"] = _summarize(report)
    return report


# Host output is written by this host under our own control, but we still shape-check it so a
# malformed file can't break downstream code — the same discipline as the sandbox path.
_LIST_KEYS = ("new_processes", "new_files", "new_runkeys", "new_tasks", "new_services", "network",
              "dns", "net_timeline", "sysmon_events")


def _sanitize(report) -> dict:
    if not isinstance(report, dict):
        raise RuntimeError("host observation report is not a JSON object")
    for k in _LIST_KEYS:
        v = report.get(k)
        if v is not None and not isinstance(v, list):
            report[k] = [v]
    for k in ("new_processes", "net_timeline", "sysmon_events"):
        if k in report:
            report[k] = [x for x in report[k] if isinstance(x, dict)]
    report["detonated"] = False      # never, on the host path
    return report


def _summarize(report: dict) -> str:
    bits = []
    for key, label in (("new_processes", "new process"), ("new_files", "file changed"),
                       ("network", "network endpoint")):
        n = len(report.get(key) or [])
        if n:
            bits.append(f"{n} {label}{'s' if n != 1 else ''}")
    if report.get("new_runkeys") or report.get("new_tasks") or report.get("new_services"):
        bits.append("persistence changed")
    return "host observation: " + ("; ".join(bits) or "no change observed")
