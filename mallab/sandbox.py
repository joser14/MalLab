"""Detonation in Windows Sandbox: a disposable, network-isolated VM wiped after every run.

The sample never runs on the host. We stage it plus a monitor script into a read-only
mapped folder, start Windows Sandbox from a generated .wsb, and the monitor records what the
sample does (processes, files, registry, scheduled tasks, network) into a writable mapped
folder. The VM is torn down when the run ends, so nothing persists.

Requires the "Windows Sandbox" optional feature (Windows Pro/Enterprise):
    Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online
    (one admin command + reboot)
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from . import fakenet, sysmon

SANDBOX_EXE = Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"

# Runs inside the sandbox. Observation only: it records behaviour, it does not attack anything.
MONITOR_PS1 = r'''
param([string]$SampleName, [int]$Timeout = 60, [switch]$Detonate, [switch]$SafeNet, [switch]$ExpectNoNetwork, [switch]$FakeNet)

$ErrorActionPreference = "SilentlyContinue"
$desk   = "C:\Users\WDAGUtilityAccount\Desktop"
$inDir  = Join-Path $desk "input"
$outDir = Join-Path $desk "output"
$sample = Join-Path $inDir $SampleName
$report = @{ started = (Get-Date).ToString("o"); sample = $SampleName; detonated = $false }

$report.monitor_pid = $PID

# Containment: when networking is on, keep the sample off the local network and the host so it
# can only reach the public internet (for C2 observation), never pivot to your LAN or this PC.
# The VM's default DNS server is the host's NAT gateway (a private address the rule blocks), so
# point DNS at public resolvers first or nothing would resolve in "Internet" mode.
# NOTE: this is in-VM containment. The sample runs as an administrator inside the VM and can
# remove the rule; it is a guard against accidents, not against a determined sample.
if ($SafeNet) {
    try {
        Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' |
            Set-DnsClientServerAddress -ServerAddresses "1.1.1.1","9.9.9.9" -ErrorAction Stop
        New-NetFirewallRule -DisplayName "mallab-block-private" -Direction Outbound -Action Block `
            -RemoteAddress "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","169.254.0.0/16","100.64.0.0/10","fc00::/7","fe80::/10" `
            -ErrorAction Stop | Out-Null
        if (-not (Get-NetFirewallRule -DisplayName "mallab-block-private" -ErrorAction SilentlyContinue)) {
            throw "firewall rule was not created"
        }
        $report.safe_net = $true
    } catch { $report.safe_net_error = $_.Exception.Message }
}

function Snapshot {
    @{
        procs = (Get-CimInstance Win32_Process | ForEach-Object {
                    @{ pid = $_.ProcessId; name = $_.Name; ppid = $_.ParentProcessId; cmd = $_.CommandLine } })
        files = (Get-ChildItem -Path $env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, "C:\Users\Public" `
                    -Recurse -File -ErrorAction SilentlyContinue |
                    Select-Object -First 4000 -ExpandProperty FullName)
        runkeys = (@("HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
                     "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
                     "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
                        $k = $_; (Get-Item $k).Property | ForEach-Object { "$k :: $_ = $((Get-ItemProperty $k).$_)" } })
        tasks = (Get-ScheduledTask | Select-Object -ExpandProperty TaskName)
        services = (Get-Service | Select-Object -ExpandProperty Name)   # installed, not just running
    }
}

# Isolation checks, run BEFORE the baseline snapshot so the services/processes these queries
# start (NetSetupSvc, WmiPrvSE) aren't mistaken for sample activity.
# Network: lets the host verify "networking off" was honored.
$report.net_adapters_up = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' |
                            Select-Object -ExpandProperty Name)
$report.has_default_route = [bool](Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue)
# GPU: with <vGPU>Disable</vGPU> the VM should only see a basic/remote display adapter, not the
# host's real GPU (GPU sharing is a VM-escape surface).
$report.display_adapters = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue |
                             Select-Object -ExpandProperty Name)

# Simulated network: FakeNet-NG diverts every connection to local fake services (DNS answers
# with a fake address, HTTP returns canned pages), so the sample's C2 traffic is recorded and
# never leaves the VM. It starts BEFORE the baseline snapshot and must be listening before the
# sample runs. Copied out of the read-only input folder because it writes files beside itself.
$fn = $null
if ($FakeNet) {
    try {
        $fnDir = "C:\mallab-fakenet"
        Copy-Item -LiteralPath (Join-Path $inDir "tools\fakenet") -Destination $fnDir -Recurse -Force -ErrorAction Stop
        $fn = Start-Process -FilePath (Join-Path $fnDir "fakenet.exe") -WorkingDirectory $fnDir -WindowStyle Hidden -PassThru `
                -ArgumentList "-p", "-c", (Join-Path $fnDir "configs\mallab.ini"), "-l", (Join-Path $outDir "fakenet.log") -ErrorAction Stop
        $report.fakenet_pid = $fn.Id
        $up = $false
        for ($i = 0; $i -lt 45 -and -not $fn.HasExited; $i++) {
            if (Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue) { $up = $true; break }
            Start-Sleep -Seconds 1
        }
        if ($up -and -not $fn.HasExited) { Start-Sleep -Seconds 3; $report.fakenet = $true }
        elseif ($fn.HasExited) { $report.fakenet_error = "FakeNet-NG exited during startup (exit code $($fn.ExitCode))" }
        else { $report.fakenet_error = "FakeNet-NG did not open its DNS listener within 45 s" }
    } catch { $report.fakenet_error = $_.Exception.Message }
}

# Fail closed: if the VM isn't isolated the way the host asked, never run the sample.
$problems = @()
$realGpu = @($report.display_adapters | Where-Object { $_ -notmatch 'Basic Display|Basic Render|Remote Display|Hyper-V Video' })
if ($realGpu.Count -gt 0) { $problems += "host GPU visible in the VM: " + ($realGpu -join ", ") }
if ($ExpectNoNetwork -and $report.has_default_route) { $problems += "network route present although networking is off" }
if ($SafeNet -and -not $report.safe_net) { $problems += "LAN/host block could not be applied: $($report.safe_net_error)" }
if ($FakeNet -and -not $report.fakenet) { $problems += "simulated network (FakeNet-NG) did not start: $($report.fakenet_error)" }
if ($problems.Count -gt 0) {
    $report.isolation_failed = $problems; $Detonate = $false
    # Without FakeNet the adapter would be a real way out; take it down before anything else runs.
    if ($FakeNet) { Get-NetAdapter -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue }
}

# Our own tooling starts BEFORE the baseline snapshot, so the Sysmon service and driver it
# installs are never reported as the sample's persistence.
# Optional Sysmon (far richer process/network/registry events) if its binary was staged in input\tools.
$sysmon = Join-Path $inDir "tools\Sysmon64.exe"
$sysmonCfg = Join-Path $inDir "tools\sysmon-config.xml"
if (Test-Path $sysmon) {
    try {
        if (Test-Path $sysmonCfg) { & $sysmon -accepteula -i $sysmonCfg | Out-Null }
        else { & $sysmon -accepteula -i | Out-Null }
        $report.sysmon = $true
    } catch { $report.sysmon_error = $_.Exception.Message }
}

# Full packet capture with the built-in pktmon (no extra tooling needed).
try {
    pktmon start --capture --pkt-size 0 --file-name (Join-Path $outDir "capture.etl") | Out-Null
    $report.pcap_started = $true
} catch { $report.pcap_error = $_.Exception.Message }
Start-Sleep -Seconds 2

$before = Snapshot
$detTime = Get-Date
$report.detonate_time = $detTime.ToString("o")

if ($Detonate -and (Test-Path $sample)) {
    try {
        $ext = [IO.Path]::GetExtension($SampleName).ToLower()
        if ($ext -in ".exe", ".com", ".scr") {
            $p = Start-Process -FilePath $sample -PassThru -ErrorAction Stop
        } elseif ($ext -eq ".dll") {
            $p = Start-Process -FilePath "rundll32.exe" -ArgumentList "`"$sample`",DllMain" -PassThru -ErrorAction Stop
        } elseif ($ext -in ".ps1") {
            $p = Start-Process -FilePath "powershell.exe" -ArgumentList "-ExecutionPolicy","Bypass","-File",$sample -PassThru -ErrorAction Stop
        } elseif ($ext -in ".js", ".vbs", ".wsf") {
            $p = Start-Process -FilePath "wscript.exe" -ArgumentList $sample -PassThru -ErrorAction Stop
        } elseif ($ext -in ".bat", ".cmd") {
            $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c",$sample -PassThru -ErrorAction Stop
        } else {
            $p = Start-Process -FilePath $sample -PassThru -ErrorAction Stop   # let the shell pick a handler
        }
        # The interpreter WE start (rundll32/powershell/wscript/cmd) is the launcher, not sample
        # behaviour; the host uses this PID to keep it out of the LOLBin detections.
        if ($p) { $report.launcher_pid = $p.Id; $report.launcher_name = $p.ProcessName }
        $report.detonated = $true
    } catch {
        $report.launch_error = $_.Exception.Message
    }
}

$deadline = (Get-Date).AddSeconds($Timeout)
$start = Get-Date
$net = @()
$timeline = @()
while ((Get-Date) -lt $deadline) {
    $eps = @(Get-NetTCPConnection -ErrorAction SilentlyContinue |
             Where-Object { $_.RemoteAddress -notin "0.0.0.0","127.0.0.1","::","::1" } |
             ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort) [$($_.State)]" })
    $net += $eps
    $timeline += @{ t = [math]::Round(((Get-Date) - $start).TotalSeconds, 1); endpoints = @($eps | Select-Object -Unique) }
    # If FakeNet dies (or the sample kills it), traffic would reach the real internet: cut the
    # adapters at once. The sample is admin and could re-enable them; the host reports this.
    if ($fn -and $report.fakenet -and $fn.HasExited -and -not $report.fakenet_died) {
        $report.fakenet_died = [math]::Round(((Get-Date) - $start).TotalSeconds, 1)
        Get-NetAdapter -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
        $report.adapters_disabled = $true
    }
    Start-Sleep -Seconds 3
}
$report.net_timeline = $timeline
# The sample is still running: take the adapters down first, then stop FakeNet, so nothing
# slips out while the monitor collects results.
if ($fn) {
    $report.fakenet_alive_at_end = -not $fn.HasExited
    Get-NetAdapter -ErrorAction SilentlyContinue | Disable-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue
    if (-not $fn.HasExited) { Stop-Process -Id $fn.Id -Force -ErrorAction SilentlyContinue }
}

$after = Snapshot
$beforeProcs = $before.procs | ForEach-Object { $_.pid }
$report.new_processes   = @($after.procs | Where-Object { $beforeProcs -notcontains $_.pid })
$report.new_files       = @(Compare-Object $before.files $after.files |
                            Where-Object { $_.SideIndicator -eq "=>" } |
                            Select-Object -First 1000 -ExpandProperty InputObject)
$report.new_runkeys     = @(Compare-Object $before.runkeys $after.runkeys |
                            Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject })
$report.new_tasks       = @(Compare-Object $before.tasks $after.tasks |
                            Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject })
$report.new_services    = @(Compare-Object $before.services $after.services |
                            Where-Object { $_.SideIndicator -eq "=>" } | ForEach-Object { $_.InputObject })
$report.network         = @($net | Select-Object -Unique)
$report.dns             = @(Get-DnsClientCache -ErrorAction SilentlyContinue |
                            Select-Object -ExpandProperty Entry -Unique)

# Bring back what the sample wrote (executables/scripts first) so the host can triage each as a
# child sample. Capped by count and size; the host re-hashes and re-validates everything.
$dropDir = Join-Path $outDir "dropped"
$dropped = @(); $dropTotal = 0
$ordered = @($report.new_files | Sort-Object { if ($_ -match '\.(exe|dll|scr|sys|ps1|vbs|js|jse|wsf|bat|cmd|hta|lnk|jar|msi)$') { 0 } else { 1 } })
foreach ($f in $ordered) {
    if ($dropped.Count -ge 25) { break }
    if ($f -match '\\(D3DSCache|DXCache|DxCache|ShaderCache|Caches|ModuleAnalysisCache|thumbcache|iconcache)') { continue }
    $item = Get-Item -LiteralPath $f -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer -or $item.Length -eq 0 -or $item.Length -gt 20MB -or ($dropTotal + $item.Length) -gt 100MB) { continue }
    if (-not (Test-Path $dropDir)) { New-Item -ItemType Directory -Path $dropDir | Out-Null }
    $idx = $dropped.Count
    try {
        Copy-Item -LiteralPath $f -Destination (Join-Path $dropDir ("{0:D3}.bin" -f $idx)) -ErrorAction Stop
        $dropped += @{ index = $idx; path = $f; size = $item.Length }
        $dropTotal += $item.Length
    } catch {}
}
$report.dropped = $dropped
# Stop packet capture and convert the ETL to pcapng for Wireshark.
if ($report.pcap_started) {
    try {
        pktmon stop | Out-Null
        pktmon etl2pcap (Join-Path $outDir "capture.etl") -o (Join-Path $outDir "capture.pcapng") | Out-Null
        if (Test-Path (Join-Path $outDir "capture.pcapng")) { $report.pcap = "capture.pcapng" }
        Remove-Item (Join-Path $outDir "capture.etl") -ErrorAction SilentlyContinue
    } catch { $report.pcap_error = $_.Exception.Message }
}

# Collect Sysmon events from detonation onward as structured fields (Image, CommandLine,
# DestinationIp, TargetObject, …) so the host can build a full process tree, including
# processes that exited before the end-of-run snapshot.
if ($report.sysmon) {
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = "Microsoft-Windows-Sysmon/Operational"; StartTime = $detTime } `
                        -MaxEvents 3000 -Oldest -ErrorAction SilentlyContinue | ForEach-Object {
            $d = @{}
            foreach ($n in ([xml]$_.ToXml()).Event.EventData.Data) { $d[$n.Name] = [string]$n.'#text' }
            @{ id = $_.Id; time = $_.TimeCreated.ToString("o"); data = $d } })
        $report.sysmon_events = $events
        $report.sysmon_event_count = $events.Count
    } catch { $report.sysmon_error = $_.Exception.Message }
}

$report.finished = (Get-Date).ToString("o")

# Desktop screenshot — captures ransom notes, popups, injected windows, etc.
try {
    Add-Type -AssemblyName System.Windows.Forms, System.Drawing
    $b = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $b.Size)
    $bmp.Save((Join-Path $outDir "screenshot.png"), [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    $report.screenshot = "screenshot.png"
} catch { $report.screenshot_error = $_.Exception.Message }

$report | ConvertTo-Json -Depth 6 | Out-File -FilePath (Join-Path $outDir "report.json") -Encoding utf8
"done" | Out-File -FilePath (Join-Path $outDir "done.flag") -Encoding ascii
'''

# Hardened Windows Sandbox config. Windows Sandbox is a Hyper-V-isolated, disposable VM; on top
# of that we close every optional host<->guest channel so a sample has nothing to pivot through:
#   - vGPU off: removes the GPU-driver escape surface (a known class of VM escapes)
#   - networking off by default: no exfiltration / C2 / lateral movement unless explicitly enabled
#   - clipboard / audio / video / printer redirection off: no data path back to the host
#   - ProtectedClient on: the connection to the VM runs with extra hardening
#   - the only shared paths are one READ-ONLY input folder and one output folder; the host never
#     executes anything the VM writes, and the whole run folder is deleted afterward.
WSB_TEMPLATE = """<Configuration>
  <vGPU>Disable</vGPU>
  <Networking>{networking}</Networking>
  <MemoryInMB>{memory}</MemoryInMB>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder><HostFolder>{in_dir}</HostFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>{out_dir}</HostFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\\Users\\WDAGUtilityAccount\\Desktop\\input\\monitor.ps1" -SampleName "{sample_name}" -Timeout {timeout} {detonate} {safenet} {nonet} {fakenet}</Command>
  </LogonCommand>
</Configuration>
"""


# Files every fresh sandbox writes on its own (shader/thumbnail/module caches): not sample activity.
NOISE_FILES = re.compile(r"\\(D3DSCache|NVIDIA\\DXCache|AMD\\DxCache|Intel\\ShaderCache"
                         r"|Microsoft\\Windows\\Caches|PowerShell\\ModuleAnalysisCache"
                         r"|Microsoft\\Windows\\Explorer\\(thumbcache|iconcache))", re.I)
BASIC_DISPLAY = re.compile(r"Basic Display|Basic Render|Remote Display|Hyper-V Video", re.I)


def available() -> tuple[bool, str]:
    if SANDBOX_EXE.exists():
        return True, "Windows Sandbox is installed."
    return False, ("Windows Sandbox is not enabled. In an elevated PowerShell run:\n"
                   '  Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online\n'
                   "then reboot. (Requires Windows Pro/Enterprise and virtualization enabled in BIOS.)")


_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # no console flash from the windowed app


_SANDBOX_PROCS = ("WindowsSandboxClient.exe", "WindowsSandbox.exe", "WindowsSandboxRemoteSession.exe")


def _kill_sandbox():
    for name in _SANDBOX_PROCS:
        subprocess.run(["taskkill", "/F", "/IM", name], capture_output=True, creationflags=_NO_WINDOW)


def sandbox_running() -> bool:
    out = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True,
                         creationflags=_NO_WINDOW).stdout.lower()
    return any(f'"{n.lower()}"' in out for n in _SANDBOX_PROCS if n != "WindowsSandbox.exe")


# Interactive session: the same hardened settings as a detonation, networking always off. The
# logon script repeats the fail-closed checks; if the VM can see the host GPU or has a route out,
# it warns and powers itself off before you can run anything.
INTERACTIVE_WSB = """<Configuration>
  <vGPU>Disable</vGPU>
  <Networking>Disable</Networking>
  <MemoryInMB>{memory}</MemoryInMB>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder><HostFolder>{in_dir}</HostFolder><ReadOnly>true</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\\Users\\WDAGUtilityAccount\\Desktop\\input\\check.ps1"</Command>
  </LogonCommand>
</Configuration>
"""

INTERACTIVE_CHECK_PS1 = r'''
$problems = @()
$gpu = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name |
         Where-Object { $_ -notmatch 'Basic Display|Basic Render|Remote Display|Hyper-V Video' })
if ($gpu.Count -gt 0) { $problems += "host GPU visible in the VM: " + ($gpu -join ", ") }
if (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue) { $problems += "network route present although networking is off" }
Add-Type -AssemblyName PresentationFramework
if ($problems.Count -gt 0) {
    [System.Windows.MessageBox]::Show("MalLab isolation check FAILED. This sandbox will shut down.`n`n" + ($problems -join "`n"), "MalLab") | Out-Null
    Stop-Computer -Force
} else {
    $note = "MalLab isolation check passed at $(Get-Date).`r`n`r`n" +
            "- No host GPU visible, no network route.`r`n" +
            "- Clipboard, audio, video and printer are disconnected from your PC.`r`n" +
            "- Files in the 'input' folder are read-only copies.`r`n" +
            "- Everything in this sandbox is wiped when you close the window."
    Set-Content -Path (Join-Path ([Environment]::GetFolderPath('Desktop')) "MALLAB-ISOLATED.txt") -Value $note
}
'''


def open_interactive(runs_root: Path, sample: tuple[bytes, str] | None = None,
                     memory_mb: int = 4096) -> dict:
    """Start a hardened Windows Sandbox for hands-on work, optionally with one sample staged
    read-only in Desktop\\input. Returns immediately; the staging folder is wiped once the
    sandbox window is closed."""
    ok, msg = available()
    if not ok:
        raise RuntimeError(msg)
    if sandbox_running():
        raise RuntimeError("A Windows Sandbox is already running (only one is allowed at a time).")
    base = Path(runs_root) / f"interactive-{uuid.uuid4().hex[:10]}"
    in_dir = base / "input"
    in_dir.mkdir(parents=True, exist_ok=True)
    staged = None
    if sample:
        data, original_name = sample
        ext = Path(original_name).suffix.lower()
        if not re.fullmatch(r"\.[a-z0-9]{1,8}", ext):
            ext = ".bin"
        staged = "sample" + ext
        (in_dir / staged).write_bytes(data)
    (in_dir / "check.ps1").write_text(INTERACTIVE_CHECK_PS1, encoding="utf-8")
    wsb = base / "interactive.wsb"
    wsb.write_text(INTERACTIVE_WSB.format(memory=max(1024, min(int(memory_mb), 16384)),
                                          in_dir=xml_escape(str(in_dir))), encoding="utf-8")
    subprocess.Popen([str(SANDBOX_EXE), str(wsb)])

    def cleanup():
        deadline = time.time() + 180          # wait for the VM to come up...
        while time.time() < deadline and not sandbox_running():
            time.sleep(3)
        while sandbox_running():              # ...then until its window is closed
            time.sleep(5)
        time.sleep(2)
        shutil.rmtree(base, ignore_errors=True)
    threading.Thread(target=cleanup, daemon=True).start()
    return {"ok": True, "staged": staged}


def detonate(sample_bytes: bytes, original_name: str, runs_root: Path, *,
             timeout: int = 60, networking: bool = False, memory_mb: int = 4096,
             do_detonate: bool = True, emit=lambda e: None, artifact_dir: Path | None = None,
             tools_dir: Path | None = None, safe_net: bool = True, simulate: bool = False,
             host_guard: bool | None = None) -> dict:
    """Run one sample in Windows Sandbox and return the behaviour report.

    networking defaults OFF. Enable it only deliberately, to observe C2 traffic, and
    understand the sample may then reach real infrastructure.
    simulate=True ("Simulated" mode) gives the VM an adapter but runs FakeNet-NG inside it, so
    connections get fake answers instead of reaching the internet. It needs FakeNet-NG in
    tools_dir and is refused otherwise.
    """
    fakenet_dir = None
    if simulate:
        fakenet_dir = fakenet.find(tools_dir)
        if not fakenet_dir:
            raise RuntimeError(fakenet.missing_message(tools_dir))
        networking, safe_net = True, False   # FakeNet replaces the in-VM firewall rule
    ok, msg = available()
    if not ok:
        raise RuntimeError(msg)
    if sandbox_running():
        raise RuntimeError("A Windows Sandbox is already running (only one is allowed at a time).")

    run_id = uuid.uuid4().hex[:10]
    base = Path(runs_root) / run_id
    in_dir, out_dir = base / "input", base / "output"
    in_dir.mkdir(parents=True, exist_ok=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Use a fixed base name plus a strictly-validated extension (so the right handler fires
    # inside the VM) instead of the attacker-controlled original name. This removes any chance
    # of the filename breaking out of the .wsb XML / PowerShell command line.
    ext = Path(original_name).suffix.lower()
    if not re.fullmatch(r"\.[a-z0-9]{1,8}", ext):
        ext = ".bin"
    safe_name = "sample" + ext
    (in_dir / safe_name).write_bytes(sample_bytes)
    (in_dir / "monitor.ps1").write_text(MONITOR_PS1, encoding="utf-8")

    # Stage optional tooling (Sysmon) so the monitor can install it inside the VM.
    if tools_dir and Path(tools_dir).exists():
        staged = in_dir / "tools"
        staged.mkdir(exist_ok=True)
        for name in ("Sysmon64.exe", "sysmon-config.xml"):
            src = Path(tools_dir) / name
            if src.exists():
                shutil.copy2(src, staged / name)
    if fakenet_dir:
        try:
            fakenet.stage(fakenet_dir, in_dir / "tools" / "fakenet")
        except Exception:
            shutil.rmtree(base, ignore_errors=True)
            raise

    wsb = base / "run.wsb"
    wsb.write_text(WSB_TEMPLATE.format(
        networking="Enable" if networking else "Disable",
        memory=max(1024, min(int(memory_mb), 16384)),
        in_dir=xml_escape(str(in_dir)), out_dir=xml_escape(str(out_dir)),
        sample_name=safe_name, timeout=max(5, min(int(timeout), 600)),
        detonate="-Detonate" if do_detonate else "",
        safenet="-SafeNet" if (networking and safe_net) else "",
        nonet="" if networking else "-ExpectNoNetwork",
        fakenet="-FakeNet" if simulate else ""), encoding="utf-8")
    mode = "off" if not networking else "simulated" if simulate else "internet" if safe_net else "full"

    done = out_dir / "done.flag"
    report_file = out_dir / "report.json"
    hard_deadline = time.time() + timeout + 180  # VM boot + work + margin
    try:  # from here on, always tear down the VM and wipe the staged sample
        emit({"type": "lab_log", "text": f"Launching Windows Sandbox (network "
                                         f"{mode.upper()}, detonate "
                                         f"{'yes' if do_detonate else 'no'}, {timeout}s)…"})
        subprocess.Popen([str(SANDBOX_EXE), str(wsb)])
        launched = time.time()
        polls = 0
        while time.time() < hard_deadline:
            if done.exists() and report_file.exists():
                break
            polls += 1
            # The output folder is writable from inside the VM: don't let a sample fill the host disk.
            if polls % 5 == 0 and _dir_size(out_dir) > MAX_OUTPUT_BYTES:
                raise RuntimeError(f"Sandbox output passed {MAX_OUTPUT_BYTES // 2**30} GB; run aborted "
                                   "(the sample may be flooding the shared output folder).")
            time.sleep(2)
        else:
            raise RuntimeError("Detonation timed out waiting for the sandbox report.")
        elapsed = time.time() - launched
        time.sleep(1)  # let the file finish flushing
        # Everything in out_dir was writable by the sample: treat it as untrusted input.
        if report_file.stat().st_size > MAX_REPORT_BYTES:
            raise RuntimeError("Sandbox report is implausibly large; refusing to parse it.")
        # Windows PowerShell's `Out-File -Encoding utf8` writes a BOM; utf-8-sig accepts both.
        report = _sanitize(json.loads(report_file.read_text(encoding="utf-8-sig", errors="replace")))
        # done.flag can't legitimately appear before boot + the full observation window.
        if do_detonate and report.get("detonated") and elapsed < timeout:
            report["early_finish"] = True
        report["_dropped_blobs"] = _collect_dropped(report, out_dir)
        if simulate:
            report["fakenet_log"] = fakenet.read_log(out_dir / "fakenet.log")
        # Preserve artifacts (screenshot, capture) before the ephemeral run folder is wiped.
        if artifact_dir:
            Path(artifact_dir).mkdir(parents=True, exist_ok=True)
            if (out_dir / "screenshot.png").exists():
                shutil.copy2(out_dir / "screenshot.png", Path(artifact_dir) / f"screenshot-{run_id}.png")
                report["screenshot"] = f"screenshot-{run_id}.png"
            if (out_dir / "capture.pcapng").exists():
                shutil.copy2(out_dir / "capture.pcapng", Path(artifact_dir) / f"capture-{run_id}.pcapng")
                report["pcap"] = f"capture-{run_id}.pcapng"
    finally:
        emit({"type": "lab_log", "text": "Tearing down the sandbox VM…"})
        _kill_sandbox()
        time.sleep(2)
        shutil.rmtree(base, ignore_errors=True)

    report["network_mode"] = mode
    if networking:
        report["host_guard"] = host_guard
    if simulate:
        sim = report.pop("fakenet_log", None) or {}
        report["fakenet"] = {"started": report.get("fakenet") is True,
                             "error": str(report.get("fakenet_error") or "")[:500] or None,
                             "died_at": report.get("fakenet_died") if isinstance(report.get("fakenet_died"), (int, float)) else None,
                             "domains": sim.get("domains", []), "urls": sim.get("urls", []),
                             "connections": sim.get("connections", []),
                             "log": sim.get("log", ""), "log_truncated": bool(sim.get("log_truncated"))}
        report.pop("fakenet_error", None)
        report.pop("fakenet_died", None)
        # Names the sample looked up through FakeNet are its real IOCs (the answers were fake).
        report["dns"] = list(dict.fromkeys([*(report.get("dns") or []), *report["fakenet"]["domains"]]))
    # The monitor's own WMI queries spin up WmiPrvSE; its *children* stay (WMI-launched payloads).
    procs = report.get("new_processes") or []
    report["new_processes"] = [p for p in procs if str(p.get("name", "")).lower() != "wmiprvse.exe"]
    files = list(dict.fromkeys(report.get("new_files") or []))   # dedupe, keep order
    report["new_files"] = [f for f in files if not NOISE_FILES.search(f)]
    report["noise_files"] = [f for f in files if NOISE_FILES.search(f)]
    adapters = report.get("display_adapters") or []
    report["vgpu_isolated"] = (all(BASIC_DISPLAY.search(a) for a in adapters) if adapters else None)
    if not networking and "has_default_route" in report:
        report["network_isolated"] = not report["has_default_route"]
    if report.get("sysmon_events"):
        report["behavior"] = sysmon.parse(report["sysmon_events"], report.get("monitor_pid"),
                                          report.get("launcher_pid"))
    report["verdict"] = _summarize(report)
    return report


MAX_OUTPUT_BYTES = 2 * 2**30          # whole shared output folder
MAX_REPORT_BYTES = 64 * 2**20         # report.json
MAX_DROPPED = 25
MAX_DROPPED_BYTES = 20 * 2**20        # per file (the monitor uses the same caps)
MAX_DROPPED_TOTAL = 100 * 2**20

# Report fields that must be lists; ConvertTo-Json flattens one-element arrays and a sample can
# rewrite report.json, so shapes are enforced before anything downstream reads them.
_LIST_KEYS = ("new_processes", "new_files", "new_runkeys", "new_tasks", "new_services", "network",
              "dns", "net_timeline", "sysmon_events", "display_adapters", "net_adapters_up",
              "isolation_failed", "dropped")
_STR_LIST_KEYS = ("new_files", "new_runkeys", "new_tasks", "new_services", "network", "dns",
                  "display_adapters", "net_adapters_up", "isolation_failed")


def _dir_size(path: Path) -> int:
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                pass
    return total


def _sanitize(report) -> dict:
    """Normalize a report that came back from inside the VM (and so may be forged)."""
    if not isinstance(report, dict):
        raise RuntimeError("sandbox report is not a JSON object")
    for k in _LIST_KEYS:
        v = report.get(k)
        if v is not None and not isinstance(v, list):
            report[k] = [v]
    for k in ("new_processes", "net_timeline", "sysmon_events", "dropped"):
        if k in report:
            report[k] = [x for x in report[k] if isinstance(x, dict)]
    for k in _STR_LIST_KEYS:
        if k in report:
            report[k] = [str(x)[:2000] for x in report[k] if x is not None]
    # Artifact names are set by the host only, from files it copied itself. A VM-supplied
    # "screenshot": "..\\..\\secret" would otherwise be served from the host's disk.
    report.pop("screenshot", None)
    report.pop("pcap", None)
    report.pop("_dropped_blobs", None)
    # Set by the host only: the parsed FakeNet log and whether the host guard was on.
    report.pop("fakenet_log", None)
    report.pop("host_guard", None)
    if not isinstance(report.get("fakenet"), bool):
        report.pop("fakenet", None)
    return report


def _collect_dropped(report: dict, out_dir: Path) -> list[tuple[str, bytes]]:
    """Read back the files the monitor copied out, by index only, re-checking every cap."""
    blobs, total, meta = [], 0, []
    for d in report.get("dropped") or []:
        idx = d.get("index")
        if not isinstance(idx, int) or not 0 <= idx < MAX_DROPPED or len(blobs) >= MAX_DROPPED:
            continue
        p = out_dir / "dropped" / f"{idx:03d}.bin"
        try:
            if p.is_symlink() or not p.is_file():
                continue
            size = p.stat().st_size
            if not 0 < size <= MAX_DROPPED_BYTES or total + size > MAX_DROPPED_TOTAL:
                continue
            data = p.read_bytes()[:MAX_DROPPED_BYTES]
        except OSError:
            continue
        total += len(data)
        path = str(d.get("path") or f"dropped-{idx}")[:500]
        blobs.append((path, data))
        meta.append({"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    report["dropped"] = meta
    return blobs


def _summarize(report: dict) -> str:
    if report.get("isolation_failed"):
        return "NOT EXECUTED: sandbox isolation check failed (" + "; ".join(report["isolation_failed"]) + ")"
    bits = []
    if report.get("early_finish"):
        bits.append("WARNING: report arrived before the observation window ended (possible tampering)")
    fn = report.get("fakenet") if isinstance(report.get("fakenet"), dict) else None
    if fn and fn.get("died_at") is not None:
        bits.append(f"WARNING: FakeNet-NG stopped {fn['died_at']}s into the run; the VM's adapters were "
                    "switched off, but traffic after that point may have reached the internet")
    if report.get("host_guard") is False:
        bits.append("host network guard was off")
    if fn and (fn.get("domains") or fn.get("urls")):
        bits.append(f"{len(fn.get('domains') or [])} domain(s) and {len(fn.get('urls') or [])} URL(s) "
                    "requested on the simulated network")
    if report.get("new_processes"):
        n = len(report["new_processes"])
        bits.append(f"{n} new process{'es' if n != 1 else ''}")
    if report.get("new_files"):
        n = len(report["new_files"])
        bits.append(f"{n} file{'s' if n != 1 else ''} dropped")
    if report.get("new_runkeys") or report.get("new_tasks") or report.get("new_services"):
        bits.append("persistence created")
    if report.get("network"):
        bits.append(f"{len(report['network'])} network endpoint(s)")
    if report.get("dropped"):
        bits.append(f"{len(report['dropped'])} dropped file(s) collected")
    if report.get("launch_error"):
        bits.append(f"launch error: {report['launch_error']}")
    if not report.get("detonated"):
        bits.append("not executed (inspection only)")
    return "; ".join(bits) or "no observable activity"
