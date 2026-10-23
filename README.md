# MalLab

A standalone malware research lab for Windows. Drop in a sample (or a password-protected
archive), get static triage, detonate it in a disposable Windows Sandbox, and check its hash
against threat-intel sources. Nothing runs on the host.

## Run it

```
pip install -r requirements.txt
MalLab.bat
```

`MalLab.bat` starts `server.py` and opens http://127.0.0.1:7860. Options:
`python server.py --port 7861 --lab-root D:\other\lab --no-browser`.

### Installer

`powershell -ExecutionPolicy Bypass -File Installer\build.ps1` builds `MalLab.exe` (YARA, the built-in
similarity matching and everything else bundled, no Python needed; TLSH too where `py-tlsh` has a
prebuilt wheel for the build's Python) and `Installer\Output\MalLab-Setup-<ver>.exe`.
The installer offers, each as a checkbox: Windows Sandbox, Sysmon, capa, FakeNet-NG, threat-group
data, the host network guard and the Defender exclusion. Tools are downloaded from their official
sources during setup (Sysmon's licence doesn't allow bundling it; capa and FakeNet arrive at their latest
GitHub release over HTTPS, checked against GitHub's SHA-256 when the release publishes one; capa's
does, FakeNet-NG's current release predates that). Any step that fails is listed in Settings with a retry button,
where every tool can also be downloaded or updated later.

The server only answers requests from this computer: other machines, DNS-rebinding hosts and
cross-site web pages are refused.

## Build the installer

```
powershell -ExecutionPolicy Bypass -File Installer\build.ps1
```

Produces `Installer\Output\MalLab-Setup-<version>.exe`, a normal Windows installer for people
without Python. MalLab then runs as a desktop app in its own window (no browser), with a
Start-menu entry and an uninstaller in Settings > Apps. Needs Python 3.11+ and Inno Setup 6
(`winget install JRSoftware.InnoSetup`). `-SkipInstaller` builds only `Installer\dist\MalLab\`.

The installer installs the WebView2 runtime if it is missing, and offers to turn on Windows
Sandbox (restart needed; not available on Windows Home), download Sysmon, add the Defender
exclusion, and save API keys. The installed app keeps lab data in `%LOCALAPPDATA%\MalLab`. The
uninstaller removes the Defender exclusion and asks before deleting lab data or API keys.

| Path | What it is |
|---|---|
| `Installer\desktop.py` | Desktop entry point (`MalLab.exe`): server in the background + native window |
| `Installer\mallab.spec` | PyInstaller build (one folder, windowed, yara-python and magic bundled) |
| `Installer\MalLab.iss` | Inno Setup installer / uninstaller, prerequisite checks |
| `Installer\build.ps1` | Builds both, in its own venv |

Bump the version in `MalLab.iss` and `version_info.txt` together.

## What's here

| Path | What it is |
|---|---|
| `server.py` | Web server: the UI plus a local-only JSON API |
| `ui/lab.html` | The whole interface (single page, no external resources) |
| `mallab/` | The engine |
| `lab/` | Your data: `mallab.db`, `quarantine/`, `reports/`, `yara/`, `tools/`, `runs/` |
| `tests/` | `python -m pytest` |

Engine modules:

- `service.py` orchestrates everything; `store.py` is the SQLite catalog.
- `static.py` hashes, file type, entropy, strings, IOCs, PE structure, Office macros, YARA, risk score.
- `sandbox.py` detonation in Windows Sandbox (hardened `.wsb`: no vGPU, clipboard, audio or printer;
  network off unless you choose it; read-only input folder; VM and run folder wiped afterward).
- `signatures.py` named detections with MITRE ATT&CK IDs and the process tree; `diffing.py` run diffs,
  sample comparison and beacon detection.
- `archives.py` unpacks `.zip` / `.7z` in memory (password `infected` by default) with size caps.
- `intel.py` hash lookups on VirusTotal, MalwareBazaar, ThreatFox, URLhaus, Hybrid Analysis and
  AlienVault OTX. Only the SHA-256 is sent; samples are never uploaded.
- `samples.py` fetching from virus.exchange (vx-underground's MWDB) or a pasted URL, with an SSRF guard.
- `defender.py` adds/removes a Microsoft Defender exclusion for `lab\quarantine` and `lab\runs` only,
  through a UAC-elevated PowerShell that you approve each time.
- `netguard.py` the host network guard: Windows Firewall rules on this PC that block the sandbox's
  virtual network from reaching it (same UAC-elevated pattern; status is read live from the firewall).
- `fakenet.py` the Simulated network mode: finds FakeNet-NG in `lab\tools`, stages it with a
  hardened config, and parses its log into requested domains, URLs and connections.
- `yara_rules.py` rule management, the starter ruleset, and draft hunting rules generated from a sample.
- `sysmon.py` turns Sysmon events into a full process tree (including short-lived processes),
  connections, DNS, registry writes, remote threads and LSASS access.
- `actors.py` threat-group tracking: import MITRE ATT&CK groups, the MISP Galaxy threat-actor list
  and Malpedia family attributions; link groups to cases/samples; suggest likely groups (leads only).
- `ioc_intel.py` free IOC enrichment for IPs/domains/URLs: OTX (often names the adversary),
  ThreatFox, URLhaus, Feodo Tracker, GreyNoise Community, Shodan InternetDB and RDAP.

## Investigation features

- **Open Sandbox** (header, or "Open in sandbox" on a sample): a hands-on Windows Sandbox with the same
  hardening (networking off, no vGPU, clipboard/audio/video/printer off). The sample, if any, is
  read-only in `Desktop\input`. At logon the VM checks it can't see the host GPU or a network route
  and powers itself off if it can.
- **Dropped payloads** are copied out of the VM after a run and added to the case as child samples.
- **PE detail**: imphash, TLSH, exports, resources (embedded PEs), TLS callbacks, overlay, .NET,
  signature presence; optional [capa](https://github.com/mandiant/capa) if `capa.exe` is in `lab\tools`.
- **Case views**: ATT&CK matrix, timeline, IOC enrichment, IOC export (CSV, STIX 2.1, defanged text).
- **Sample Investigate tab**: related samples across the lab (imphash, TLSH, shared IOCs),
  suggested threat groups with the reason for each, and a YARA rule draft.
- Analyst notes and labels on samples and groups.

## Safety model

- Samples are stored by hash as `sample.bin`, never under their real name or extension.
- They only execute inside Windows Sandbox. Enable it once (admin PowerShell, then reboot):
  `Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -Online`
- Network inside the VM is off by default. Each run verifies inside the VM that "off" really meant no
  route out.
- Network modes, safest first:
  - **Off**: no adapter route; verified at the start of every run.
  - **Simulated**: the VM gets an adapter, but [FakeNet-NG](https://github.com/mandiant/flare-fakenet-ng)
    runs inside it and diverts every connection to local fake services. DNS answers with a fake
    address and HTTP returns canned pages, so you see the domains and URLs the sample asks for. They
    go into the run report and the case IOCs, with FakeNet's log. Install FakeNet-NG from Settings >
    Analysis tools (official GitHub release), or extract a release folder into `lab\tools` by hand;
    without it the mode is refused. FakeNet starts before the baseline snapshot, and the sample
    isn't run unless its DNS listener is up. The staged config removes FakeNet's stock exemptions,
    which would otherwise send traffic out for real: blacklisted ports (TCP 139; UDP 137, 138, 443 =
    QUIC, 1900, 5355) and the process/host black- and whitelists in `[Diverter]` and in every
    listener section. Only DHCP to the host's switch is left undiverted. If FakeNet
    exits mid-run, the monitor switches the VM's adapters off and the run is flagged. At the end it
    does the same before stopping FakeNet. **Limits:** all of this happens inside the VM, where the
    sample is administrator. A sample that kills FakeNet and re-enables the adapter could reach the
    real internet. Windows offers no host-side way to block a Windows Sandbox VM's outbound traffic:
    the Hyper-V firewall only covers WSL. So this is strong protection against ordinary malware
    phoning home, not a guarantee against a sample built to escape it.
  - **Internet**: real internet, with your LAN and this PC blocked by a firewall rule **inside the
    VM** (the run is refused if the rule can't be applied). The sample runs as administrator in the
    VM and could remove that rule, so treat it as protection against accidents, not against a
    determined sample. C2 servers also see your public IP.
  - **Full**: real internet and your LAN.
- **Host network guard** (Settings, off until you turn it on). Windows Sandbox has no adapter of its
  own: a networked sandbox joins the Hyper-V "Default Switch" (a NAT network whose host side is
  `vEthernet (Default Switch)`; its subnet changes at every reboot). The guard adds four Windows
  Firewall rules **on this PC**. They block inbound TCP, UDP, ICMPv4 and ICMPv6 arriving on that
  adapter, whatever source address the VM uses. The sample can't touch them from inside the VM. To
  keep networked runs working, UDP 53 (the switch's DNS proxy) and UDP 67 (its DHCP server) stay
  open. The guard protects this PC, not your LAN or the internet: NAT traffic is forwarded, not
  delivered to this PC. While it's on, other Hyper-V VMs on the Default Switch can't reach this PC
  either. Status is checked live against the firewall (non-admin read): the guard only shows "on"
  when all four rules are active, block inbound, target the current adapter, and the firewall is on
  for every profile. Every networked run records whether the guard was on, and the run dialog and
  report warn when it was off.
  Why it matters, measured on a dev PC with the guard off: a networked sandbox could open TCP 135
  (RPC), 2179 (Hyper-V VM management), 7680 and 49667 on the host, both at the switch address and
  at the host's LAN address, and use the host's DNS. Ping was already blocked by Windows' defaults.
  What is verified: those exposures, the adapter discovery, and that every rule's parameters are
  accepted by `New-NetFirewallRule` (dry run). Not yet verified: that the applied rules close those
  ports while internet access through NAT keeps working. To check, turn the guard on and run
  `powershell -ExecutionPolicy Bypass -File tests\manual\verify-host-guard.ps1`. It starts a
  sample-less networked sandbox that probes this PC and the internet. With the guard on, both
  `host_*_tcp_open` lists should be empty, while `dns_via_host` and the internet checks still
  succeed.
- For hostile samples, prefer Off or Simulated, with the host guard on.
- Everything the VM writes back (report, screenshot, capture, dropped files) is treated as
  untrusted: shapes and sizes are checked, artifact names are assigned by the host, the shared
  output folder is capped at 2 GB, and a report that arrives too early is flagged as possible tampering.
- Quarantined files are re-hashed every time they're read; a file changed on disk is refused.
- GPU sharing is disabled with `<vGPU>Disable</vGPU>` (the exact, case-sensitive spelling; newer
  Windows Sandbox versions ignored the old `<VGpu>` spelling and shared the host GPU).
- Fail-closed: before running the sample, the monitor checks inside the VM that no host GPU is
  visible and, with networking off, that there is no route out. If either check fails, the
  sample is not executed and the run is marked "NOT EXECUTED: sandbox isolation check failed".
- Deleting a case removes its quarantined files unless another case still uses them.

## API keys

Set in Settings (kept in memory) or as environment variables to persist:
`VT_API_KEY`, `ABUSECH_API_KEY`, `HA_API_KEY`, `OTX_API_KEY`, `VX_API_KEY` (and `VX_API_URL`).

IOC enrichment and the threat-group import work without any key. A free abuse.ch key adds
ThreatFox and URLhaus. Looking up an indicator tells that service you're interested in it; samples
are never uploaded.
