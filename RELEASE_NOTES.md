## MalLab 1.2.2

A standalone malware analysis lab for Windows: static triage, detonation in a hardened, disposable
Windows Sandbox, threat intel, and reports, all in one app. No Python needed.

### Install

1. Download `MalLab-Setup-1.2.2.exe` below and run it.
2. Windows may say **"Windows protected your PC"** because the installer isn't code-signed: click
   **More info → Run anyway**.
3. Optional: compare the download's SHA-256 with `SHA256SUMS.txt`
   (`Get-FileHash .\MalLab-Setup-1.2.2.exe`).

Needs 64-bit Windows 10 (1903+) or 11. Detonation needs Windows Pro, Enterprise or Education with
virtualization enabled; on Windows Home, everything except detonation works.

### New in 1.2.2

- A one-time safety warning before the first detonation or sample opened in the sandbox: VM-escape
  risk, network modes, and never opening quarantined files on this PC. It must be ticked and
  accepted, and is remembered afterwards.
- Setup detects what's already installed (tools, threat-group data, host guard, Defender
  exclusion) and leaves it unticked, and upgrades cleanly over an older version, keeping your lab.
- Uninstalling restores Windows: every Defender exclusion and firewall rule MalLab added is removed,
  and if setup turned Windows Sandbox on, you're asked whether to turn it off again.

### Highlights

- **Verdict and 0–100 threat score** per sample, fusing static, behaviour, intel, YARA, Sigma and
  memory evidence, with the reasons and a likely family.
- **Hardened detonation**: no GPU, clipboard, audio or printer sharing; networking Off, Simulated
  (FakeNet-NG), Internet or Full; fail-closed isolation checks; host network guard.
- **Behaviour**: process tree and behaviour graph from Sysmon, SigmaHQ detections, ATT&CK mapping,
  memory scanning with hollows_hunter, dropped-file capture.
- **Static**: PE analysis, capa, YARA and YARA Forge packs, retrohunt, Office macros, archives.
- **Intel**: VirusTotal, MalwareBazaar, ThreatFox, URLhaus, Hybrid Analysis, OTX (hash only,
  samples never uploaded), free IOC enrichment and threat-group tracking.
- **Reporting**: professional HTML report, STIX 2.1 and CSV export, MISP push.
- **BLU MODE** for incident responders: host observation on a dedicated analysis machine; MalLab
  executes nothing.

Only analyse samples you're authorised to handle. See the README for the full safety model.
