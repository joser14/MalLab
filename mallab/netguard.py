"""Host network guard: a Windows Firewall rule on THIS PC that stops a networked sandbox from
reaching the host.

How Windows Sandbox is wired (checked on the host while a sandbox with networking ran): it gets
no adapter of its own. The VM joins the Hyper-V "Default Switch", an ICS/NAT network whose host
side is the adapter "vEthernet (Default Switch)" (e.g. 172.22.64.1/20; the VM gets a DHCP
address in that subnet with the host as gateway and DNS). The subnet is re-randomized at every
host boot, so the rules are scoped to that interface rather than to an address range. That also
covers a sample that gives itself a static/spoofed address.

The rules live in the host's firewall, outside the VM, so a sample that is administrator inside
the VM can't remove them (unlike the in-VM rule of "Internet" mode). Two holes are left on
purpose, or networked runs stop working: UDP 67 (the switch's DHCP server) and UDP 53 (its DNS
proxy). Traffic the NAT forwards to the internet is not inbound to this PC and is not affected.

Changing firewall rules needs admin rights, so — like defender.py — the change runs in an
elevated PowerShell (UAC prompt every time) that writes its verified result to a state file.
Reading rules doesn't need admin, so status() also checks the live firewall.
"""

import ipaddress
import json
import subprocess
import sys
import time
from pathlib import Path

STATE_FILE = "netguard-state.json"
SCRIPT_FILE = "netguard-apply.ps1"
GROUP = "MalLab host guard"
ADAPTER = "vEthernet (Default Switch)"
RULES = 4                       # TCP, UDP (minus DHCP/DNS), ICMPv4, ICMPv6
_cache: dict = {}

# Finds the Default Switch's host adapter. Exact name first; the description check guards against
# an unrelated adapter that merely has "Default Switch" in its name.
_FIND_ADAPTER = f"""$a = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {{ $_.Name -eq '{ADAPTER}' }})
if (-not $a) {{ $a = @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {{
    $_.Name -like '*(Default Switch)' -and $_.InterfaceDescription -like 'Hyper-V Virtual Ethernet Adapter*' }}) }}
$a = $a | Select-Object -First 1"""


def _ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _run_ps(command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                          capture_output=True, text=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


_PROBE = _FIND_ADAPTER + f"""
$o = [ordered]@{{ adapter = $null; ipv4 = $null; prefix = $null; rules = @(); profiles = @() }}
if ($a) {{
  $o.adapter = $a.Name
  $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($ip) {{ $o.ipv4 = $ip.IPAddress; $o.prefix = [int]$ip.PrefixLength }}
}}
$o.rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group {_ps_quote(GROUP)} -ErrorAction SilentlyContinue | ForEach-Object {{
  [ordered]@{{ name = $_.DisplayName; enabled = ([string]$_.Enabled -eq 'True'); action = [string]$_.Action;
              direction = [string]$_.Direction; alias = @(($_ | Get-NetFirewallInterfaceFilter).InterfaceAlias) }} }})
$o.profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue | ForEach-Object {{
  [ordered]@{{ name = [string]$_.Name; enabled = ([string]$_.Enabled -eq 'True') }} }})
$o | ConvertTo-Json -Depth 4 -Compress"""


def _probe() -> dict:
    """Live, non-admin view of the adapter and the guard rules. Cached for 30 s."""
    if _cache.get("t", 0) > time.time() - 30:
        return _cache["v"]
    v = {}
    if sys.platform == "win32":
        try:
            r = _run_ps(_PROBE, timeout=30)
            if r.returncode == 0 and r.stdout.strip():
                v = json.loads(r.stdout)
        except Exception:
            v = {}
    _cache.update(t=time.time(), v=v)
    return v


def subnet(ipv4, prefix) -> str | None:
    try:
        return str(ipaddress.ip_interface(f"{ipv4}/{int(prefix)}").network)
    except (ValueError, TypeError):
        return None


def evaluate(probe: dict, state: dict) -> dict:
    """Combine the live probe with the last elevated result. 'enabled' is True only when every
    guard rule is active, blocks inbound, targets the sandbox adapter, and the firewall is on."""
    probe = probe if isinstance(probe, dict) else {}
    as_list = lambda v: v if isinstance(v, list) else [] if v is None else [v]   # ConvertTo-Json unwraps 1-item arrays
    rules = [r for r in as_list(probe.get("rules")) if isinstance(r, dict)]
    adapter = probe.get("adapter")
    good = [r for r in rules if r.get("enabled") is True and str(r.get("action")) == "Block"
            and str(r.get("direction")) == "Inbound" and adapter and adapter in as_list(r.get("alias"))]
    profiles = [p for p in as_list(probe.get("profiles")) if isinstance(p, dict)]
    fw_off = [p.get("name") for p in profiles if not p.get("enabled")]
    problems = []
    if not adapter:
        problems.append("The sandbox's network adapter (vEthernet (Default Switch)) isn't present right now. "
                        "It appears once Hyper-V networking starts; run a networked sandbox once, then turn the guard on.")
    if rules and len(good) < RULES:
        problems.append(f"Only {len(good)} of {RULES} guard rules are active and aimed at the sandbox adapter. "
                        "Turn the guard off and on again to rebuild them.")
    if fw_off:
        problems.append("Windows Firewall is off for the " + ", ".join(map(str, fw_off)) +
                        " profile(s), so its rules aren't enforced.")
    available = sys.platform == "win32" and bool(probe)
    return {"available": available,
            "enabled": available and len(good) >= RULES and not fw_off,
            "installed": bool(rules),
            "adapter": adapter,
            "subnet": subnet(probe.get("ipv4"), probe.get("prefix")),
            "host_ip": probe.get("ipv4"),
            "rules": len(good),
            "problems": problems,
            "verified": state.get("time"),
            "last_error": state.get("error")}


def _read_state(tools_dir: Path) -> dict:
    f = Path(tools_dir) / STATE_FILE
    if f.exists():
        try:
            st = json.loads(f.read_text(encoding="utf-8-sig"))
            return st if isinstance(st, dict) else {}
        except ValueError:
            pass
    return {}


def status(tools_dir: Path) -> dict:
    return evaluate(_probe(), _read_state(tools_dir))


def _script(enable: bool, state_path: Path) -> str:
    g = _ps_quote(GROUP)
    create = f"""
    if (-not $a) {{ throw "The sandbox network adapter ('{ADAPTER}') was not found. Run a sandbox with networking once so Hyper-V creates it, then try again." }}
    $alias = $a.Name
    $common = @{{ Group = {g}; Direction = 'Inbound'; Action = 'Block'; InterfaceAlias = $alias; Profile = 'Any'; Enabled = 'True' }}
    New-NetFirewallRule @common -DisplayName 'MalLab guard: block sandbox TCP to this PC' -Protocol TCP | Out-Null
    New-NetFirewallRule @common -DisplayName 'MalLab guard: block sandbox UDP to this PC (except DHCP, DNS)' -Protocol UDP -LocalPort '1-52','54-66','68-65535' | Out-Null
    New-NetFirewallRule @common -DisplayName 'MalLab guard: block sandbox ICMPv4 to this PC' -Protocol ICMPv4 | Out-Null
    New-NetFirewallRule @common -DisplayName 'MalLab guard: block sandbox ICMPv6 to this PC' -Protocol ICMPv6 | Out-Null""" if enable else ""
    return f"""$ErrorActionPreference = 'Stop'
$alias = $null
try {{
{_FIND_ADAPTER}
    Get-NetFirewallRule -Group {g} -ErrorAction SilentlyContinue | Remove-NetFirewallRule
{create}
    $n = @(Get-NetFirewallRule -PolicyStore ActiveStore -Group {g} -ErrorAction SilentlyContinue | Where-Object {{ [string]$_.Enabled -eq 'True' }}).Count
    $state = [ordered]@{{ ok = $true; enabled = ($n -ge {RULES}); rules = $n; adapter = $alias }}
}} catch {{
    $state = [ordered]@{{ ok = $false; error = $_.Exception.Message }}
}}
$state.time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$state | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath {_ps_quote(state_path)}
"""


def set_enabled(tools_dir: Path, enable: bool) -> dict:
    """Create or remove the guard rules via an elevated PowerShell (UAC prompt). Blocks until the
    elevated script finishes, then returns the live, verified status."""
    if sys.platform != "win32":
        raise RuntimeError("The host network guard is only available on Windows.")
    tools_dir = Path(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    script, state = tools_dir / SCRIPT_FILE, tools_dir / STATE_FILE
    before = state.stat().st_mtime if state.exists() else 0
    script.write_text(_script(enable, state), encoding="utf-8-sig")
    args = f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}"'
    r = _run_ps(f"Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList {_ps_quote(args)}",
                timeout=300)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()
        if "cancel" in err.lower():
            raise RuntimeError("The Windows permission prompt was declined, so nothing changed.")
        raise RuntimeError(f"Could not start the elevated PowerShell: {err.splitlines()[0] if err else r.returncode}")
    if not state.exists() or state.stat().st_mtime <= before:
        raise RuntimeError("The elevated script didn't report back; the firewall may not have changed.")
    _cache.clear()
    st = _read_state(tools_dir)
    if not st.get("ok"):
        raise RuntimeError(f"Windows Firewall refused the change: {st.get('error') or 'unknown error'}")
    return status(tools_dir)
