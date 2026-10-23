"""Microsoft Defender exclusions for the lab's sample folders.

Real samples are written to lab/quarantine (as sample.bin) and staged under lab/runs for the
sandbox. Defender's real-time protection deletes them on sight, so analysts usually exclude
exactly those folders. This module adds/removes that exclusion — and nothing else: the paths
are fixed by the lab root, never taken from a request.

Changing exclusions needs admin rights, so the change runs in an elevated PowerShell that
Windows confirms with a UAC prompt every time. Non-admin processes can't read the exclusion
list either ("Must be an administrator to view exclusions"), so the elevated script also
verifies the result and writes it to a state file, which is what status() reports.
"""

import json
import subprocess
import sys
from pathlib import Path

from . import swr

STATE_FILE = "defender-state.json"
SCRIPT_FILE = "defender-apply.ps1"


def _ps_quote(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def lab_paths(lab_root: Path) -> list[str]:
    root = Path(lab_root).resolve()
    return [str(root / "quarantine"), str(root / "runs")]


def _run_ps(command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                          capture_output=True, text=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _realtime() -> dict:
    """Defender service / real-time status (readable without admin). Refreshed in the background
    at most once a minute, so status reads never wait on PowerShell after the first."""
    return _REALTIME.get()


def _read_realtime() -> dict:
    v = {"available": False, "realtime": None, "tamper": None}
    if sys.platform == "win32":
        try:
            r = _run_ps("Get-MpComputerStatus | Select-Object AMServiceEnabled,RealTimeProtectionEnabled,"
                        "IsTamperProtected | ConvertTo-Json", timeout=20)
            if r.returncode == 0 and r.stdout.strip():
                j = json.loads(r.stdout)
                v = {"available": bool(j.get("AMServiceEnabled")),
                     "realtime": j.get("RealTimeProtectionEnabled"), "tamper": j.get("IsTamperProtected")}
        except Exception:
            pass
    return v


_REALTIME = swr.Probe(_read_realtime, 60)


def status(lab_root: Path, tools_dir: Path) -> dict:
    st = {}
    f = Path(tools_dir) / STATE_FILE
    if f.exists():
        try:
            st = json.loads(f.read_text(encoding="utf-8-sig"))
        except ValueError:
            st = {}
    paths = lab_paths(lab_root)
    same_paths = sorted(st.get("paths") or []) == sorted(paths)
    return {**_realtime(), "paths": paths,
            "excluded": bool(st.get("excluded")) if st.get("ok") and same_paths else None,
            "verified": st.get("time") if same_paths else None,
            "last_error": st.get("error")}


def _script(paths: list[str], exclude: bool, state_path: Path) -> str:
    plist = ",".join(_ps_quote(p) for p in paths)
    action = "Add-MpPreference" if exclude else "Remove-MpPreference"
    return f"""$ErrorActionPreference = 'Stop'
$paths = @({plist})
try {{
  foreach ($p in $paths) {{
    if (-not (Test-Path -LiteralPath $p)) {{ New-Item -ItemType Directory -Force -Path $p | Out-Null }}
    {action} -ExclusionPath $p
  }}
  $ex = @((Get-MpPreference).ExclusionPath)
  $hit = @($paths | Where-Object {{ $ex -contains $_ }}).Count
  $state = [ordered]@{{ ok = $true; excluded = ($hit -eq $paths.Count); partial = ($hit -gt 0 -and $hit -lt $paths.Count) }}
}} catch {{
  $state = [ordered]@{{ ok = $false; error = $_.Exception.Message }}
}}
$state.paths = $paths
$state.time = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$state | ConvertTo-Json | Set-Content -Encoding UTF8 -LiteralPath {_ps_quote(state_path)}
"""


def set_excluded(lab_root: Path, tools_dir: Path, exclude: bool) -> dict:
    """Add or remove the exclusion via an elevated PowerShell (UAC prompt). Blocks until the
    elevated script finishes, then returns the verified status."""
    if sys.platform != "win32":
        raise RuntimeError("Defender settings are only available on Windows.")
    tools_dir = Path(tools_dir)
    tools_dir.mkdir(parents=True, exist_ok=True)
    script, state = tools_dir / SCRIPT_FILE, tools_dir / STATE_FILE
    before = state.stat().st_mtime if state.exists() else 0
    script.write_text(_script(lab_paths(lab_root), exclude, state), encoding="utf-8-sig")
    args = f'-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "{script}"'
    r = _run_ps(f"Start-Process powershell -Verb RunAs -Wait -WindowStyle Hidden -ArgumentList {_ps_quote(args)}",
                timeout=300)
    if r.returncode != 0:
        err = (r.stderr or r.stdout).strip()
        if "cancel" in err.lower():
            raise RuntimeError("The Windows permission prompt was declined, so nothing changed.")
        raise RuntimeError(f"Could not start the elevated PowerShell: {err.splitlines()[0] if err else r.returncode}")
    if not state.exists() or state.stat().st_mtime <= before:
        raise RuntimeError("The elevated script didn't report back; the setting may not have changed.")
    _REALTIME.clear()
    out = status(lab_root, tools_dir)
    if out["last_error"] and out["excluded"] is None:
        raise RuntimeError(f"Defender refused the change: {out['last_error']}")
    return out
