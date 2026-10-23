<#
  Builds MalLab for distribution:
    Installer\dist\MalLab\MalLab.exe      the app (one folder, no Python needed)
    Installer\Output\MalLab-Setup-<ver>.exe   the installer / uninstaller

  Usage (from anywhere):   powershell -ExecutionPolicy Bypass -File Installer\build.ps1
  Needs Python 3.11+ on PATH and Inno Setup 6 (winget install JRSoftware.InnoSetup).
  -SkipInstaller builds only the app folder.
#>
param([switch]$SkipInstaller)
$ErrorActionPreference = "Stop"
$here = $PSScriptRoot
$root = Split-Path $here -Parent
Set-Location $here

# 1. Isolated build environment, so only the app's own dependencies end up in the bundle.
$venv = Join-Path $here ".venv"
$py = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path $py)) {
    Write-Host "Creating build venv..."
    python -m venv $venv
    if ($LASTEXITCODE) { throw "python -m venv failed" }
}
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r (Join-Path $root "requirements.txt") pyinstaller pywebview pillow
if ($LASTEXITCODE) { throw "pip install failed" }
# Optional extras the lab uses when present. Bundle them so nothing is missing for users.
foreach ($extra in "yara-python", "python-magic-bin", "py-tlsh") {
    & $py -m pip install --quiet --only-binary=:all: $extra
    if ($LASTEXITCODE) { Write-Warning "$extra has no prebuilt wheel for this Python; the app will run without it." }
}

# 2. Icon, then the app.
& $py make_icon.py
& $py -m PyInstaller --noconfirm --clean --distpath dist --workpath build mallab.spec
if ($LASTEXITCODE) { throw "PyInstaller failed" }
Write-Host "App built: $here\dist\MalLab\MalLab.exe"

# 3. Installer.
if ($SkipInstaller) { return }
$iscc = @(
    (Get-Command iscc.exe -ErrorAction SilentlyContinue).Source,
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $iscc) {
    throw "Inno Setup 6 not found. Install it with:  winget install JRSoftware.InnoSetup   then run this script again."
}
& $iscc /Q MalLab.iss
if ($LASTEXITCODE) { throw "Inno Setup failed" }
Get-ChildItem (Join-Path $here "Output") -Filter *.exe | ForEach-Object { Write-Host "Installer built: $($_.FullName)" }
