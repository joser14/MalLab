# PyInstaller spec for MalLab.exe (one-folder, windowed). Run through build.ps1, which sets up
# the build venv first:  pyinstaller --noconfirm --distpath dist --workpath build mallab.spec
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

HERE = Path(SPECPATH)
ROOT = HERE.parent

# yaml is imported inside functions in mallab.sigma (Sigma rule parsing); name it explicitly so
# PyInstaller's analysis can never miss it.
hidden = collect_submodules("uvicorn") + collect_submodules("mallab") + ["server", "yaml"]
datas = [(str(ROOT / "ui" / "lab.html"), "ui"), (str(ROOT / "ui" / "fonts"), "ui/fonts")]
datas += collect_data_files("oletools")
for optional in ("magic", "yara", "tlsh"):   # bundled when build.ps1 could install them
    try:
        __import__(optional)
        hidden.append(optional)
        datas += collect_data_files(optional)
    except ImportError:
        pass

a = Analysis(
    [str(HERE / "desktop.py")],
    pathex=[str(ROOT)],
    datas=datas,
    hiddenimports=hidden,
    excludes=["pytest", "tkinter", "matplotlib", "numpy", "PIL"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="MalLab",
    icon=str(HERE / "mallab.ico"),
    version=str(HERE / "version_info.txt"),
    console=False,
    upx=False,   # UPX-packed binaries get flagged by antivirus far more often
)
coll = COLLECT(exe, a.binaries, a.datas, name="MalLab", upx=False)
