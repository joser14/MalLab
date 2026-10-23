"""MalLab desktop app: runs the lab server in the background and shows the UI in its own window.
This is the entry point PyInstaller builds into MalLab.exe.

    MalLab.exe                         # open the lab
    MalLab.exe --lab-root D:\\lab       # use another lab folder
    MalLab.exe --setup-sysmon          # download Sysmon into the lab's tools folder, then exit
    MalLab.exe --setup-capa            # download capa (official GitHub release), then exit
    MalLab.exe --setup-fakenet         # download FakeNet-NG (official GitHub release), then exit
    MalLab.exe --import-actors         # import MITRE ATT&CK / MISP / Malpedia threat groups, then exit
    MalLab.exe --defender-exclude      # add the Defender exclusion (UAC prompt), then exit
    MalLab.exe --host-guard            # turn on the host network guard (UAC prompt), then exit

The setup flags are what the installer runs for its optional steps; they exit with 0 on success.
"""

import argparse
import ctypes
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))   # server.py / mallab when run from source

import server  # noqa: E402

APP_NAME = "MalLab"
MUTEX_NAME = "MalLabDesktopSingleInstance"   # also used by the installer (AppMutex)


def _data_dir(lab_root: Path) -> Path:
    d = lab_root.parent if lab_root.name == "lab" else lab_root
    d.mkdir(parents=True, exist_ok=True)
    return d


def _log_to_file(data_dir: Path):
    """A windowed exe has no stdout/stderr; send prints and uvicorn's logging to a file instead."""
    if sys.stdout is None or sys.stderr is None:
        f = open(data_dir / "mallab.log", "a", buffering=1, encoding="utf-8", errors="replace")
        sys.stdout = sys.stdout or f
        sys.stderr = sys.stderr or f
        print(f"\n--- MalLab started {time.strftime('%Y-%m-%d %H:%M:%S')} ---")


def _record_setup_failures(lab_root: Path, names: list[str]):
    """Leave a note for the app (Settings shows it): install-time steps can fail (offline, Defender,
    the sandbox adapter not existing until after the restart) and should be retried there."""
    f = lab_root / "setup-pending.txt"
    old = set(f.read_text(encoding="utf-8").splitlines()) if f.exists() else set()
    f.write_text("\n".join(sorted(old | set(names))) + "\n", encoding="utf-8")


def _message(text: str, error: bool = False):
    ctypes.windll.user32.MessageBoxW(None, text, APP_NAME, 0x10 if error else 0x40)


def _single_instance() -> bool:
    """True if this is the only running MalLab; otherwise bring the open window forward."""
    ctypes.windll.kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if ctypes.windll.kernel32.GetLastError() != 183:   # ERROR_ALREADY_EXISTS
        return True
    hwnd = ctypes.windll.user32.FindWindowW(None, APP_NAME)
    if hwnd:
        ctypes.windll.user32.ShowWindow(hwnd, 9)   # SW_RESTORE
        ctypes.windll.user32.SetForegroundWindow(hwnd)
    return False


def _pick_port(preferred: int) -> int:
    """The preferred port keeps the page's saved preferences (they're per origin); any free one otherwise."""
    if not server._port_in_use(preferred):
        return preferred
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    p = argparse.ArgumentParser(description="MalLab: a local malware research lab.")
    p.add_argument("--lab-root", default=str(server.default_lab_root()))
    p.add_argument("--port", type=int, default=7860)
    p.add_argument("--setup-sysmon", action="store_true", help="download Sysmon, then exit")
    p.add_argument("--setup-capa", action="store_true", help="download capa, then exit")
    p.add_argument("--setup-fakenet", action="store_true", help="download FakeNet-NG, then exit")
    p.add_argument("--setup-memscan", action="store_true", help="download hollows_hunter (pe-sieve), then exit")
    p.add_argument("--setup-sigma", action="store_true", help="download SigmaHQ rules, then exit")
    p.add_argument("--setup-yara-forge", action="store_true", help="download YARA Forge rules, then exit")
    p.add_argument("--import-actors", action="store_true", help="import public threat-group data, then exit")
    p.add_argument("--defender-exclude", action="store_true", help="add the Defender exclusion, then exit")
    p.add_argument("--host-guard", action="store_true", help="turn on the host network guard, then exit")
    p.add_argument("--defer", metavar="STEP", help="list an install step for Settings to offer later, then exit")
    args = p.parse_args()

    lab_root = Path(args.lab_root)
    data_dir = _data_dir(lab_root)
    _log_to_file(data_dir)

    from mallab import MalLab

    if args.defer:   # e.g. the host guard, which needs the restart that turns Windows Sandbox on
        lab_root.mkdir(parents=True, exist_ok=True)
        _record_setup_failures(lab_root, [args.defer[:60]])
        return 0

    steps =[(args.setup_sysmon, "Sysmon", lambda lab: lab.setup_sysmon()),
             (args.setup_capa, "capa", lambda lab: lab.setup_tool("capa")),
             (args.setup_fakenet, "FakeNet-NG", lambda lab: lab.setup_tool("fakenet")),
             (args.setup_memscan, "hollows_hunter", lambda lab: lab.setup_tool("hollows_hunter")),
             (args.setup_sigma, "Sigma rules", lambda lab: lab.setup_tool("sigma")),
             (args.setup_yara_forge, "YARA Forge rules", lambda lab: lab.setup_tool("yara_forge")),
             (args.import_actors, "threat-group data", lambda lab: lab.import_actor_catalog()),
             (args.defender_exclude, "Defender exclusion", lambda lab: lab.set_defender_exclusion(True)),
             (args.host_guard, "host network guard", lambda lab: lab.set_netguard(True))]
    if any(on for on, _, _ in steps):
        lab = MalLab(lab_root, emit=lambda e: print(e.get("text", e)))
        failed = []
        for on, name, run in steps:   # each step is independent: one failure doesn't skip the rest
            if not on:
                continue
            try:
                run(lab)
            except Exception as e:
                print(f"{name} setup failed: {type(e).__name__}: {e}")
                failed.append(name)
        if failed:
            _record_setup_failures(lab_root, failed)
        return 1 if failed else 0

    if not _single_instance():
        return 0

    import uvicorn
    import webview

    hub = server.Hub()
    lab = MalLab(lab_root, emit=hub.publish)
    port = _pick_port(args.port)
    url = f"http://127.0.0.1:{port}/"
    print(f"MalLab: {url}  (lab data: {lab_root.resolve()})")

    srv = uvicorn.Server(uvicorn.Config(server.LocalOnly(server.build_app(lab, hub)),
                                        host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.time() + 20
    while not srv.started:
        if not thread.is_alive() or time.time() > deadline:
            _message(f"MalLab's local server could not start on port {port}.\n"
                     f"See {data_dir / 'mallab.log'} for details.", error=True)
            return 1
        time.sleep(0.05)

    webview.settings["ALLOW_DOWNLOADS"] = True                 # case reports, pcaps
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True  # MITRE / intel links open in the real browser
    window = webview.create_window(APP_NAME, url, width=1400, height=900, min_size=(960, 640))

    def closing():
        if lab.detonating:   # MB_YESNO | MB_ICONWARNING | MB_TOPMOST; 6 = Yes
            return ctypes.windll.user32.MessageBoxW(
                None, "A detonation is still running. Close MalLab anyway?\n"
                      "The sandbox VM will keep running until you close it.", APP_NAME, 0x40034) == 6
        return True
    window.events.closing += closing

    try:
        webview.start(private_mode=False, storage_path=str(data_dir / "webview"))
    except Exception as e:
        _message("MalLab needs the Microsoft Edge WebView2 Runtime to show its window.\n"
                 "Reinstall MalLab (it installs WebView2 for you) or get it from\n"
                 "https://developer.microsoft.com/microsoft-edge/webview2/\n\n"
                 f"({type(e).__name__}: {e})", error=True)
        return 1
    finally:
        srv.should_exit = True
        thread.join(timeout=5)
    return 0


if __name__ == "__main__":
    sys.exit(main())
