"""Sandbox plumbing that can be checked without starting a VM: the in-VM monitor script parses,
the .wsb stays hardened, and report post-processing filters environment noise."""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import sandbox


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only")
def test_monitor_script_parses(tmp_path):
    p = tmp_path / "monitor.ps1"
    p.write_text(sandbox.MONITOR_PS1, encoding="utf-8-sig")
    r = subprocess.run(["powershell", "-NoProfile", "-Command",
                        f"$e=$null; [void][System.Management.Automation.Language.Parser]::ParseFile('{p}', [ref]$null, [ref]$e); $e.Count"],
                       capture_output=True, text=True, timeout=60)
    assert r.stdout.strip() == "0", r.stdout + r.stderr


def test_wsb_template_keeps_host_channels_closed():
    # Element names are case-sensitive: Windows Sandbox 0.8+ ignored the old "<VGpu>" spelling
    # and left the host GPU shared. Use the exact names from Microsoft's .wsb reference.
    assert "<VGpu>" not in sandbox.WSB_TEMPLATE
    for setting in ("<vGPU>Disable</vGPU>", "<Networking>{networking}</Networking>",
                    "<ProtectedClient>Enable</ProtectedClient>", "<ClipboardRedirection>Disable</ClipboardRedirection>",
                    "<AudioInput>Disable</AudioInput>", "<VideoInput>Disable</VideoInput>",
                    "<PrinterRedirection>Disable</PrinterRedirection>", "<ReadOnly>true</ReadOnly>"):
        assert setting in sandbox.WSB_TEMPLATE


def test_isolation_failure_is_fail_closed():
    assert "$Detonate = $false" in sandbox.MONITOR_PS1           # monitor refuses to run the sample
    assert "{nonet}" in sandbox.WSB_TEMPLATE
    v = sandbox._summarize({"isolation_failed": ["host GPU visible in the VM: X"], "detonated": False})
    assert v.startswith("NOT EXECUTED")


def test_noise_and_isolation_flags():
    assert sandbox.NOISE_FILES.search(r"C:\Users\x\AppData\Local\NVIDIA\DXCache\a.nvph")
    assert not sandbox.NOISE_FILES.search(r"C:\Users\x\AppData\Local\Temp\payload.exe")
    assert sandbox.BASIC_DISPLAY.search("Microsoft Remote Display Adapter")
    assert not sandbox.BASIC_DISPLAY.search("NVIDIA GeForce RTX 5080")
