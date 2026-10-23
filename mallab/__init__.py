"""MalLab: a malware analysis lab.

Case workspaces, static triage, isolated detonation in Windows Sandbox, and sample
acquisition from VX Underground / virus.exchange (MWDB API). Everything is oriented to
*analysis*: samples are quarantined on arrival and only ever execute inside a disposable,
network-isolated sandbox VM, never on the host.
"""

from .service import MalLab

__all__ = ["MalLab"]
