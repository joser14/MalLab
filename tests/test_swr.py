"""Stale-while-revalidate probe: only the first read waits; stale reads return at once."""

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mallab import swr


def test_first_read_blocks_then_serves_stale_and_refreshes():
    calls, gate = [], threading.Event()

    def read():
        calls.append(time.time())
        if len(calls) > 1:
            gate.wait(5)            # the background refresh is slow
        return len(calls)

    p = swr.Probe(read, max_age=0)
    assert p.get() == 1              # first read runs inline
    t0 = time.time()
    assert p.get() == 1              # stale: old value returned immediately...
    assert time.time() - t0 < 0.5    # ...without waiting for the slow refresh
    assert p.get() == 1              # a refresh is already running: no second thread
    time.sleep(0.05)
    assert len(calls) == 2           # first read + exactly one background refresh in flight
    gate.set()
    for _ in range(50):
        if p.get() >= 2:
            break
        time.sleep(0.02)
    assert p.get() >= 2


def test_failed_refresh_keeps_old_value_and_clear_forces_fresh():
    state = {"n": 0, "fail": False}

    def read():
        if state["fail"]:
            raise RuntimeError("probe broke")
        state["n"] += 1
        return state["n"]

    p = swr.Probe(read, max_age=0)
    assert p.get() == 1
    state["fail"] = True
    assert p.get() == 1
    time.sleep(0.1)
    assert p.get() == 1              # still the last good value
    state["fail"] = False
    p.clear()
    assert p.get() == 2              # after clear, the next read is fresh and inline
