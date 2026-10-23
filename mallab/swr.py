"""Stale-while-revalidate cache for slow system probes.

Some status checks shell out to PowerShell (Defender status, the firewall guard) and take one to
three seconds. Blocking on them made every status refresh, and any page waiting on one, freeze
whenever the cache expired. With this, only the very first read blocks; after that a stale value
is returned at once and a single background thread refreshes it.
"""

import threading
import time


class Probe:
    def __init__(self, read, max_age: float):
        self._read, self.max_age = read, max_age
        self._lock = threading.Lock()
        self._value, self._t, self._busy = None, 0.0, False

    def _store(self, value):
        with self._lock:
            self._value, self._t, self._busy = value, time.time(), False
        return value

    def _refresh_in_background(self):
        try:
            self._store(self._read())
        except Exception:          # keep serving the old value; try again on a later read
            with self._lock:
                self._busy = False

    def get(self):
        with self._lock:
            have = self._t > 0
            start = have and not self._busy and time.time() - self._t > self.max_age
            if start:
                self._busy = True
            value = self._value
        if not have:
            return self._store(self._read())       # first read: nothing to serve yet
        if start:
            threading.Thread(target=self._refresh_in_background, daemon=True).start()
        return value

    def clear(self):
        """Forget the value, so the next read is fresh (after the user changed the setting)."""
        with self._lock:
            self._value, self._t, self._busy = None, 0.0, False
