"""Global politeness throttle -- a minimum interval between outbound requests across the whole scan.

A full DAST run fires a lot (recon + port scan + per-param battery + stored writes + page renders), and
hammering a live target is both rude and a reliability risk. Rather than thread a delay through every
function signature, each outbound primitive (dast_oracle._send, exploit.fire, dast_recon.http_fetch /
scan_ports, auth._post, dom_oracle render, browser_recon crawl) calls `wait()` before it sends.

Default delay is 0 -> `wait()` returns immediately and nothing changes. `configure(delay)` (called once
by dast_scan.scan) turns it on; the limiter is thread-safe so it also paces the concurrent port scan.
"""
from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_delay = 0.0
_last = 0.0


def configure(delay):
    """Set the minimum seconds between requests (0 disables). Resets the clock."""
    global _delay, _last
    _delay = max(0.0, float(delay or 0.0))
    _last = 0.0


def wait():
    """Block until at least `delay` seconds have passed since the previous request. No-op when disabled."""
    if _delay <= 0:
        return
    global _last
    with _lock:
        gap = _delay - (time.monotonic() - _last)
        if gap > 0:
            time.sleep(gap)
        _last = time.monotonic()
