"""Politeness-throttle regression (dast_throttle.py). Deterministic via a fake clock -- no real sleeping.

Run: pytest tests/test_dast_throttle.py -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent.orchestrator import dast_throttle as throttle


class FakeTime:
    """A controllable monotonic clock; sleep records the duration and advances the clock."""
    def __init__(self, start=1000.0):
        self.t = start
        self.slept = []

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def test_disabled_by_default(monkeypatch):
    ft = FakeTime()
    monkeypatch.setattr(throttle, "time", ft)
    throttle.configure(0)
    throttle.wait()
    throttle.wait()
    assert ft.slept == []                              # delay 0 -> never sleeps


def test_first_request_does_not_wait(monkeypatch):
    ft = FakeTime(start=1000.0)
    monkeypatch.setattr(throttle, "time", ft)
    throttle.configure(0.5)
    throttle.wait()                                    # real clock is far ahead of the reset _last -> no sleep
    assert ft.slept == []


def test_second_request_is_paced(monkeypatch):
    ft = FakeTime(start=1000.0)
    monkeypatch.setattr(throttle, "time", ft)
    throttle.configure(0.5)
    throttle.wait()                                    # establishes _last = now
    throttle.wait()                                    # immediately after -> must wait the full delay
    assert ft.slept == [0.5]


def test_partial_elapsed_only_waits_remainder(monkeypatch):
    ft = FakeTime(start=1000.0)
    monkeypatch.setattr(throttle, "time", ft)
    import pytest
    throttle.configure(1.0)
    throttle.wait()
    ft.t += 0.4                                        # 0.4s passed doing work
    throttle.wait()
    assert ft.slept == [pytest.approx(0.6)]            # only the remaining ~0.6s


def test_configure_resets(monkeypatch):
    ft = FakeTime()
    monkeypatch.setattr(throttle, "time", ft)
    throttle.configure(0.5)
    throttle.configure(0)                              # back off -> disabled again
    throttle.wait()
    assert ft.slept == []
