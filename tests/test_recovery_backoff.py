"""
Tests for core/backoff.py -- RecoveryBackoff. Uses an injected `now` clock
throughout, never a real time.sleep(), so this runs instantly and deterministically.
"""
import sys
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.backoff import RecoveryBackoff  # noqa: E402


def test_first_attempt_allowed_immediately():
    b = RecoveryBackoff()
    assert b.attempt_allowed(now=1000.0) is True


def test_schedule_gates_subsequent_attempts():
    b = RecoveryBackoff()
    b.record_attempt(now=1000.0)  # 1st attempt used
    assert b.attempt_allowed(now=1000.0) is False  # 2nd needs 30s
    assert b.attempt_allowed(now=1029.0) is False
    assert b.attempt_allowed(now=1030.0) is True

    b.record_attempt(now=1030.0)  # 2nd attempt used
    assert b.attempt_allowed(now=1030.0) is False  # 3rd needs 120s
    assert b.attempt_allowed(now=1149.0) is False
    assert b.attempt_allowed(now=1150.0) is True

    b.record_attempt(now=1150.0)  # 3rd attempt used
    assert b.attempt_allowed(now=1150.0) is False  # 4th needs 600s
    assert b.attempt_allowed(now=1749.0) is False
    assert b.attempt_allowed(now=1750.0) is True


def test_exhausted_after_max_attempts():
    b = RecoveryBackoff(max_attempts=3)
    assert b.exhausted() is False
    b.record_attempt(now=0.0)
    assert b.exhausted() is False
    b.record_attempt(now=1000.0)
    assert b.exhausted() is False
    b.record_attempt(now=2000.0)
    assert b.exhausted() is True
    assert b.attempt_allowed(now=999999.0) is False  # exhausted overrides any wait


def test_reset_clears_attempt_history():
    b = RecoveryBackoff(max_attempts=2)
    b.record_attempt(now=0.0)
    b.record_attempt(now=1.0)
    assert b.exhausted() is True
    b.reset()
    assert b.exhausted() is False
    assert b.attempt_count == 0
    assert b.attempt_allowed(now=0.0) is True


def test_attempt_count_tracks_records():
    b = RecoveryBackoff()
    assert b.attempt_count == 0
    b.record_attempt(now=0.0)
    assert b.attempt_count == 1
    b.record_attempt(now=1000.0)
    assert b.attempt_count == 2


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
