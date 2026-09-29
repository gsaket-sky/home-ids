"""
Incident aggregation: collapses repeat Telegram notifications for the same ongoing
incident (same device+target+signature, see incident_key.py) into: the first
occurrence, any severity escalation (SUSPICIOUS -> HIGH -> CRITICAL), and periodic
"still ongoing" updates -- instead of a full Telegram alert every single time the
existing per-device cadence gate (pipeline.py's `time_elapsed > 300 or ...` check)
clears. That gate is UNCHANGED by this: alerts.json still gets a line every qualifying
cycle (that data feeds CL-AFPE/retrain/audits and must not be lost) -- IncidentTracker
only gates the Telegram send layered on top of it.

Deliberately in-memory only, same rationale as DeviceState.suspicious_since: a service
restart just means incident grouping starts fresh -- a safe, low-consequence
simplification (worst case: one redundant "first occurrence" Telegram alert after a
restart, not a real problem).
"""
import threading
import time
from dataclasses import dataclass
from typing import Dict, NamedTuple, Optional

# Coarse severity ordering for escalation detection -- deliberately not importing
# DecisionState (core.decision_engine) to keep this module dependency-free and usable
# from any caller (matches incident_key.py's own zero-dependency design). Any state
# name not listed here (including unrecognized/legacy strings) ranks as 0, the same as
# BENIGN/ANOMALOUS/SUSPICIOUS -- only HIGH/CRITICAL are genuine escalations worth an
# out-of-cadence re-notify.
_SEVERITY_RANK = {"SUSPICIOUS": 0, "ANOMALOUS": 0, "BENIGN": 0, "HIGH": 1, "CRITICAL": 2}

# Opportunistic prune trigger -- checked cheaply (a dict len()) on every call, only pays
# the O(n) scan cost once the tracker has actually grown large (many distinct
# device+target+signature combinations seen), not on every single call.
_PRUNE_SIZE_THRESHOLD = 2000


class IncidentNotifyResult(NamedTuple):
    should_notify: bool     # whether THIS occurrence should trigger a Telegram send
    occurrence_count: int   # total occurrences of this incident seen so far (including this one)
    is_escalation: bool     # True if should_notify fired because severity increased, not just cadence
    incident_age_seconds: float  # time since this incident's first occurrence


@dataclass
class _IncidentRecord:
    first_seen: float
    last_seen: float
    occurrence_count: int
    last_notified_at: float
    last_notified_severity_rank: int


class IncidentTracker:
    def __init__(self, grouping_window_seconds: float = 1800.0, update_min_interval_seconds: float = 900.0):
        # grouping_window_seconds: how long a gap since the last occurrence before the
        # NEXT occurrence is treated as a genuinely new incident rather than a
        # continuation -- a long-quiet gap means the earlier episode really did end.
        # update_min_interval_seconds: minimum spacing between "still ongoing, N
        # occurrences" periodic re-notifications for one incident that's staying open.
        self._grouping_window_seconds = grouping_window_seconds
        self._update_min_interval_seconds = update_min_interval_seconds
        self._incidents: Dict[str, _IncidentRecord] = {}
        self._lock = threading.RLock()

    def should_notify(self, key: str, severity_state: str, now: Optional[float] = None) -> IncidentNotifyResult:
        """Call once per qualifying cycle (i.e. exactly where pipeline.py already decided
        a Telegram send is otherwise eligible -- HIGH/CRITICAL and not FP-suppressed).
        Always records the occurrence regardless of the notify decision -- alerts.json/
        CL-AFPE training already happened independently of this and is unaffected;
        `should_notify` only tells the caller whether THIS occurrence should also reach
        Telegram."""
        now = now if now is not None else time.time()
        severity_rank = _SEVERITY_RANK.get(severity_state, 0)

        with self._lock:
            if len(self._incidents) > _PRUNE_SIZE_THRESHOLD:
                self._prune(now)

            record = self._incidents.get(key)

            if record is None or (now - record.last_seen) > self._grouping_window_seconds:
                self._incidents[key] = _IncidentRecord(
                    first_seen=now, last_seen=now, occurrence_count=1,
                    last_notified_at=now, last_notified_severity_rank=severity_rank,
                )
                return IncidentNotifyResult(True, 1, False, 0.0)

            record.last_seen = now
            record.occurrence_count += 1

            escalated = severity_rank > record.last_notified_severity_rank
            due_for_update = (now - record.last_notified_at) >= self._update_min_interval_seconds

            if escalated or due_for_update:
                record.last_notified_at = now
                record.last_notified_severity_rank = max(severity_rank, record.last_notified_severity_rank)
                return IncidentNotifyResult(True, record.occurrence_count, escalated, now - record.first_seen)

            return IncidentNotifyResult(False, record.occurrence_count, False, now - record.first_seen)

    def _prune(self, now: float) -> None:
        # Not holding a separate lock here -- always called from inside should_notify's
        # `with self._lock:` block.
        stale_cutoff = self._grouping_window_seconds * 4
        stale_keys = [k for k, r in self._incidents.items() if (now - r.last_seen) > stale_cutoff]
        for k in stale_keys:
            del self._incidents[k]
