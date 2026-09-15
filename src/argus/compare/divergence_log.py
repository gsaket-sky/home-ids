"""
v13 divergence comparator (Phase 7 wiring -- Documentation/V13_REMAINING_WORK.md
item A8). Compares v-current's real alerts (`.94`'s `state/alerts.json`,
mounted read-only on `.19` via the new `v13-alerts` Samba share, 2026-09-06 --
a narrow hardlink-only export directory, not the whole `state/` tree, which
also holds trust caches and reactive-capture data this comparator has no
need for) against v13's own real decisions (A7, this box's `v13_graph.db`).

This is the actual data source `src/v13/ops/gap_monitor.py` (not yet built,
A9) needs before it can evaluate any mechanism against a documented bar --
until this module ran, there was no real divergence data for anything.

CORRELATION STRATEGY (documented explicitly, not improvised inline, per this
session's own A8 scoping note):

v-current's `alerts.json` contains ONLY alert-worthy records already
(confirmed via direct inspection this session: every entry present carries a
real signature/risk, not a per-cycle BENIGN dump) -- matching v13's own
`decisions` table's dedup-guarded shape (A7) almost exactly. So this
comparator's real job is temporal-proximity matching, not filtering:

For every v-current alert in a time window, find the temporally-closest v13
decision for the SAME device (by IP) within TOLERANCE_SECONDS, and classify:
  - AGREE            -- both non-benign, same decision_path
  - DIFFERENT_PATH    -- both non-benign, different decision_path/signature --
                          agreed something was wrong, disagreed on what
  - VCURRENT_ONLY      -- v-current alerted; no v13 decision at all near this
                          device/time (v13 either called it benign, or never
                          evaluated this device/time -- the two are
                          distinguished via `v13_evaluated_but_benign`)
For every v13 decision with no corresponding v-current alert nearby:
  - V13_ONLY           -- v13 flagged something v-current never alerted on

KNOWN LIMITATION (flagged, not silent): v13's device_id is the raw source IP
-- daemon.py never routes through identity/resolver.py's stable-hash
device_id (a separate, already-flagged simplification, see the daemon's own
module docstring) -- while v-current's `device.id` is a stable hash that
survives IP churn. Correlating on IP is what both sides actually have in
common today, not perfectly robust across a device changing addresses
mid-comparison-window, but a real, working signal for the common case.
"""
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from argus.graph.store import GraphStore

LOGGER = logging.getLogger("v13.compare.divergence_log")

TOLERANCE_SECONDS = 300.0  # matches RollingWindowView.SHORT_WINDOW_SECONDS's
                             # own "same cycle, roughly" tolerance elsewhere in v13

_NON_BENIGN_STATES = frozenset({"ANOMALOUS", "SUSPICIOUS", "HIGH", "CRITICAL"})


@dataclass
class Divergence:
    kind: str  # AGREE | DIFFERENT_PATH | V13_ONLY | VCURRENT_ONLY
    device_ip: str
    timestamp: float
    vcurrent_signature: Optional[str] = None
    vcurrent_decision_path: Optional[str] = None
    vcurrent_risk: Optional[float] = None
    v13_state: Optional[str] = None
    v13_decision_path: Optional[str] = None
    v13_evaluated_but_benign: bool = False
    detail: str = ""


class AlertsJsonlTailer:
    """Tails .94's alerts.json (JSONL, one record per line) with a persistent
    byte-offset+inode cursor -- same cursor algorithm as ZeekLogSource/
    PiHoleLogSource (src/v13/ingest/sources.py), so a 100MB+, continuously-
    growing file is only ever scanned incrementally, not re-read whole on
    every comparator run. Deliberately not shared code with those two
    classes (each already documented its own reason for not refactoring into
    a common base under this session's time constraints) -- same algorithm,
    a third independent copy, all three tested identically."""

    def __init__(self, path: Path, cursor_path: Path):
        self.path = Path(path)
        self.cursor_path = Path(cursor_path)
        self._pos = 0
        self._inode: Optional[int] = None
        self._load_cursor()
        if self._inode is None:
            self._seek_to_end()
            # BUGFIX (found via test_argus_run_gap_check.py, 2026-09-06): unlike
            # ZeekLogSource/PiHoleLogSource (used by a long-LIVED daemon
            # process, constructed once and reused across every poll -- only
            # a full process restart ever re-triggers this branch), this
            # class is also used by run_gap_check.py's run_once(), which
            # constructs a FRESH tailer every cron tick with no persistent
            # object across calls. Without saving the cursor immediately
            # here, a tick that finds nothing new (read_new_alerts()'s own
            # early-return skips _save_cursor()) leaves no baseline behind --
            # the NEXT tick's fresh construction re-seeks to whatever is the
            # LATEST current EOF by then, permanently skipping anything that
            # arrived in between. Saving here establishes a real, persisted
            # baseline on the very first construction, not just the first
            # one that happens to find something to process.
            self._save_cursor()

    def _load_cursor(self) -> None:
        if not self.cursor_path.exists():
            return
        try:
            data = json.loads(self.cursor_path.read_text())
            if self.path.exists() and self.path.stat().st_ino == data.get("inode"):
                self._inode = data["inode"]
                self._pos = data["pos"]
        except Exception:
            pass

    def _save_cursor(self) -> None:
        if self._inode is None:
            return
        try:
            self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
            self.cursor_path.write_text(json.dumps({"inode": self._inode, "pos": self._pos}))
        except Exception:
            pass

    def _seek_to_end(self) -> None:
        if not self.path.exists():
            return
        try:
            stat = self.path.stat()
            self._inode = stat.st_ino
            self._pos = stat.st_size
        except OSError:
            pass

    def read_new_alerts(self) -> List[dict]:
        """Returns newly-appended, complete, parseable alert records since the
        last call. A malformed line is skipped, not fatal -- matches this
        project's own detector-resilience convention."""
        out: List[dict] = []
        if not self.path.exists():
            return out
        try:
            stat = self.path.stat()
            if stat.st_ino != self._inode or stat.st_size < self._pos:
                self._pos = 0
                self._inode = stat.st_ino
            if stat.st_size <= self._pos:
                return out

            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._pos)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        break
                    clean_line = line.strip()
                    if clean_line:
                        try:
                            out.append(json.loads(clean_line))
                        except json.JSONDecodeError:
                            LOGGER.debug("Skipping malformed alerts.json line.")
                    self._pos = f.tell()
                self._save_cursor()
        except OSError as exc:
            LOGGER.debug("alerts.json unreadable this poll: %s", exc)
        return out


def _extract_vcurrent_fields(alert: dict) -> Optional[Dict[str, Any]]:
    """Pulls the fields this comparator actually needs from a real alert
    record's confirmed shape (device.ip, timestamp, hee_decision_path,
    signature, risk -- confirmed via direct inspection of a real record on
    `.94`, 2026-09-06, not guessed). Returns None for a record missing the
    minimum needed to correlate (device.ip or timestamp) rather than raising --
    a malformed/unexpected-shape record is skipped, not fatal."""
    device = alert.get("device") or {}
    device_ip = device.get("ip")
    timestamp = alert.get("timestamp")
    if not device_ip or timestamp is None:
        return None
    return {
        "device_ip": device_ip,
        "timestamp": float(timestamp),
        "decision_path": alert.get("hee_decision_path"),
        "signature": alert.get("signature"),
        "risk": alert.get("risk"),
    }


def compare_window(store: GraphStore, vcurrent_alerts: List[dict],
                     since: float, until: Optional[float] = None,
                     tolerance_seconds: float = TOLERANCE_SECONDS) -> List[Divergence]:
    """Correlates a batch of v-current alert records (already parsed dicts,
    e.g. from AlertsJsonlTailer.read_new_alerts()) against v13's own real
    decisions in [since, until) (GraphStore.get_decisions_since(), A7).
    Pure function of its inputs -- no I/O of its own, so it's fully testable
    with synthetic alert lists and a real (or in-memory) GraphStore."""
    v13_decisions = store.get_decisions_since(since, until=until)

    # Index v13 decisions by device_ip for fast lookup -- v13's device_id IS
    # the raw IP in the current daemon wiring (see module docstring's KNOWN
    # LIMITATION), so no translation is needed here, just a direct key match.
    v13_by_device: Dict[str, List[dict]] = {}
    for d in v13_decisions:
        v13_by_device.setdefault(d["device_id"], []).append(d)

    matched_v13_indices: set = set()
    divergences: List[Divergence] = []

    for raw_alert in vcurrent_alerts:
        fields = _extract_vcurrent_fields(raw_alert)
        if fields is None:
            continue
        if fields["timestamp"] < since or (until is not None and fields["timestamp"] >= until):
            continue

        candidates = v13_by_device.get(fields["device_ip"], [])
        best_idx, best_delta = None, None
        for idx, d in enumerate(candidates):
            delta = abs(d["timestamp"] - fields["timestamp"])
            if delta <= tolerance_seconds and (best_delta is None or delta < best_delta):
                best_idx, best_delta = idx, delta

        if best_idx is None:
            # No v13 decision at all within tolerance for this device/time --
            # v13 either has no evidence for this device right now, or its
            # verdict fell outside the tolerance window. Either way: no
            # matching v13 decision to compare against.
            divergences.append(Divergence(
                kind="VCURRENT_ONLY", device_ip=fields["device_ip"], timestamp=fields["timestamp"],
                vcurrent_signature=fields["signature"], vcurrent_decision_path=fields["decision_path"],
                vcurrent_risk=fields["risk"], v13_evaluated_but_benign=False,
                detail="v-current alerted; no v13 decision found for this device within tolerance",
            ))
            continue

        matched_v13_indices.add((fields["device_ip"], best_idx))
        v13_decision = candidates[best_idx]
        v13_non_benign = v13_decision["state"] in _NON_BENIGN_STATES

        if not v13_non_benign:
            divergences.append(Divergence(
                kind="VCURRENT_ONLY", device_ip=fields["device_ip"], timestamp=fields["timestamp"],
                vcurrent_signature=fields["signature"], vcurrent_decision_path=fields["decision_path"],
                vcurrent_risk=fields["risk"], v13_state=v13_decision["state"],
                v13_decision_path=v13_decision["decision_path"], v13_evaluated_but_benign=True,
                detail="v-current alerted; v13 evaluated this device nearby but called it BENIGN",
            ))
        elif v13_decision["decision_path"] == fields["decision_path"]:
            divergences.append(Divergence(
                kind="AGREE", device_ip=fields["device_ip"], timestamp=fields["timestamp"],
                vcurrent_signature=fields["signature"], vcurrent_decision_path=fields["decision_path"],
                vcurrent_risk=fields["risk"], v13_state=v13_decision["state"],
                v13_decision_path=v13_decision["decision_path"],
                detail="both flagged this device via the same decision_path",
            ))
        else:
            divergences.append(Divergence(
                kind="DIFFERENT_PATH", device_ip=fields["device_ip"], timestamp=fields["timestamp"],
                vcurrent_signature=fields["signature"], vcurrent_decision_path=fields["decision_path"],
                vcurrent_risk=fields["risk"], v13_state=v13_decision["state"],
                v13_decision_path=v13_decision["decision_path"],
                detail="both flagged this device, but via different decision_path values",
            ))

    for device_ip, decisions in v13_by_device.items():
        for idx, d in enumerate(decisions):
            if (device_ip, idx) in matched_v13_indices:
                continue
            if d["state"] not in _NON_BENIGN_STATES:
                continue  # a v13 BENIGN decision with no v-current alert nearby is not a divergence
            divergences.append(Divergence(
                kind="V13_ONLY", device_ip=device_ip, timestamp=d["timestamp"],
                v13_state=d["state"], v13_decision_path=d["decision_path"],
                detail="v13 flagged this device; no v-current alert found nearby",
            ))

    return divergences


def append_divergences_jsonl(divergences: List[Divergence], output_path: Path) -> None:
    """Appends each divergence as one JSON line -- matches the plan's own
    stated design (`state/v13_divergence.jsonl`), and this project's general
    append-only-audit-trail convention (alerts.json itself, retro_hunt_findings.jsonl)."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "a", encoding="utf-8") as f:
        for d in divergences:
            f.write(json.dumps(d.__dict__) + "\n")


def run_comparison(store: GraphStore, alerts_tailer: AlertsJsonlTailer,
                     output_path: Path, lookback_seconds: float = 3600.0,
                     now: Optional[float] = None) -> List[Divergence]:
    """One comparator cycle: reads newly-appended v-current alerts, compares
    them against a lookback window of v13's own decisions, appends any
    divergences found, and returns them (for a caller that wants to log a
    summary, e.g. a Telegram notification -- not built here, matching
    ClAfpeEngine/RetroHunter's own "hand data back to the caller" shape)."""
    now = now if now is not None else time.time()
    new_alerts = alerts_tailer.read_new_alerts()
    if not new_alerts:
        return []
    divergences = compare_window(store, new_alerts, since=now - lookback_seconds, until=now)
    if divergences:
        append_divergences_jsonl(divergences, output_path)
    return divergences
