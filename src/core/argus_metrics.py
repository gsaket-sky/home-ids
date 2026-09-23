"""
argus_metrics.py -- read-only Prometheus exporter for the Argus evidence graph.

Everything the Argus architecture decides and learns lives in the graph DB
(state/v13_graph.db): alert outcomes, decisions, incidents, autotune history (global /
per device type / per device), CL-AFPE learned trust, Bayesian baselines and their
regime changes, population priors, backtests, containment and operator actions. None
of it reached Prometheus before -- src/argus/ deliberately has no Prometheus
dependency. This module reads it from the OUTSIDE and publishes it.

Pi-safety (Documentation/ARGUS_OBSERVABILITY_PLAN.md, section 2.4):
  - own daemon thread, never on the pipeline's main loop;
  - own short-lived READ-ONLY SQLite connection per pass (mode=ro), so it can never
    write, and a WAL reader never blocks the engine's writer;
  - every pass is bounded by a SQLite progress-handler deadline, abandoned cleanly
    if exceeded;
  - no query touches the two big tables (evidence, edges) -- every table read here
    is small or served by an existing timestamp index.

Network-agnostic: nothing here knows about any particular network. Device ids,
labels, device types, parameters and destination classes all come from the graph.
"""
import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from metrics import (
    argus_alert_events_24h, argus_alert_events_retained, argus_decisions_24h,
    argus_incidents_active_24h, autotune_value, autotune_canary_value, autotune_config_value,
    autotune_changes, autotune_last_change_timestamp, cl_afpe_trust_entries, cl_afpe_trust_mean,
    baseline_models, population_priors, backtest_last_pass, backtest_last_run_timestamp,
    containment_actions, operator_actions, argus_exporter_last_success_timestamp,
    argus_exporter_duration_seconds, device_alerts_fired_24h, device_alerts_suppressed_24h,
    device_learned_trust, device_baseline_regime_shifts, device_sigma_shift,
)

LOGGER = logging.getLogger("home_ids.argus_metrics")

DEFAULT_INTERVAL_SECONDS = 120.0
DEFAULT_PASS_TIMEOUT_SECONDS = 10.0
DAY = 86400.0

# Every gauge this module owns and the label names it sets, in order.
_GAUGE_LABELS = {
    argus_alert_events_24h: ("status",),
    argus_alert_events_retained: ("status",),
    argus_decisions_24h: ("state",),
    autotune_value: ("parameter", "scope", "target"),
    autotune_canary_value: ("parameter", "scope", "target"),
    autotune_config_value: ("parameter",),
    autotune_changes: ("parameter", "scope", "status"),
    autotune_last_change_timestamp: ("status",),
    cl_afpe_trust_entries: ("destination_class",),
    cl_afpe_trust_mean: ("destination_class",),
    baseline_models: ("model_kind",),
    population_priors: ("device_type",),
    containment_actions: ("action_type", "status"),
    operator_actions: ("action",),
    device_alerts_fired_24h: ("device",),
    device_alerts_suppressed_24h: ("device",),
    device_learned_trust: ("device",),
    device_baseline_regime_shifts: ("device",),
    device_sigma_shift: ("device",),
}


class _PassTimeout(Exception):
    pass


def canonical_device_map(rows: Iterable[Tuple[str, Optional[str]]]) -> Dict[str, str]:
    """{device_id: canonical_id}, following merged_into_device_id transitively with a
    cycle guard (the graph has had merge cycles before -- see GraphStore.merge_device())."""
    parent = {dev: merged for dev, merged in rows}
    out = {}
    for dev in parent:
        seen, cur = {dev}, dev
        while parent.get(cur) and parent[cur] not in seen and parent[cur] in parent:
            cur = parent[cur]
            seen.add(cur)
        out[dev] = cur
    return out


def autotune_scope(device_id: Optional[str], device_type: Optional[str]) -> Tuple[str, str]:
    """(scope, target) exactly as AutotuneEngine._promoted_value_at_scope() defines a
    scope: device (device_id set), category (device_type set), or global (neither)."""
    if device_id:
        return "device", device_id
    if device_type:
        return "category", device_type
    return "global", ""


def autotune_status(row: dict, now: float) -> str:
    if row.get("rolled_back_at"):
        return "rolled_back"
    if row.get("promoted_at"):
        return "promoted"
    if row.get("canary_until") and float(row["canary_until"]) > now:
        return "canary"
    return "not_promoted"


def summarize_autotune(rows: List[dict], canonical: Dict[str, str], now: float):
    """Pure function over threshold_history rows. Returns:
      active:  {(parameter, scope, target): value}   latest promoted, not rolled back
      canary:  {(parameter, scope, target): value}   latest proposal still in canary
      changes: {(parameter, scope, status): count}   'promoted' split into active vs superseded
      last:    {status: latest timestamp}"""
    active_rows: Dict[Tuple[str, str, str], dict] = {}
    canary: Dict[Tuple[str, str, str], Tuple[float, float]] = {}
    changes: Dict[Tuple[str, str, str], int] = {}
    last: Dict[str, float] = {}
    for row in rows:
        dev = canonical.get(row.get("device_id"), row.get("device_id")) if row.get("device_id") else None
        scope, target = autotune_scope(dev, row.get("device_type"))
        key = (row["parameter"], scope, target)
        status = autotune_status(row, now)
        if status == "promoted":
            prev = active_rows.get(key)
            if prev is None or float(row["promoted_at"]) > float(prev["promoted_at"]):
                active_rows[key] = row
        elif status == "canary":
            prev_c = canary.get(key)
            if prev_c is None or float(row["proposed_at"]) > prev_c[0]:
                canary[key] = (float(row["proposed_at"]), float(row["new_value"]))
        ts_field = {"promoted": "promoted_at", "rolled_back": "rolled_back_at"}.get(status, "proposed_at")
        if row.get(ts_field):
            last[status] = max(last.get(status, 0.0), float(row[ts_field]))
    active_ids = {id(r) for r in active_rows.values()}
    for row in rows:
        dev = canonical.get(row.get("device_id"), row.get("device_id")) if row.get("device_id") else None
        scope, _ = autotune_scope(dev, row.get("device_type"))
        status = autotune_status(row, now)
        if status == "promoted" and id(row) not in active_ids:
            status = "superseded"
        ck = (row["parameter"], scope, status)
        changes[ck] = changes.get(ck, 0) + 1
    active = {k: float(r["new_value"]) for k, r in active_rows.items() if r.get("new_value") is not None}
    return active, {k: v[1] for k, v in canary.items()}, changes, last


class ArgusMetricsExporter:
    def __init__(self, db_path, config, interval_seconds: Optional[float] = None,
                 pass_timeout_seconds: Optional[float] = None):
        self.db_path = Path(db_path)
        self.config = config
        self.interval = float(interval_seconds if interval_seconds is not None
                              else config.get("argus_metrics_interval_seconds", DEFAULT_INTERVAL_SECONDS))
        self.pass_timeout = float(pass_timeout_seconds if pass_timeout_seconds is not None
                                  else config.get("argus_metrics_pass_timeout_seconds", DEFAULT_PASS_TIMEOUT_SECONDS))
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._published: Dict[object, set] = {g: set() for g in _GAUGE_LABELS}

    # ---------------------------------------------------------------- lifecycle
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="argus-metrics-exporter", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.run_once()
            self._stop.wait(self.interval)

    # ---------------------------------------------------------------- one pass
    def run_once(self, now: Optional[float] = None) -> bool:
        if not self.db_path.exists():
            return False
        started = time.monotonic()
        now = time.time() if now is None else now
        conn = None
        try:
            conn = sqlite3.connect(f"file:{self.db_path.as_posix()}?mode=ro", uri=True, timeout=2.0)
            conn.row_factory = sqlite3.Row
            deadline = started + self.pass_timeout

            def _guard():
                return 1 if time.monotonic() > deadline else 0  # non-zero aborts the running statement
            conn.set_progress_handler(_guard, 10_000)  # bounds any single long statement
            staged = self._collect(conn, now, deadline)
        except (sqlite3.OperationalError, _PassTimeout) as exc:
            LOGGER.warning("Argus metrics pass abandoned (%s) -- previous values kept.", exc)
            return False
        except Exception as exc:
            LOGGER.warning("Argus metrics pass failed: %s", exc)
            return False
        finally:
            if conn is not None:
                conn.close()
        for gauge, rows in staged.items():
            self._publish(gauge, rows)
        argus_incidents_active_24h.set(staged.get("_incidents", 0))
        argus_exporter_duration_seconds.set(time.monotonic() - started)
        argus_exporter_last_success_timestamp.set(time.time())
        return True

    def _publish(self, gauge, rows: Dict[tuple, float]) -> None:
        """Set every row, then drop label sets this gauge published last pass but not
        this one (a device that vanished, a rolled-back scope) -- never clear() first,
        so a scrape mid-publish never sees a half-empty gauge."""
        if gauge not in self._published:
            return
        for labels, value in rows.items():
            gauge.labels(*labels).set(value)
        for stale in self._published[gauge] - set(rows):
            try:
                gauge.remove(*stale)
            except KeyError:
                pass
        self._published[gauge] = set(rows)

    def _collect(self, conn: sqlite3.Connection, now: float, deadline: float) -> dict:
        def q(sql, args=()):
            # The progress handler only fires every N VM steps, so a pass made of many
            # SMALL queries would never be checked -- bound the pass between queries too.
            if time.monotonic() > deadline:
                raise _PassTimeout("pass exceeded its time budget")
            return conn.execute(sql, args).fetchall()
        day_ago = now - DAY
        out: dict = {g: {} for g in _GAUGE_LABELS}

        # Devices: canonical ids (merges), display labels, Argus sensitivity shift.
        # The graph stores no device names -- series are keyed by canonical device id only.
        dev_rows = q("SELECT device_id, merged_into_device_id, metadata_json FROM devices")
        canonical = canonical_device_map((r["device_id"], r["merged_into_device_id"]) for r in dev_rows)

        def dev_key(device_id):
            return (canonical.get(device_id, device_id),)

        for r in dev_rows:
            if r["merged_into_device_id"]:
                continue
            try:
                shift = (json.loads(r["metadata_json"] or "{}") or {}).get("sigma_shift")
            except ValueError:
                shift = None
            if isinstance(shift, (int, float)):
                out[device_sigma_shift][dev_key(r["device_id"])] = float(shift)

        # Alert outcomes (restart-proof -- the graph, not a process counter).
        for r in q("SELECT status, COUNT(*) AS n FROM alert_events WHERE timestamp >= ? GROUP BY status", (day_ago,)):
            out[argus_alert_events_24h][(r["status"],)] = float(r["n"])
        for r in q("SELECT status, COUNT(*) AS n FROM alert_events GROUP BY status"):
            out[argus_alert_events_retained][(r["status"],)] = float(r["n"])
        per_dev = {}
        for r in q("SELECT device_id, status, COUNT(*) AS n FROM alert_events WHERE timestamp >= ? "
                   "GROUP BY device_id, status", (day_ago,)):
            k = (dev_key(r["device_id"]), r["status"])
            per_dev[k] = per_dev.get(k, 0) + r["n"]
        for (dk, status), n in per_dev.items():
            if status == "FIRED":
                out[device_alerts_fired_24h][dk] = float(n)
            elif status == "SUPPRESSED_AUTONOMOUS":
                out[device_alerts_suppressed_24h][dk] = float(n)

        for r in q("SELECT state, COUNT(*) AS n FROM decisions WHERE timestamp >= ? GROUP BY state", (day_ago,)):
            out[argus_decisions_24h][(str(r["state"]),)] = float(r["n"])
        out["_incidents"] = float(q("SELECT COUNT(*) AS n FROM incidents WHERE last_seen >= ?", (day_ago,))[0]["n"])

        # Autotune: global / per device type / per device.
        th_rows = [dict(r) for r in q("SELECT parameter, device_id, device_type, new_value, proposed_at, "
                                      "canary_until, promoted_at, rolled_back_at FROM threshold_history")]
        active, canary, changes, last = summarize_autotune(th_rows, canonical, now)

        for key, value in active.items():
            out[autotune_value][key] = value
        for key, value in canary.items():
            out[autotune_canary_value][key] = value
        for key, n in changes.items():
            out[autotune_changes][key] = float(n)
        for status, ts in last.items():
            out[autotune_last_change_timestamp][(status,)] = ts
        for parameter in {r["parameter"] for r in th_rows}:
            value = self.config.get(parameter)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                out[autotune_config_value][(parameter,)] = float(value)

        # CL-AFPE learned trust.
        for r in q("SELECT destination_class, COUNT(*) AS n, AVG(trust_value) AS m FROM cl_afpe_trust "
                   "GROUP BY destination_class"):
            out[cl_afpe_trust_entries][(str(r["destination_class"]),)] = float(r["n"])
            out[cl_afpe_trust_mean][(str(r["destination_class"]),)] = float(r["m"] or 0.0)
        trust_acc = {}
        for r in q("SELECT device_id, SUM(trust_value) AS s, COUNT(*) AS n FROM cl_afpe_trust GROUP BY device_id"):
            s, n = trust_acc.get(dev_key(r["device_id"]), (0.0, 0))
            trust_acc[dev_key(r["device_id"])] = (s + float(r["s"] or 0.0), n + int(r["n"]))
        for dk, (s, n) in trust_acc.items():
            if n:
                out[device_learned_trust][dk] = s / n

        # Bayesian baselines + BOCPD regime changes, population priors.
        for r in q("SELECT model_kind, COUNT(*) AS n FROM device_baselines GROUP BY model_kind"):
            out[baseline_models][(str(r["model_kind"]),)] = float(r["n"])
        for r in q("SELECT device_id, MAX(regime_id) AS m FROM device_baselines GROUP BY device_id"):
            dk = dev_key(r["device_id"])
            out[device_baseline_regime_shifts][dk] = max(out[device_baseline_regime_shifts].get(dk, 0.0),
                                                         float(r["m"] or 0))
        for r in q("SELECT device_type, COUNT(*) AS n FROM population_priors GROUP BY device_type"):
            out[population_priors][(str(r["device_type"]),)] = float(r["n"])

        latest = q("SELECT finished_at, overall_pass FROM backtest_runs WHERE finished_at IS NOT NULL "
                   "ORDER BY finished_at DESC LIMIT 1")
        if latest:
            backtest_last_pass.set(float(latest[0]["overall_pass"] or 0))
            backtest_last_run_timestamp.set(float(latest[0]["finished_at"]))

        for r in q("SELECT action_type, status, COUNT(*) AS n FROM containment_actions GROUP BY action_type, status"):
            out[containment_actions][(str(r["action_type"]), str(r["status"]))] = float(r["n"])
        for r in q("SELECT action, COUNT(*) AS n FROM operator_actions GROUP BY action"):
            out[operator_actions][(str(r["action"]),)] = float(r["n"])
        return out
