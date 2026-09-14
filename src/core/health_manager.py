"""
health_manager.py -- the watchdog/health-manager subsystem (Documentation/
HEALTH_MANAGER_DEPENDENCY_MAP.md has the full design writeup; this is the
implementation).

Runs as one daemon thread, started from main.py before the blocking
pipeline.run() call (same pattern as the existing boot_alert_thread /
ti_engine.start_refresh_thread()). Two independent state machines:

1. Per-component: HEALTHY -> DEGRADED -> UNHEALTHY -> RECOVERY_ATTEMPT -> VERIFY
   -> HEALTHY, or RECOVERY_FAILED -> SAFE_MODE (after RecoveryBackoff is
   exhausted) -> HEALTHY once a later check passes on its own.
2. Resource pressure: NORMAL -> RESOURCE_PRESSURE -> CONSERVATION -> CRITICAL,
   escalating to a proactive self-restart if CRITICAL sustains for
   health_manager_critical_sustain_checks consecutive cycles -- the direct fix
   for the 2026-09-14 OOM incident this subsystem was built in response to.

Fails safe throughout: every check/action is wrapped in try/except inside
_check_cycle()/_run_loop(), so a bug in ANY single check can never crash or
block the main pipeline this thread shares a process with.
"""
import gc
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from core.backoff import RecoveryBackoff
from core.heartbeat import HEARTBEATS, read_component_heartbeats
from core.healing_actions import ACTIONS

LOGGER = logging.getLogger("home_ids.health_manager")

# --- per-component state machine states ---
HEALTHY = "healthy"
DEGRADED = "degraded"
UNHEALTHY = "unhealthy"
RECOVERY_FAILED = "recovery_failed"
SAFE_MODE = "safe_mode"

# --- resource-pressure states ---
NORMAL = "normal"
RESOURCE_PRESSURE = "resource_pressure"
CONSERVATION = "conservation"
CRITICAL = "critical"
_PRESSURE_ORDER = [NORMAL, RESOURCE_PRESSURE, CONSERVATION, CRITICAL]

_CONSERVATION_OVERRIDE_KEYS = (
    "reactive_capture_spotcheck_enabled",
    "reactive_capture_wired_probe_trigger_enabled",
    "reactive_capture_suricata_enabled",
)

try:
    import psutil
except ImportError:  # pragma: no cover -- exercised only if the dependency is missing
    psutil = None


class HealthManager:
    def __init__(
        self,
        config,
        alert_manager,
        *,
        pipeline=None,
        state_dir: str = "state",
        fastapi_proc=None,
        fastapi_log_file=None,
        scheduler_proc=None,
        scheduler_log_file=None,
        ips_mitigator=None,
    ):
        self.config = config
        self.alert_manager = alert_manager
        self.pipeline = pipeline
        self.state_dir = Path(state_dir)
        self.fastapi_proc = fastapi_proc
        self.fastapi_log_file = fastapi_log_file
        self.scheduler_proc = scheduler_proc
        self.scheduler_log_file = scheduler_log_file
        self.ips_mitigator = ips_mitigator

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._component_state: Dict[str, Dict[str, Any]] = {}
        self._pressure_state: str = NORMAL
        self._pressure_entered_at: float = time.time()
        self._critical_streak: int = 0
        self._alerted_pressure_level: Optional[str] = None
        self._process = psutil.Process() if psutil is not None else None

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        if not bool(self.config.get("health_manager_enabled", True)):
            LOGGER.info("Health manager disabled via config (health_manager_enabled=false).")
            return
        if psutil is None:
            LOGGER.error(
                "psutil is not installed -- resource-pressure monitoring will be "
                "skipped. Component heartbeat checks still run. `pip install psutil`."
            )
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="health_manager")
        self._thread.start()
        LOGGER.info("Health manager thread started.")

    def stop(self) -> None:
        self._running = False

    # ------------------------------------------------------------------ main loop

    def _run_loop(self) -> None:
        while self._running:
            interval = float(self.config.get("health_manager_check_interval_seconds", 15.0))
            if interval <= 0:
                interval = 15.0
            try:
                if bool(self.config.get("health_manager_enabled", True)):
                    self._check_cycle()
            except Exception as exc:
                # Must never crash the pipeline this thread shares a process with --
                # same contract EnginePipeline._identity_reconcile_worker() already
                # honors (pipeline.py:743-758).
                LOGGER.error("Health manager check cycle failed (non-fatal, will retry next interval): %s", exc, exc_info=True)
            time.sleep(interval)

    def _check_cycle(self) -> None:
        self._evaluate_resource_pressure()

        pipeline = self.pipeline
        now = time.time()

        # in-process heartbeat components
        self._evaluate_heartbeat_component(
            "pipeline_main_loop", HEARTBEATS.get("pipeline_main_loop"), now,
            expected_interval=max(2.0, float(self.config.get("poll_interval", 2.0))),
        )
        self._evaluate_heartbeat_component(
            "identity_reconcile_worker", HEARTBEATS.get("identity_reconcile_worker"), now,
            expected_interval=float(self.config.get("identity_reconcile_interval_seconds", 600.0)),
        )
        self._evaluate_heartbeat_component(
            "ti_refresh", HEARTBEATS.get("ti_refresh"), now,
            expected_interval=float(self.config.get("ti_refresh_interval", 3600.0)),
        )

        # cross-process heartbeat components (self-reported via file)
        cross_process = read_component_heartbeats(self.state_dir)
        self._evaluate_heartbeat_component(
            "api_subprocess", cross_process.get("api_subprocess"), now, expected_interval=10.0,
        )
        self._evaluate_heartbeat_component(
            "scheduler_subprocess", cross_process.get("scheduler_subprocess"), now, expected_interval=60.0,
        )

        # probe-based components (no self-reported heartbeat -- checked directly,
        # reusing the exact same real checks main.py's boot-time alert already does)
        self._evaluate_probe_component("zeek", self._check_zeek_freshness())
        self._evaluate_probe_component("suricata", self._check_suricata())
        self._evaluate_probe_component("pihole", self._check_pihole())

        # read-only classification off existing files -- never re-alerts what
        # feed_health.py/job_health.json's own consumers already alert on
        self._evaluate_feed_health_components()
        self._evaluate_job_health_components(now)

    # ------------------------------------------------------------- component probes

    def _check_zeek_freshness(self) -> Tuple[bool, str]:
        """Same check as main.py's boot-time alert (main.py:427-436), factored
        out so it can run on a repeating interval instead of once."""
        try:
            zeek_dir = Path(self.config.get("zeek_log_dir", "/opt/zeek/logs/current"))
            if not zeek_dir.exists():
                return False, f"log dir not found at {zeek_dir}"
            recent = any((time.time() - f.stat().st_mtime) < 3600 for f in zeek_dir.glob("*.log"))
            return (True, "producing recent logs") if recent else (False, "log dir exists but no recent (<1h) activity")
        except Exception as exc:
            return False, f"error ({exc})"

    def _check_suricata(self) -> Tuple[bool, str]:
        if not bool(self.config.get("reactive_capture_suricata_enabled", True)):
            return True, "disabled"  # a disabled optional feature isn't unhealthy
        try:
            from intelligence.detectors.suricata_scan import check_suricata_health
            return check_suricata_health(
                self.config.get("reactive_capture_suricata_bin", "/usr/bin/suricata"),
                self.config.get("reactive_capture_suricata_rules_path", ""),
            )
        except Exception as exc:
            return False, f"error ({exc})"

    def _check_pihole(self) -> Tuple[bool, str]:
        if self.ips_mitigator is None:
            return True, "not wired to a live ips_mitigator"
        try:
            return self.ips_mitigator.check_pihole_health()
        except Exception as exc:
            return False, f"error ({exc})"

    # ------------------------------------------------------------- resource pressure

    def _rss_mb(self) -> float:
        if self._process is None:
            return 0.0
        try:
            return self._process.memory_info().rss / (1024 * 1024)
        except Exception:
            return 0.0

    def _classify_pressure(self) -> str:
        if psutil is None:
            return NORMAL
        rss_mb = self._rss_mb()
        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
        except Exception:
            return NORMAL

        sysmem_pct = vm.percent
        swap_pct = swap.percent
        available_mb = vm.available / (1024 * 1024)

        if (
            rss_mb >= float(self.config.get("health_manager_rss_critical_mb", 1843))
            or swap_pct >= float(self.config.get("health_manager_swap_critical_pct", 80))
            or available_mb < float(self.config.get("health_manager_min_available_mb", 512))
        ):
            return CRITICAL
        if (
            rss_mb >= float(self.config.get("health_manager_rss_conservation_mb", 1536))
            or swap_pct >= float(self.config.get("health_manager_swap_conservation_pct", 60))
            or sysmem_pct >= 85
        ):
            return CONSERVATION
        if (
            rss_mb >= float(self.config.get("health_manager_rss_pressure_mb", 1024))
            or swap_pct >= float(self.config.get("health_manager_swap_pressure_pct", 40))
            or sysmem_pct >= float(self.config.get("health_manager_sysmem_pressure_pct", 75))
        ):
            return RESOURCE_PRESSURE
        return NORMAL

    def _evaluate_resource_pressure(self) -> None:
        if psutil is None:
            return
        now = time.time()
        new_level = self._classify_pressure()
        old_level = self._pressure_state

        if new_level == CRITICAL:
            self._critical_streak += 1
        else:
            self._critical_streak = 0

        if new_level != old_level:
            self._pressure_state = new_level
            self._pressure_entered_at = now
            self._apply_pressure_level(new_level)
            if new_level in (CONSERVATION, CRITICAL) or (new_level == RESOURCE_PRESSURE and self._alerted_pressure_level != RESOURCE_PRESSURE):
                self._send_pressure_alert(new_level, escalating=(_PRESSURE_ORDER.index(new_level) > _PRESSURE_ORDER.index(old_level)))
        elif new_level == NORMAL and self._alerted_pressure_level not in (None, NORMAL):
            # Fully recovered -- one confirmation alert, then stop repeating.
            self._send_pressure_alert(NORMAL, escalating=False)

        if new_level == CRITICAL and self._critical_streak >= int(self.config.get("health_manager_critical_sustain_checks", 3)):
            self._trigger_critical_self_restart()

    def _send_pressure_alert(self, level: str, escalating: bool) -> None:
        self._alerted_pressure_level = level
        if self.alert_manager is None or not bool(self.config.get("telegram_enabled", False)):
            return
        rss = self._rss_mb()
        icon = {"normal": "✅", "resource_pressure": "⚠️", "conservation": "🟠", "critical": "🔴"}.get(level, "⚠️")
        try:
            self.alert_manager.send(
                f"{icon} *Health Manager: resource pressure -> {level.upper()}* "
                f"(rss={rss:.0f}MB)"
            )
        except Exception:
            pass

    def _apply_pressure_level(self, level: str) -> None:
        """The concrete degradation levers for each pressure tier. Each tier
        includes everything the tiers below it already did (RESOURCE_PRESSURE's
        actions stay applied through CONSERVATION/CRITICAL too)."""
        idx = _PRESSURE_ORDER.index(level)

        # RESOURCE_PRESSURE+: pause TI enrichment (the only lever available --
        # otx_api_key/abuseipdb_api_key/virustotal_api_key are all _STATIC_KEYS,
        # immune to the live config-override channel; these are in-process flags
        # on the already-constructed client objects instead).
        pause_ti = idx >= _PRESSURE_ORDER.index(RESOURCE_PRESSURE)
        if self.pipeline is not None:
            for attr in ("ti_engine", "abuseipdb", "virustotal"):
                client = getattr(self.pipeline, attr, None)
                if client is not None:
                    client.paused = pause_ti
            if pause_ti:
                try:
                    gc.collect()
                except Exception:
                    pass

        # CONSERVATION+: disable the memory/CPU-hungry reactive-capture triggers
        # via the existing, genuinely-live config-override channel (none of
        # these three keys are in _STATIC_KEYS).
        conserve = idx >= _PRESSURE_ORDER.index(CONSERVATION)
        for key in _CONSERVATION_OVERRIDE_KEYS:
            if conserve:
                self._set_config_override(key, False)
            else:
                self._clear_config_override(key)

        if self.pipeline is not None:
            self.pipeline._health_pressure_poll_floor = 10.0 if conserve else None

    def _trigger_critical_self_restart(self) -> None:
        if not bool(self.config.get("health_manager_auto_recovery_enabled", True)):
            LOGGER.critical(
                "Sustained CRITICAL memory pressure but health_manager_auto_recovery_enabled "
                "is false -- not self-restarting. Manual intervention needed."
            )
            return
        ACTIONS["resource_pressure"](self, "resource_pressure")

    # --------------------------------------------------------- config-override helper

    def _set_config_override(self, key: str, value: Any) -> None:
        """Same read-modify-write shape as middleware/routers/config_api.py's own
        _set_override() -- kept as a small local copy rather than importing that
        module (which would pull fastapi/pydantic into the main pipeline process
        and create a core/ -> middleware/ dependency that doesn't exist anywhere
        else in this codebase) since this is the one place core/ needs the same
        effect without the HTTP layer around it."""
        try:
            overrides_path = self.config._overrides_path
            data = {}
            if overrides_path.exists():
                data = json.loads(overrides_path.read_text(encoding="utf-8"))
            existing = data.get(key)
            baseline = existing["baseline"] if isinstance(existing, dict) and "baseline" in existing else self.config.get(key)
            data[key] = {"value": value, "baseline": baseline, "set_at": time.time(), "set_by": "health_manager", "reason": "resource pressure"}
            overrides_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = overrides_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(overrides_path)
            self.config._load_overrides()
        except Exception as exc:
            LOGGER.warning("Health manager failed to set config override %s=%s: %s", key, value, exc)

    def _clear_config_override(self, key: str) -> None:
        try:
            overrides_path = self.config._overrides_path
            if not overrides_path.exists():
                return
            data = json.loads(overrides_path.read_text(encoding="utf-8"))
            entry = data.pop(key, None)
            if entry is None:
                return
            tmp = overrides_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
            tmp.replace(overrides_path)
            baseline = entry.get("baseline") if isinstance(entry, dict) else None
            self.config.revert_override(key, baseline)
        except Exception as exc:
            LOGGER.warning("Health manager failed to clear config override %s: %s", key, exc)

    # ------------------------------------------------------------- state machine

    def _get_record(self, component: str) -> Dict[str, Any]:
        rec = self._component_state.get(component)
        if rec is None:
            rec = {
                "state": HEALTHY,
                "backoff": RecoveryBackoff(int(self.config.get("health_manager_recovery_max_attempts", 5))),
                "alerted_safe_mode": False,
            }
            self._component_state[component] = rec
        return rec

    def _evaluate_heartbeat_component(self, component: str, entry: Optional[Dict[str, Any]], now: float, expected_interval: float) -> None:
        if entry is None:
            # Never seen a heartbeat yet -- grace period, don't alarm on a cold boot.
            return
        age = now - float(entry.get("last_heartbeat", now))
        if age < 2 * expected_interval:
            signal, detail = HEALTHY, f"heartbeat age {age:.0f}s"
        elif age < 5 * expected_interval:
            signal, detail = DEGRADED, f"heartbeat age {age:.0f}s (expected ~{expected_interval:.0f}s)"
        else:
            signal, detail = UNHEALTHY, f"heartbeat stale for {age:.0f}s (expected ~{expected_interval:.0f}s)"
        self._apply_signal(component, signal, detail)

    def _evaluate_probe_component(self, component: str, result: Tuple[bool, str]) -> None:
        ok, detail = result
        rec = self._get_record(component)
        fail_streak = rec.get("probe_fail_streak", 0)
        if ok:
            rec["probe_fail_streak"] = 0
            self._apply_signal(component, HEALTHY, detail)
            return
        fail_streak += 1
        rec["probe_fail_streak"] = fail_streak
        signal = DEGRADED if fail_streak < 3 else UNHEALTHY
        self._apply_signal(component, signal, detail)

    def _evaluate_feed_health_components(self) -> None:
        path = self.state_dir / "feed_health.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        for feed_name, entry in data.items():
            if not isinstance(entry, dict):
                continue
            failures = int(entry.get("consecutive_failures", 0) or 0)
            category = entry.get("category", "external_infra")
            component = f"feed:{feed_name}"
            if failures == 0:
                self._apply_signal(component, HEALTHY, "no recent failures")
            elif category == "auth_expired":
                self._apply_signal(component, UNHEALTHY, "auth failure -- needs a credential fix")
            elif category == "rate_limited":
                self._apply_signal(component, DEGRADED, f"{failures} consecutive rate-limit responses")
            else:
                signal = DEGRADED if failures < 3 else UNHEALTHY
                self._apply_signal(component, signal, f"{failures} consecutive failures")

    def _evaluate_job_health_components(self, now: float) -> None:
        path = self.state_dir / "job_health.json"
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        staleness_hours = float(self.config.get("health_manager_job_staleness_hours", 30.0))
        for job_name, entry in data.items():
            if not isinstance(entry, dict):
                continue
            last_success = float(entry.get("last_success", 0) or 0)
            age_hours = (now - last_success) / 3600.0
            component = f"job:{job_name}"
            if age_hours < staleness_hours:
                self._apply_signal(component, HEALTHY, f"last success {age_hours:.1f}h ago")
            else:
                self._apply_signal(component, DEGRADED, f"no success in {age_hours:.1f}h (expected within {staleness_hours:.0f}h)")

    def _apply_signal(self, component: str, signal: str, detail: str) -> None:
        rec = self._get_record(component)
        prev_state = rec["state"]
        backoff: RecoveryBackoff = rec["backoff"]

        if prev_state == SAFE_MODE:
            if signal == HEALTHY:
                rec["state"] = HEALTHY
                rec["alerted_safe_mode"] = False
                backoff.reset()
                self._alert(f"✅ *Health Manager*: `{component}` recovered on its own -- exiting SAFE_MODE.")
            return  # SAFE_MODE otherwise sits still -- no further auto action, by design

        if signal == HEALTHY:
            if prev_state != HEALTHY:
                LOGGER.info("Health manager: %s recovered -> HEALTHY (%s)", component, detail)
                backoff.reset()
            rec["state"] = HEALTHY
            return

        if signal == DEGRADED:
            if prev_state == HEALTHY:
                LOGGER.warning("Health manager: %s -> DEGRADED (%s)", component, detail)
            rec["state"] = DEGRADED
            return

        # signal == UNHEALTHY
        if prev_state != UNHEALTHY and prev_state != RECOVERY_FAILED:
            LOGGER.error("Health manager: %s -> UNHEALTHY (%s)", component, detail)
        rec["state"] = UNHEALTHY
        self._maybe_recover(component, rec, detail)

    def _maybe_recover(self, component: str, rec: Dict[str, Any], detail: str) -> None:
        if not bool(self.config.get("health_manager_auto_recovery_enabled", True)):
            return
        action = ACTIONS.get(component)
        if action is None:
            return  # alert-only component (zeek/suricata/pihole/feeds/jobs) -- no lever exists
        backoff: RecoveryBackoff = rec["backoff"]
        if not backoff.attempt_allowed():
            if backoff.exhausted() and not rec.get("alerted_safe_mode"):
                rec["state"] = SAFE_MODE
                rec["alerted_safe_mode"] = True
                self._alert(
                    f"🚨 *Health Manager*: `{component}` failed to recover after "
                    f"{backoff.attempt_count} attempts ({detail}). Entering SAFE_MODE -- "
                    f"needs a human. Auto-recovery for this component is paused until it "
                    f"reports healthy on its own."
                )
            return

        backoff.record_attempt()
        LOGGER.warning("Health manager: attempting recovery for %s (attempt %d)", component, backoff.attempt_count)
        try:
            success, action_detail = action(self, component)
        except Exception as exc:
            success, action_detail = False, f"action raised: {exc}"

        if success:
            LOGGER.info("Health manager: recovery action for %s succeeded (%s) -- verifying", component, action_detail)
            rec["state"] = HEALTHY  # optimistic; next cycle's own fresh signal will correct this if verification fails
            self._alert(f"🔧 *Health Manager*: recovery action for `{component}` completed ({action_detail}).")
        else:
            rec["state"] = RECOVERY_FAILED
            LOGGER.error("Health manager: recovery action for %s failed (%s)", component, action_detail)

    def _alert(self, message: str) -> None:
        if self.alert_manager is None or not bool(self.config.get("telegram_enabled", False)):
            return
        try:
            self.alert_manager.send(message)
        except Exception:
            pass

    # ------------------------------------------------------------- read-only snapshot

    def snapshot(self) -> Dict[str, Any]:
        """Everything /api/health/status needs -- called from the SAME process
        this HealthManager lives in only (the console API subprocess reads the
        heartbeat/job/feed files directly instead, since it can't reach this
        live instance across the process boundary)."""
        return {
            "pressure_level": self._pressure_state,
            "rss_mb": self._rss_mb(),
            "components": {
                name: {"state": rec["state"], "recovery_attempts": rec["backoff"].attempt_count}
                for name, rec in self._component_state.items()
            },
        }
