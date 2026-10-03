"""
resource_gate.py -- "is there room to start one more scheduled subprocess job right
now" signal for scripts/scheduler.py (a separate OS process).

Deliberately independent from health_manager.py's own pressure classifier: that one
answers "is THIS process itself in danger" (tuned against this process's own RSS,
sustained-check debouncing, and a destructive self-restart consequence) -- a different
question, with different tuning needs, from "should a new batch job be admitted." Reusing
health_manager's tiers/thresholds directly would couple two decisions that failed for
unrelated reasons before (see health_manager.py's own BUGFIX #1/#2 comments) and risks
destabilizing that already-hardened, incident-scarred logic by feeding it a second
consumer with different requirements. This module reads the same cgroup accounting
files (a plain fact about the shared cgroup every job subprocess also runs in, not
something owned by health_manager) plus a genuinely new signal: system CPU load average,
which nothing in this codebase measures today.

Deliberately minimal imports (no config.py, no fastapi) so this can be imported from
scripts/scheduler.py without pulling in the full engine -- same reasoning
scripts/scheduler.py already documents for reading config.yaml directly.
"""
import os
from pathlib import Path
from typing import Optional

try:
    import psutil
except ImportError:
    psutil = None

NORMAL = "normal"
RESOURCE_PRESSURE = "resource_pressure"
CONSERVATION = "conservation"
CRITICAL = "critical"
_TIER_ORDER = [NORMAL, RESOURCE_PRESSURE, CONSERVATION, CRITICAL]


def _tier_rank(tier: str) -> int:
    try:
        return _TIER_ORDER.index(tier)
    except ValueError:
        return 0


def cgroup_memory_pct() -> Optional[float]:
    """Same sysfs read health_manager.py's own _cgroup_memory_pct() uses (see that
    method's docstring for why memory.current/memory.max is the authoritative number,
    not summed process RSS) -- duplicated here deliberately rather than imported, so
    this module has zero dependency on health_manager.py's instance state and can be
    called from a standalone script process. Returns None if unreadable (Windows dev
    environment, cgroup v1, non-systemd deployment, or no cap set) -- callers must
    treat that as "no signal", never as "healthy"."""
    try:
        cgroup_line = Path("/proc/self/cgroup").read_text(encoding="utf-8").strip()
        rel_path = cgroup_line.split("::", 1)[1].lstrip("/")
        base = Path("/sys/fs/cgroup") / rel_path
        current = int((base / "memory.current").read_text().strip())
        max_raw = (base / "memory.max").read_text().strip()
        if max_raw == "max":
            return None
        max_bytes = int(max_raw)
        if max_bytes <= 0:
            return None
        return 100.0 * current / max_bytes
    except Exception:
        return None


def load_per_core() -> Optional[float]:
    """1-minute load average divided by CPU count -- e.g. 1.0 means "as busy as all
    cores can sustain", not an absolute thread count. The signal genuinely missing
    from this codebase today (health_manager.py tracks memory/swap only). None if
    unavailable (Windows dev environment, or os.cpu_count() returns None)."""
    try:
        load1, _, _ = os.getloadavg()
        cpu_count = os.cpu_count()
        if not cpu_count:
            return None
        return load1 / cpu_count
    except (OSError, AttributeError):
        return None


def get_job_pressure_tier(config: dict) -> str:
    """Classifies current system business into the same four tier NAMES
    health_manager.py uses (NORMAL/RESOURCE_PRESSURE/CONSERVATION/CRITICAL) for
    operator familiarity, but with independently-tuned thresholds and inputs (cgroup
    memory % + CPU load-per-core) -- see this module's own docstring for why these
    are not shared with health_manager's thresholds. Best-effort: any missing signal
    is simply not used as an escalation trigger, never treated as "healthy" on its
    own but also never blocks job admission just because a probe is unavailable
    (e.g. local dev on Windows) -- same philosophy as every other bounded probe in
    this codebase (best-effort, degrade gracefully, never hang or crash the caller)."""
    cgroup_pct = cgroup_memory_pct()
    load_ratio = load_per_core()

    cgroup_critical = float(config.get("job_gate_cgroup_critical_pct", 90))
    cgroup_conservation = float(config.get("job_gate_cgroup_conservation_pct", 75))
    cgroup_pressure = float(config.get("job_gate_cgroup_pressure_pct", 60))
    load_critical = float(config.get("job_gate_load_per_core_critical", 2.0))
    load_conservation = float(config.get("job_gate_load_per_core_conservation", 1.5))
    load_pressure = float(config.get("job_gate_load_per_core_pressure", 1.0))

    if (cgroup_pct is not None and cgroup_pct >= cgroup_critical) or (
        load_ratio is not None and load_ratio >= load_critical
    ):
        return CRITICAL
    if (cgroup_pct is not None and cgroup_pct >= cgroup_conservation) or (
        load_ratio is not None and load_ratio >= load_conservation
    ):
        return CONSERVATION
    if (cgroup_pct is not None and cgroup_pct >= cgroup_pressure) or (
        load_ratio is not None and load_ratio >= load_pressure
    ):
        return RESOURCE_PRESSURE
    return NORMAL


def may_admit_new_job(config: dict) -> bool:
    """True if current pressure is at or below the configured admission ceiling
    (default RESOURCE_PRESSURE -- a new job may start under light pressure, but not
    once the system is in CONSERVATION or CRITICAL)."""
    ceiling = str(config.get("job_admission_max_pressure_tier", RESOURCE_PRESSURE)).lower()
    return _tier_rank(get_job_pressure_tier(config)) <= _tier_rank(ceiling)
