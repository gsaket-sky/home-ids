"""
core/source_availability.py -- which evidence sources are available right now (DETECTION_CORE_REWORK P0 "capability
registry", section M: "one registry of which sensors/sources are present; every verdict records what was available").

Why: the owner decided (2026-10-14) that threat-intel feeds, AbuseIPDB/VirusTotal, GeoIP/ASN, RDAP and Tranco are optional
and may be off or failing, and that "not checked" never means "clean". A verdict made while a source was down is a
different fact from the same verdict made with it working; the engine and the person reading an alert must be able to
tell. This module answers, per source, one of four states:

    ok           configured and delivering
    degraded     configured but not delivering fully (a stale feed, one of two GeoIP databases, a poll that stopped)
    unavailable  expected but missing (no log directory, no engine, no database, nothing ever recorded)
    disabled     switched off or no key -- a choice, not a fault

Every check is a function over the source's OWN status API, injected -- nothing here names a vendor, an address or a
network, and a check never raises (a failing check reads `unavailable` with the error). The pipeline takes one cached
snapshot per cycle (SourceAvailability.snapshot); it becomes part of the gathered cycle (live_engine.GatheredCycle.sources)
and is recorded on every decision (`_sources`) and alert. The snapshot is also persisted for other processes (the
console), atomically. This module records availability; what a verdict DOES with a missing source (a feed down never
counts as clean) belongs to the layers that consume it.

Hardware gates (capture NIC, LLM RAM) live in core/hardware_capabilities.py and validate real traffic/RAM with their own
cost; they are not part of the per-cycle snapshot.
"""
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

LOGGER = logging.getLogger("home_ids.source_availability")

OK = "ok"
DEGRADED = "degraded"
UNAVAILABLE = "unavailable"
DISABLED = "disabled"
STATES = (OK, DEGRADED, UNAVAILABLE, DISABLED)

DEFAULT_TTL_SECONDS = 30.0
# a component heartbeat older than this means the component stopped delivering (its writers beat at least every 30 s)
HEARTBEAT_STALE_SECONDS = 180.0

Check = Callable[[float], Tuple[str, str]]     # check(now) -> (state, detail)


class SourceAvailability:
    def __init__(self, ttl_seconds: float = DEFAULT_TTL_SECONDS, state_path: Optional[Path] = None):
        self.ttl_seconds = float(ttl_seconds)
        self.state_path = Path(state_path) if state_path else None
        self._checks: Dict[str, Check] = {}
        self._details: Dict[str, Dict[str, Any]] = {}
        self._evaluated_at: Optional[float] = None

    def register(self, name: str, check: Check) -> None:
        self._checks[name] = check

    def _evaluate(self, now: float) -> None:
        previous = self._details
        details: Dict[str, Dict[str, Any]] = {}
        for name, check in self._checks.items():
            try:
                state, detail = check(now)
                if state not in STATES:
                    state, detail = UNAVAILABLE, f"check returned an unknown state {state!r}"
            except Exception as exc:        # a check never raises into the engine
                state, detail = UNAVAILABLE, f"check raised {type(exc).__name__}: {exc}"
            before = previous.get(name, {}).get("state")
            transition = "unchanged" if before in (None, state) else f"{before}->{state}"
            if transition != "unchanged":
                LOGGER.info("Source %r: %s (%s)", name, transition, detail)
            details[name] = {"state": state, "detail": detail, "checked_at": now, "transition": transition}
        self._details = details
        self._evaluated_at = now
        self._persist(details)

    def _persist(self, details: Dict[str, Dict[str, Any]]) -> None:
        if self.state_path is None:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.state_path.with_name(f"{self.state_path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(details, indent=2), encoding="utf-8")
            os.replace(tmp, self.state_path)
        except Exception as exc:            # best effort: the in-memory snapshot is what the engine uses
            LOGGER.debug("could not persist the source snapshot: %s", exc)

    def details(self, now: Optional[float] = None) -> Dict[str, Dict[str, Any]]:
        now = now if now is not None else time.time()
        if self._evaluated_at is None or now - self._evaluated_at >= self.ttl_seconds or now < self._evaluated_at:
            self._evaluate(now)
        return {k: dict(v) for k, v in self._details.items()}

    def snapshot(self, now: Optional[float] = None) -> Dict[str, str]:
        """{source: state}, evaluated at most once per ttl."""
        return {k: v["state"] for k, v in self.details(now).items()}


# ------------------------------------------------------------------------------------------------------ the checks

def _zeek_check(collector) -> Check:
    def check(now):
        if collector is None:
            return UNAVAILABLE, "no collector"
        return (OK, "logs readable") if collector.is_available() else (UNAVAILABLE, "log directory not readable")
    return check


def _heartbeat_check(heartbeats: Callable[[], Mapping[str, Mapping[str, Any]]], component: str,
                     stale_after: float = HEARTBEAT_STALE_SECONDS) -> Check:
    def check(now):
        entry = (heartbeats() or {}).get(component)
        if not entry:
            return UNAVAILABLE, "nothing recorded"
        last = float(entry.get("last_success") or 0.0)
        age = now - last
        if age > stale_after:
            return DEGRADED, f"last success {int(age)} s ago"
        return OK, f"last success {int(max(age, 0))} s ago"
    return check


def _geoip_check(engine) -> Check:
    def check(now):
        if engine is None:
            return UNAVAILABLE, "no GeoIP engine"
        city = getattr(engine, "reader", None) is not None
        asn = getattr(engine, "asn_reader", None) is not None
        fallback = getattr(engine, "iptoasn", None) is not None
        if city and asn:
            return OK, "country and ASN databases loaded"
        if city or asn:
            return DEGRADED, "only one of the country / ASN databases loaded"
        if fallback:
            return DEGRADED, "only the fallback ASN table is loaded"
        return UNAVAILABLE, "no GeoIP database loaded"
    return check


def _feeds_check(engine) -> Check:
    def check(now):
        if engine is None:
            return UNAVAILABLE, "no threat-intel engine"
        ready, reason = engine.check_status(now)
        if ready:
            return OK, "lists loaded and fresh"
        return (DISABLED, "paused") if reason == "paused" else (DEGRADED, reason or "not checked")
    return check


def _client_check(client) -> Check:
    def check(now):
        if client is None:
            return UNAVAILABLE, "no client"
        return (OK, "active") if getattr(client, "active", False) else (DISABLED, "no key or switched off")
    return check


def _reactive_capture_check(config: Mapping[str, Any], dispatcher) -> Check:
    def check(now):
        if not config.get("reactive_capture_enabled", False):
            return DISABLED, "switched off"
        if dispatcher is None:
            return UNAVAILABLE, "no dispatcher"
        if getattr(dispatcher, "disk_degraded", False):
            return DEGRADED, "disk budget exhausted; bursts are deferred"
        return OK, "enabled"
    return check


def _suricata_check(config: Mapping[str, Any], health: Callable[[], Tuple[bool, str]], recheck_seconds: float) -> Check:
    """Suricata only ever scans captured bursts, so it needs reactive capture too. Its health probe runs the binary, so it
    is cached far longer than the 30 s snapshot."""
    cache: Dict[str, Any] = {"at": None, "result": (False, "not probed")}

    def check(now):
        if not config.get("reactive_capture_suricata_enabled", False):
            return DISABLED, "switched off"
        if not config.get("reactive_capture_enabled", False):
            return DISABLED, "reactive capture is off (Suricata only scans captured bursts)"
        if cache["at"] is None or now - cache["at"] >= recheck_seconds or now < cache["at"]:
            cache["result"] = health()
            cache["at"] = now
        healthy, reason = cache["result"]
        return (OK, reason) if healthy else (UNAVAILABLE, reason)
    return check


def _rdap_check(get_service: Callable[[], Any]) -> Check:
    def check(now):
        service = get_service()
        if service is None:
            return UNAVAILABLE, "service not built"
        status = service.status()
        if not status.get("enabled"):
            return DISABLED, "switched off (opt-in)"
        used, cap = int(status.get("used_today") or 0), int(status.get("daily_cap") or 0)
        if cap and used >= cap:
            return DEGRADED, "daily lookup cap reached; new names are not looked up until tomorrow"
        return OK, f"{used}/{cap} lookups today"
    return check


def _tranco_check(engine) -> Check:
    def check(now):
        if engine is None:
            return UNAVAILABLE, "no threat-intel engine"
        status = engine.tranco_status()
        if not status.get("enabled"):
            return DISABLED, "switched off"
        loaded = int(status.get("ranks_loaded") or 0)
        return (OK, f"{loaded} ranks loaded") if loaded else (DEGRADED, "enabled but no list loaded yet")
    return check


def _default_suricata_health(config: Mapping[str, Any]) -> Callable[[], Tuple[bool, str]]:
    def health():
        from intelligence.detectors.suricata_scan import check_suricata_health
        return check_suricata_health(config.get("reactive_capture_suricata_bin", "/usr/bin/suricata"),
                                     config.get("reactive_capture_suricata_rules_path", ""))
    return health


SURICATA_RECHECK_SECONDS = 600.0


def build_source_availability(*, config: Mapping[str, Any], zeek_collector, ti_engine, geoip_engine, abuseipdb,
                              virustotal, heartbeats: Callable[[], Mapping[str, Mapping[str, Any]]],
                              state_dir: Path, ttl_seconds: float = DEFAULT_TTL_SECONDS, reactive_capture=None,
                              rdap: Optional[Callable[[], Any]] = None,
                              suricata_health: Optional[Callable[[], Tuple[bool, str]]] = None) -> SourceAvailability:
    """The registry the engine runs: Zeek, the DNS source (Pi-hole poll), GeoIP, the threat-intel feeds, AbuseIPDB,
    VirusTotal, reactive capture, Suricata, RDAP domain age and Tranco. `heartbeats` returns the cross-process component
    heartbeats (core.heartbeat.read_component_heartbeats); `rdap` returns the RDAP service lazily (it is built after this
    registry); `suricata_health` defaults to the real binary / rules probe."""
    av = SourceAvailability(ttl_seconds=ttl_seconds, state_path=Path(state_dir) / "source_availability.json")
    av.register("zeek", _zeek_check(zeek_collector))
    av.register("pihole", _heartbeat_check(heartbeats, "pihole_poll"))
    av.register("geoip", _geoip_check(geoip_engine))
    av.register("threat_intel", _feeds_check(ti_engine))
    av.register("abuseipdb", _client_check(abuseipdb))
    av.register("virustotal", _client_check(virustotal))
    av.register("reactive_capture", _reactive_capture_check(config, reactive_capture))
    av.register("suricata", _suricata_check(config, suricata_health or _default_suricata_health(config),
                                            SURICATA_RECHECK_SECONDS))
    av.register("rdap", _rdap_check(rdap or (lambda: None)))
    av.register("tranco", _tranco_check(ti_engine))
    return av
