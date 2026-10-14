"""
The source-availability registry (DETECTION_CORE_REWORK P0 "capability registry"; section M: "one registry of which
sensors/sources are present; every verdict records what was available"). Owner decisions 2026-10-14: threat-intel feeds,
AbuseIPDB/VirusTotal and GeoIP are optional everywhere and may be off or failing; "not checked" is never "clean".

core/source_availability.py answers, per source, one of four states -- ok / degraded (configured but not delivering) /
unavailable (expected, missing) / disabled (switched off or no key) -- from the sources' own status APIs, injected, so
nothing here names a vendor, an address or a network. The pipeline takes one snapshot per cycle; it becomes part of the
gathered cycle and is recorded on every decision (`_sources`) and on every alert.

Run directly: `python tests/test_source_availability.py`
"""
import sys
import tempfile
import time
from pathlib import Path as _P
from types import SimpleNamespace

sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.source_availability import (  # noqa: E402
    DEGRADED, DISABLED, OK, UNAVAILABLE, SourceAvailability, build_source_availability,
)

NOW = 1_700_000_000.0
tmp = _P(tempfile.mkdtemp(prefix="source_avail_"))


def build(*, config=None, zeek=True, ti=(True, ""), geo="both", abuse=True, vt=False, hb=None, no_ti=False,
          no_geo=False, no_zeek=False):
    zeek_c = None if no_zeek else SimpleNamespace(is_available=lambda: zeek)
    ti_e = None if no_ti else SimpleNamespace(check_status=lambda now=None: ti)
    geo_e = None if no_geo else SimpleNamespace(
        reader=object() if geo in ("both", "city") else None, asn_reader=object() if geo in ("both", "asn") else None,
        iptoasn=object() if geo == "iptoasn" else None)
    return build_source_availability(
        config=config or {}, zeek_collector=zeek_c, ti_engine=ti_e, geoip_engine=geo_e,
        abuseipdb=SimpleNamespace(active=abuse), virustotal=SimpleNamespace(active=vt),
        heartbeats=lambda: (hb if hb is not None else {"pihole_poll": {"last_success": NOW - 10}}),
        state_dir=tmp)


def states(av, now=NOW):
    return av.snapshot(now)


# --- every source has a state, from its own signal -------------------------------------------------------------------
s = states(build())
check("all expected sources are reported", {"zeek", "pihole", "geoip", "threat_intel", "abuseipdb", "virustotal"} <= set(s),
      str(sorted(s)))
check("a working setup: zeek, pihole, geoip, threat intel and the keyed client are ok",
      all(s[k] == OK for k in ("zeek", "pihole", "geoip", "threat_intel", "abuseipdb")), str(s))
check("a client with no key / switched off is disabled, not unavailable", s["virustotal"] == DISABLED, s["virustotal"])

check("zeek logs not readable -> unavailable", states(build(zeek=False))["zeek"] == UNAVAILABLE)
check("no zeek collector at all -> unavailable", states(build(no_zeek=True))["zeek"] == UNAVAILABLE)
check("no Pi-hole poll ever recorded -> unavailable", states(build(hb={}))["pihole"] == UNAVAILABLE)
check("a Pi-hole poll that stopped 10 minutes ago -> degraded",
      states(build(hb={"pihole_poll": {"last_success": NOW - 600}}))["pihole"] == DEGRADED)
check("feeds stale / empty / not loaded -> degraded (a 'no match' is not a clean check)",
      all(states(build(ti=(False, why)))["threat_intel"] == DEGRADED for why in ("stale", "empty", "not loaded")))
check("feeds paused by the operator -> disabled", states(build(ti=(False, "paused")))["threat_intel"] == DISABLED)
check("no feed engine -> unavailable", states(build(no_ti=True))["threat_intel"] == UNAVAILABLE)
check("GeoIP with no database -> unavailable (optional: nothing breaks, it is just recorded)",
      states(build(geo="none"))["geoip"] == UNAVAILABLE)
check("GeoIP with only one of its databases -> degraded", states(build(geo="asn"))["geoip"] == DEGRADED
      and states(build(geo="city"))["geoip"] == DEGRADED)
check("GeoIP served by the fallback ASN table only -> degraded", states(build(geo="iptoasn"))["geoip"] == DEGRADED)
check("no GeoIP engine -> unavailable", states(build(no_geo=True))["geoip"] == UNAVAILABLE)

# --- a failing check never raises and never reads as ok ---------------------------------------------------------------
av = SourceAvailability(state_path=tmp / "sa_boom.json")
av.register("boom", lambda now: (_ for _ in ()).throw(RuntimeError("check exploded")))
av.register("fine", lambda now: (OK, "fine"))
snap = av.snapshot(NOW)
check("a check that raises is reported unavailable with the error; the others still report",
      snap == {"boom": UNAVAILABLE, "fine": OK}, str(snap))

# --- cached: one evaluation per ttl; detail and transitions ----------------------------------------------------------
calls = []
av = SourceAvailability(ttl_seconds=30.0, state_path=tmp / "sa_cache.json")
av.register("x", lambda now: calls.append(1) or (OK, "d"))
av.snapshot(NOW)
av.snapshot(NOW + 29)
check("the snapshot is cached for its ttl (one evaluation)", len(calls) == 1, str(len(calls)))
av.snapshot(NOW + 31)
check("and re-evaluated after it", len(calls) == 2)
check("details carry the reason and when it was checked",
      av.details(NOW + 31)["x"]["detail"] == "d" and av.details(NOW + 31)["x"]["state"] == OK)

state = {"v": OK}
av = SourceAvailability(ttl_seconds=0.5, state_path=tmp / "sa_trans.json")
av.register("y", lambda now: (state["v"], "d"))
av.snapshot(NOW)
state["v"] = UNAVAILABLE
d1 = av.details(NOW + 1)["y"]          # one evaluation: the change since the previous one
check("a state change is reported as a transition (ok -> unavailable)", d1["transition"] == "ok->unavailable", str(d1))
d2 = av.details(NOW + 2)["y"]
check("no change is 'unchanged'", d2["transition"] == "unchanged", str(d2))

# the snapshot is persisted for other processes (the console), atomically
import json  # noqa: E402
persisted = json.loads((tmp / "sa_trans.json").read_text(encoding="utf-8"))
check("the snapshot is written for other processes", persisted["y"]["state"] == UNAVAILABLE)

print("SOURCE AVAILABILITY", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
