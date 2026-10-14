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

# --- Suricata, reactive capture, RDAP domain age, Tranco (2026-10-14: each from its own status API) -------------------------
def build2(*, config=None, health=(True, "ok"), health_calls=None, capture="ok", rdap="ok", tranco="ok", no_capture=False):
    def health_fn():
        if health_calls is not None:
            health_calls.append(1)
        return health
    dispatcher = None if no_capture else SimpleNamespace(disk_degraded=(capture == "degraded"))
    rdap_obj = {"ok": SimpleNamespace(status=lambda: {"enabled": True, "used_today": 3, "daily_cap": 50}),
                "off": SimpleNamespace(status=lambda: {"enabled": False, "used_today": 0, "daily_cap": 50}),
                "cap": SimpleNamespace(status=lambda: {"enabled": True, "used_today": 50, "daily_cap": 50}),
                "none": None}[rdap]
    tr = {"ok": {"enabled": True, "ranks_loaded": 1000}, "off": {"enabled": False, "ranks_loaded": 0},
          "empty": {"enabled": True, "ranks_loaded": 0}}[tranco]
    ti_e = SimpleNamespace(check_status=lambda now=None: (True, ""), tranco_status=lambda: tr)
    return build_source_availability(
        config=config or {}, zeek_collector=SimpleNamespace(is_available=lambda: True), ti_engine=ti_e,
        geoip_engine=SimpleNamespace(reader=object(), asn_reader=object(), iptoasn=None),
        abuseipdb=SimpleNamespace(active=True), virustotal=SimpleNamespace(active=False),
        heartbeats=lambda: {"pihole_poll": {"last_success": NOW - 10}}, state_dir=tmp,
        reactive_capture=dispatcher, rdap=lambda: rdap_obj, suricata_health=health_fn)


CAP_ON = {"reactive_capture_enabled": True}
SUR_ON = {"reactive_capture_enabled": True, "reactive_capture_suricata_enabled": True}
s2 = states(build2())
check("the new sources are reported", {"suricata", "reactive_capture", "rdap", "tranco"} <= set(s2), str(sorted(s2)))
check("reactive capture switched off (the default) -> disabled", s2["reactive_capture"] == DISABLED, s2["reactive_capture"])
check("reactive capture on and not disk-degraded -> ok", states(build2(config=CAP_ON))["reactive_capture"] == OK)
check("reactive capture on but its disk budget is exhausted -> degraded",
      states(build2(config=CAP_ON, capture="degraded"))["reactive_capture"] == DEGRADED)
check("reactive capture on but no dispatcher -> unavailable", states(build2(config=CAP_ON, no_capture=True))["reactive_capture"] == UNAVAILABLE)
check("suricata off (the default) -> disabled", s2["suricata"] == DISABLED, s2["suricata"])
check("suricata on but reactive capture off (it only ever scans bursts) -> disabled",
      states(build2(config={"reactive_capture_suricata_enabled": True}))["suricata"] == DISABLED)
check("suricata on, binary and rules healthy -> ok", states(build2(config=SUR_ON))["suricata"] == OK)
check("suricata on but the health probe fails -> unavailable, with the reason",
      states(build2(config=SUR_ON, health=(False, "binary not found")))["suricata"] == UNAVAILABLE
      and "binary not found" in build2(config=SUR_ON, health=(False, "binary not found")).details(NOW)["suricata"]["detail"])
calls = []
av = build2(config=SUR_ON, health_calls=calls)
for dt in (0, 31, 100, 500):
    av.snapshot(NOW + dt)
check("the suricata probe (a subprocess) runs at most every 10 minutes, not on every 30 s snapshot", len(calls) == 1, str(len(calls)))
av.snapshot(NOW + 700)
check("... and again after that", len(calls) == 2, str(len(calls)))
calls2 = []
build2(config={}, health_calls=calls2).snapshot(NOW)
check("a disabled suricata never runs its probe", calls2 == [])
check("rdap switched off (the opt-in default) -> disabled", states(build2(rdap="off"))["rdap"] == DISABLED)
check("rdap on and under its cap -> ok", states(build2(rdap="ok"))["rdap"] == OK)
check("rdap at its daily cap -> degraded (new names are not looked up until tomorrow)", states(build2(rdap="cap"))["rdap"] == DEGRADED)
check("rdap service not built -> unavailable", states(build2(rdap="none"))["rdap"] == UNAVAILABLE)
check("tranco switched off (the default) -> disabled", states(build2(tranco="off"))["tranco"] == DISABLED)
check("tranco on with its ranks loaded -> ok", states(build2())["tranco"] == OK)
check("tranco on but nothing loaded yet -> degraded", states(build2(tranco="empty"))["tranco"] == DEGRADED)
check("a caller that passes none of the new inputs still builds (older call sites)",
      "rdap" in states(build_source_availability(config={}, zeek_collector=None, ti_engine=None, geoip_engine=None,
                                                 abuseipdb=None, virustotal=None, heartbeats=lambda: {}, state_dir=tmp)))

print("SOURCE AVAILABILITY", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
