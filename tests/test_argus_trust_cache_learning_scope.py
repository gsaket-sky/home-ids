"""
The CL-AFPE trust cache can never hide a threat during learning (master TODO M2, 2026-10-04).

Two independent guards:
  1. ThreatIntel.is_allowlisted() step 3: a trust-cache entry shields a name only from suffix matches and weak
     indicators. An activated feed's strong hit (confidence >= 0.5) on the name, or on any name up to the trusted
     entry, takes priority -- for every correction source, a person's included.
  2. Network-agnostic, needs no feed: an automatic correction (Stage 1b/2/3, the AI advisor) made for a device in its
     learning period trusts the destination for that device only. It is not in get_dynamic_trust_cache(), so it
     neither shields the name from threat intel nor fast-paths another device's alert. A person's correction stays
     network-wide.

Not part of the pytest suite -- run directly:
`venv/Scripts/python.exe tests/test_argus_trust_cache_learning_scope.py`
"""
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine, TRUST_SCOPE_DEVICE  # noqa: E402
from intelligence.device_familiarity import DeviceFamiliarity  # noqa: E402
from intelligence.threat_intel import ThreatIntel  # noqa: E402
from extractors.dns_features import NOVELTY_MIN_ACTIVE_DAYS, NOVELTY_MIN_ACTIVE_HOURS  # noqa: E402

tmpdir = _PathForSysPath(tempfile.mkdtemp(prefix="trust_scope_test_"))
store = GraphStore(str(tmpdir / "graph.db"))
familiarity = DeviceFamiliarity()
cl_afpe = ClAfpeEngine(store, familiarity=familiarity)

DAY = 86400.0
NOW = time.time() - 3600  # near the wall clock: ThreatIntel reads the trust cache at time.time()

for dev in ("learner", "learner2", "baselined", "bystander"):
    store.upsert_device(dev, timestamp=NOW)

# "baselined": a full learning period of observed activity (days x hours per day, both bars cleared).
hours_per_day = -(-NOVELTY_MIN_ACTIVE_HOURS // NOVELTY_MIN_ACTIVE_DAYS)
for d in range(NOVELTY_MIN_ACTIVE_DAYS):
    for h in range(hours_per_day):
        familiarity.record_device_baseline_observation("baselined", domain_base="x.example",
                                                       now=NOW - (d + 1) * DAY + h * 3600)
# "learner": one active day only.
familiarity.record_device_baseline_observation("learner", domain_base="x.example", now=NOW - DAY)

check("a device with a full learning period of activity is out of it",
      not cl_afpe.device_in_learning_period("baselined"))
check("a device with one active day is in its learning period", cl_afpe.device_in_learning_period("learner"))
check("an unknown device counts as learning (its state cannot be known)", cl_afpe.device_in_learning_period("unknown"))


def _alert(device_id, domain, dest_ip=""):
    return {"signature": "NETWORK_INTRUSION", "device": {"id": device_id, "hostname": device_id},
            "network_context": {"queried_domain": domain, "destination_ip": dest_ip}}


def _edges(dst):
    return store.get_edges(relation="trusts", dst_id=dst)


# --- guard 2: automatic corrections during learning are device-scoped -------------------------------------------

r = cl_afpe.mark_false_positive(_alert("learner", "c2.preexisting-c2.net"), source="autonomous_stage23", now=NOW)
check("an automatic correction for a learning device still immunizes (it is not refused)",
      not r.refused and r.immunized_destination == "preexisting-c2.net")
e = _edges("preexisting-c2.net")
check("... as a device-scoped edge", len(e) == 1 and e[0]["metadata"].get("scope") == TRUST_SCOPE_DEVICE)
check("... which is NOT network-wide trust", "preexisting-c2.net" not in cl_afpe.get_dynamic_trust_cache(now=NOW))
check("... still trusted for the device it was made for",
      cl_afpe.is_trust_cached("preexisting-c2.net", device_id="learner", hypothesis="NETWORK_INTRUSION", now=NOW))
check("... but not for another device (no spread of trust from a learning device)",
      not cl_afpe.is_trust_cached("preexisting-c2.net", device_id="bystander", hypothesis="NETWORK_INTRUSION", now=NOW))

cl_afpe.mark_false_positive(_alert("learner", "x.ai-advised.net"), source="llm_validated", now=NOW)
check("the AI advisor counts as automatic (device-scoped during learning)",
      "ai-advised.net" not in cl_afpe.get_dynamic_trust_cache(now=NOW))

cl_afpe.mark_false_positive(_alert("learner", "cdn.vendor-cloud.net"), source="operator", now=NOW)
check("a person's correction for a learning device is network-wide (the human override)",
      "vendor-cloud.net" in cl_afpe.get_dynamic_trust_cache(now=NOW))

cl_afpe.mark_false_positive(_alert("baselined", "api.normal-vendor.net"), source="autonomous_stage23", now=NOW)
check("an automatic correction for a baselined device is network-wide (unchanged behaviour)",
      "normal-vendor.net" in cl_afpe.get_dynamic_trust_cache(now=NOW))

cl_afpe.mark_false_positive(_alert("unknown", "", dest_ip="203.0.113.7"), source="autonomous_stage23", now=NOW)
e = _edges("203.0.113.7")
check("an automatic correction with no attributable device is device-scoped (to 'unattributed')",
      len(e) == 1 and e[0]["metadata"].get("scope") == TRUST_SCOPE_DEVICE and e[0]["src_id"] == "unattributed")
check("... and matches only unattributed alerts",
      cl_afpe.is_trust_cached("203.0.113.7", device_id="unknown", hypothesis="NETWORK_INTRUSION", now=NOW)
      and not cl_afpe.is_trust_cached("203.0.113.7", device_id="bystander", hypothesis="NETWORK_INTRUSION", now=NOW))

# Scoped refreshes never downgrade or remove other trust.
cl_afpe.mark_false_positive(_alert("learner", "www.normal-vendor.net"), source="autonomous_stage23", now=NOW + 60)
check("a learning device's scoped edge never removes an existing network-wide one",
      "normal-vendor.net" in cl_afpe.get_dynamic_trust_cache(now=NOW + 60))
familiarity.record_device_baseline_observation("learner2", domain_base="x.example", now=NOW - DAY)
cl_afpe.mark_false_positive(_alert("learner2", "c2.preexisting-c2.net"), source="autonomous_stage23", now=NOW + 60)
check("two learning devices keep their own scoped edges (one does not replace the other)",
      cl_afpe.is_trust_cached("preexisting-c2.net", device_id="learner", hypothesis="NETWORK_INTRUSION", now=NOW + 60)
      and cl_afpe.is_trust_cached("preexisting-c2.net", device_id="learner2", hypothesis="NETWORK_INTRUSION",
                                  now=NOW + 60))
is_new = cl_afpe.mark_false_positive(_alert("learner", "c2.preexisting-c2.net"), source="autonomous_stage23",
                                     now=NOW + 120).is_new_immunization
check("refreshing a device's own scoped edge is not a new immunization and does not duplicate it",
      not is_new and sum(1 for x in _edges("preexisting-c2.net") if x["src_id"] == "learner") == 1)
cl_afpe.mark_false_positive(_alert("baselined", "c2.preexisting-c2.net"), source="autonomous_stage23", now=NOW + 180)
e = _edges("preexisting-c2.net")
check("a later network-wide correction replaces the scoped edges with one network-wide edge",
      len(e) == 1 and e[0]["metadata"].get("scope") is None
      and "preexisting-c2.net" in cl_afpe.get_dynamic_trust_cache(now=NOW + 180))

# --- guard 1 + wiring: threat intel honours only network-wide trust, and never over a strong feed hit -----------

ti = ThreatIntel(cache_dir=str(tmpdir / "ti"), et_open_enabled=False)
ti.trust_cache_provider = cl_afpe

check("no domain feed activated: network-wide trust shields the name (unchanged behaviour)",
      ti.is_allowlisted("api.normal-vendor.net") and ti.is_allowlisted("normal-vendor.net"))
check("no domain feed activated: a learning device's scoped trust does NOT shield the name network-wide",
      not ti.is_allowlisted("x.ai-advised.net"))

ti._bad_domains["vendor-cloud.net"] = {"source": "test", "confidence": 0.95}
check("an activated feed's strong hit on the trusted base domain takes priority over a person's trust",
      not ti.is_allowlisted("cdn.vendor-cloud.net") and ti.lookup_domain("cdn.vendor-cloud.net") is not None)

ti._bad_domains["c2.normal-vendor.net"] = {"source": "test", "confidence": 0.9}
check("a strong hit on a subdomain of a trusted base domain takes priority (and lookup reports it)",
      not ti.is_allowlisted("c2.normal-vendor.net") and ti.lookup_domain("c2.normal-vendor.net") is not None)
check("... while sibling names under the same trusted base stay shielded",
      ti.is_allowlisted("api.normal-vendor.net"))

ti._bad_domains["deep.c2.normal-vendor.net"] = {"source": "test", "confidence": 0.3}
ti._bad_domains["telemetry.normal-vendor.net"] = {"source": "test", "confidence": 0.4}
check("a weak indicator on a trusted name is still shielded (trust may hide weak indicators)",
      ti.is_allowlisted("telemetry.normal-vendor.net") and ti.lookup_domain("telemetry.normal-vendor.net") is None)
check("a weak hit on the name does not hide a strong hit on a parent up to the trusted entry",
      not ti.is_allowlisted("deep.c2.normal-vendor.net"))


class _RaisingProvider:
    def get_dynamic_trust_cache(self):
        raise RuntimeError("graph store unavailable")


ti_err = ThreatIntel(cache_dir=str(tmpdir / "ti_err"), et_open_enabled=False)
ti_err.trust_cache_provider = _RaisingProvider()
check("a raising trust-cache provider does not change a static-allowlist verdict",
      ti_err.is_allowlisted("www.google.com"))
check("... and an unlisted name is simply not allowlisted", not ti_err.is_allowlisted("unlisted-example.net"))

store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All trust-cache learning-scope checks PASSED.")
