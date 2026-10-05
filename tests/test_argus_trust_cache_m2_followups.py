"""
CL-AFPE trust cache, M2 follow-ups to PR #3 (master TODO M2, 2026-10-05):

1. A domain the popularity learning-adoption ledger marks as learning-only (every device that used it first used it
   during its own learning period) never gets network-wide trust from an automatic correction, even once the
   correcting device has left its learning period.
2. DEVICE_SCOPED_TRUST_HYPOTHESES (DNS_EVASION etc.) edges are left out of the network-wide trust cache.
3. ThreatIntel step 3 forms the base domain with etld1_strict (a.example.co.uk -> example.co.uk), the same base
   CL-AFPE immunizes.

Not part of the pytest suite -- run directly:
`venv/Scripts/python.exe tests/test_argus_trust_cache_m2_followups.py`
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
from intelligence.local_popularity import LocalPopularity  # noqa: E402
from intelligence.threat_intel import ThreatIntel  # noqa: E402
from extractors.dns_features import NOVELTY_MIN_ACTIVE_DAYS, NOVELTY_MIN_ACTIVE_HOURS  # noqa: E402
from utils import etld1  # noqa: E402

tmpdir = _PathForSysPath(tempfile.mkdtemp(prefix="trust_m2_followups_"))
DAY = 86400.0
NOW = time.time() - 3600  # near the wall clock: ThreatIntel reads the trust cache at time.time()

# --- the ledger itself: LocalPopularity.is_learning_only ----------------------------------------------------------

learning_now = {"cam", "tv"}
clock = [NOW - 10 * DAY]
pop = LocalPopularity(tmpdir / "pop.db", etld1_fn=etld1, now_fn=lambda: clock[0],
                      learning_fn=lambda d: d in learning_now)
pop.observe("cam", "c2.learning-only.net")
pop.observe("tv", "beacon.learning-only.net")
pop.observe("cam", "api.shared-vendor.net")
pop.observe("laptop", "api.shared-vendor.net")      # out of learning when it adopted the name
pop.flush()
check("ledger: a name only learning-period devices adopted is learning-only",
      pop.is_learning_only("learning-only.net") is True)
check("ledger: a name a baselined device adopted outside its learning period is not",
      pop.is_learning_only("shared-vendor.net") is False)
check("ledger: an unrecorded name is unknown (None)", pop.is_learning_only("never-seen.net") is None)

learning_now.clear()                                 # both devices leave their learning period
clock[0] = NOW
pop._history_cache.clear()
pop._learning_memo.clear()
pop.observe("cam", "c2.learning-only.net")
pop.flush()
check("ledger: adoption status is fixed at first use (still learning-only after the devices leave learning)",
      pop.is_learning_only("learning-only.net") is True)

# --- 1. engine: learning-only domains stay device-scoped ----------------------------------------------------------

store = GraphStore(str(tmpdir / "graph.db"))
familiarity = DeviceFamiliarity()
cl_afpe = ClAfpeEngine(store, familiarity=familiarity, popularity=pop)
for dev in ("cam", "laptop", "bystander"):
    store.upsert_device(dev, timestamp=NOW)
hours_per_day = -(-NOVELTY_MIN_ACTIVE_HOURS // NOVELTY_MIN_ACTIVE_DAYS)
for dev in ("cam", "laptop"):
    for d in range(NOVELTY_MIN_ACTIVE_DAYS):
        for h in range(hours_per_day):
            familiarity.record_device_baseline_observation(dev, domain_base="x.example",
                                                           now=NOW - (d + 1) * DAY + h * 3600)
check("setup: cam and laptop are out of their learning periods",
      not cl_afpe.device_in_learning_period("cam") and not cl_afpe.device_in_learning_period("laptop"))


def _alert(device_id, domain, dest_ip="", signature="NETWORK_INTRUSION"):
    return {"signature": signature, "device": {"id": device_id, "hostname": device_id},
            "network_context": {"queried_domain": domain, "destination_ip": dest_ip}}


cl_afpe.mark_false_positive(_alert("cam", "c2.learning-only.net"), source="autonomous_stage23", now=NOW)
e = store.get_edges(relation="trusts", dst_id="learning-only.net")
check("an automatic correction on a learning-only domain is device-scoped, even for a baselined device",
      len(e) == 1 and e[0]["metadata"].get("scope") == TRUST_SCOPE_DEVICE and e[0]["src_id"] == "cam")
check("... so it is not network-wide trust", "learning-only.net" not in cl_afpe.get_dynamic_trust_cache(now=NOW))
check("... but still suppresses for that device",
      cl_afpe.is_trust_cached("learning-only.net", device_id="cam", hypothesis="NETWORK_INTRUSION", now=NOW))
check("... and not for another device",
      not cl_afpe.is_trust_cached("learning-only.net", device_id="bystander", hypothesis="NETWORK_INTRUSION", now=NOW))

cl_afpe.mark_false_positive(_alert("laptop", "api.shared-vendor.net"), source="autonomous_stage23", now=NOW)
check("an automatic correction on a name a baselined device vouched for is network-wide (unchanged)",
      "shared-vendor.net" in cl_afpe.get_dynamic_trust_cache(now=NOW))

cl_afpe.mark_false_positive(_alert("cam", "x.never-seen.net"), source="autonomous_stage23", now=NOW)
check("no ledger history: an automatic correction for a baselined device is network-wide (unchanged)",
      "never-seen.net" in cl_afpe.get_dynamic_trust_cache(now=NOW))

cl_afpe.mark_false_positive(_alert("cam", "c2.learning-only.net"), source="operator", now=NOW + 60)
check("a person's correction on a learning-only domain is network-wide (the human override)",
      "learning-only.net" in cl_afpe.get_dynamic_trust_cache(now=NOW + 60))


class _BrokenLedger:
    def is_learning_only(self, domain):
        raise RuntimeError("database locked")


no_pop = ClAfpeEngine(GraphStore(str(tmpdir / "graph2.db")), familiarity=familiarity)
no_pop.store.upsert_device("cam", timestamp=NOW)
no_pop.mark_false_positive(_alert("cam", "c2.learning-only.net"), source="autonomous_stage23", now=NOW)
check("without a popularity store the behaviour is unchanged (network-wide for a baselined device)",
      "learning-only.net" in no_pop.get_dynamic_trust_cache(now=NOW))
no_pop.popularity = _BrokenLedger()
check("an unreadable ledger reads as not learning-only, never raises",
      no_pop.domain_learning_only("learning-only.net") is False)

# --- 2. DNS-hypothesis edges leave the network-wide set ----------------------------------------------------------

cl_afpe.mark_false_positive(_alert("laptop", "unknown", dest_ip="198.51.100.9", signature="DNS_EVASION (persisted 60s)"),
                            source="autonomous_stage23", now=NOW)
check("a DNS_EVASION correction still immunizes for that device",
      cl_afpe.is_trust_cached("198.51.100.9", device_id="laptop", hypothesis="DNS_EVASION", now=NOW))
check("... and not for another device",
      not cl_afpe.is_trust_cached("198.51.100.9", device_id="bystander", hypothesis="DNS_EVASION", now=NOW))
check("... and is not in the network-wide trust cache", "198.51.100.9" not in cl_afpe.get_dynamic_trust_cache(now=NOW))
cl_afpe.immunize("policy-bypass.example", device_id="laptop", hypothesis="DNS_POLICY_BYPASS", now=NOW)
check("a DNS_POLICY_BYPASS edge on a name is not network-wide either",
      "policy-bypass.example" not in cl_afpe.get_dynamic_trust_cache(now=NOW))

# --- 3. ThreatIntel step 3 uses the public-suffix-aware base ----------------------------------------------------

cl_afpe.immunize("example.co.uk", device_id="laptop", source="operator", now=NOW)
ti = ThreatIntel(cache_dir=str(tmpdir / "ti"), et_open_enabled=False)
ti.trust_cache_provider = cl_afpe
check("a subdomain of a trusted multi-part-suffix domain is shielded (a.example.co.uk -> example.co.uk)",
      ti.is_allowlisted("a.example.co.uk"))
check("... and a different domain under the same public suffix is not", not ti.is_allowlisted("a.other.co.uk"))
check("a two-label base still matches as before", ti.is_allowlisted("cdn.shared-vendor.net"))
check("a DNS-hypothesis edge does not shield the name network-wide", not ti.is_allowlisted("policy-bypass.example"))
ti._bad_domains["evil.example.co.uk"] = {"source": "test", "confidence": 0.9}
check("a strong feed hit under a trusted multi-part-suffix domain still takes priority",
      not ti.is_allowlisted("evil.example.co.uk"))

store.close()
no_pop.store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All trust-cache M2 follow-up checks PASSED.")
