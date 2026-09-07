"""
Standalone runtime test for v13's RetroHunter (src/v13/retro_hunter.py, Phase 6 --
Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: the core historical re-scan loop (real graph query, not a JSONL scan),
per-device evidence write-back for a threat-intel match, dedup-by-destination for
the lookup itself while still preserving per-device attribution in the output,
confidence-sorted findings, and clean no-op behavior when nothing matches or the
lookback window excludes everything.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_retro_hunter.py`
"""
import sys
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.graph.store import GraphStore  # noqa: E402
from v13.evidence.model import Evidence  # noqa: E402
from v13.retro_hunter import RetroHunter, real_threat_intel_lookup_factory  # noqa: E402
import intelligence.threat_intel  # noqa: E402  -- forces the namespace package into sys.modules so mock.patch's dotted-string resolution can find it below

# --- real_threat_intel_lookup_factory: ThreatIntel mocked, NO real network calls ---
mock_ti_instance = MagicMock()
mock_ti_instance.lookup_domain = MagicMock(return_value={"confidence": 3.0, "tags": ["test"], "source": "MockFeed"})

with patch("intelligence.threat_intel.ThreatIntel", return_value=mock_ti_instance) as mock_ti_class:
    lookup = real_threat_intel_lookup_factory({"otx_api_key": "x"}, "/tmp/fake_state", refresh=True)

check("real_threat_intel_lookup_factory constructs a ThreatIntel instance with the given config",
      mock_ti_class.call_args.kwargs.get("otx_api_key") == "x")
check("real_threat_intel_lookup_factory calls _refresh_all() when refresh=True",
      mock_ti_instance._refresh_all.called)
check("real_threat_intel_lookup_factory returns ThreatIntel's OWN lookup_domain method directly "
      "(a genuine pass-through, not a wrapper reimplementing the lookup)",
      lookup is mock_ti_instance.lookup_domain)
check("the returned lookup callable produces ThreatIntel's real return shape unchanged",
      lookup("evil.example.com") == {"confidence": 3.0, "tags": ["test"], "source": "MockFeed"})

mock_ti_instance2 = MagicMock()
with patch("intelligence.threat_intel.ThreatIntel", return_value=mock_ti_instance2):
    real_threat_intel_lookup_factory({}, "/tmp/fake_state", refresh=False)
check("refresh=False skips the network-calling _refresh_all() entirely",
      not mock_ti_instance2._refresh_all.called)

tmpdir = tempfile.mkdtemp(prefix="v13_retro_test_")
db_path = str(_PathForSysPath(tmpdir) / "test_retro.db")
store = GraphStore(db_path)

NOW = 1_000_000.0
DAY = 86400.0

# Two devices touched the same now-malicious domain within the lookback window;
# one device touched a domain that stays clean; one touch is too old to count.
store.insert_evidence(Evidence(device_id="dev1", destination_id="evil-later.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=NOW - 2 * DAY, source="s", value=2.0))
store.insert_evidence(Evidence(device_id="dev2", destination_id="evil-later.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=NOW - 5 * DAY, source="s", value=2.0))
store.insert_evidence(Evidence(device_id="dev3", destination_id="always-clean.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=NOW - 1 * DAY, source="s", value=1.0))
store.insert_evidence(Evidence(device_id="dev4", destination_id="evil-later.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=NOW - 20 * DAY, source="s", value=2.0))  # outside 14-day window

lookup_calls = []


def fake_threat_intel_lookup(domain):
    lookup_calls.append(domain)
    if domain == "evil-later.example.com":
        return {"confidence": 4.5, "tags": ["botnet"], "source": "ThreatFox"}
    return None


hunter = RetroHunter(store, threat_intel_lookup=fake_threat_intel_lookup)
findings = hunter.hunt(days_back=14, now=NOW)

# --- core matching behavior ---
check("both devices that touched the now-malicious domain within the window get a finding",
      {f.device_id for f in findings} == {"dev1", "dev2"}, f"got {[f.device_id for f in findings]}")
check("the clean domain's device produces no finding", "dev3" not in {f.device_id for f in findings})
check("the too-old touch (outside the 14-day window) is excluded even though the domain matched",
      "dev4" not in {f.device_id for f in findings})
check("each finding carries the real confidence/tags/source from the lookup",
      all(f.confidence == 4.5 and f.tags == ["botnet"] and f.source == "ThreatFox" for f in findings))

# --- dedup-by-destination for the lookup, while preserving per-device attribution ---
check("the threat-intel lookup itself is called once per distinct destination, not once per device "
      "(dev1 and dev2 share one domain -- only one lookup call for it)",
      lookup_calls.count("evil-later.example.com") == 1)
check("...but the OUTPUT still attributes the finding to each device separately -- v13 evidence is "
      "inherently device-attributed, unlike v-current's fully-deduped domain set", len(findings) == 2)

# --- evidence write-back: checked HERE, before any second hunt() call runs (below)
# also matches this same destination and would inflate the count for this device. ---
dev1_evidence = store.get_evidence_for_device("dev1")
retro_evidence = [e for e in dev1_evidence if e.source == "retro_hunter"]
check("a real reputation Evidence item is written back for the confirmed device",
      len(retro_evidence) == 1 and retro_evidence[0].evidence_type == "reputation"
      and retro_evidence[0].independence_family == "reputation")
check("the written-back evidence carries the real confidence value from the intel match",
      retro_evidence[0].value == 4.5)
check("the written-back evidence is timestamped at discovery time (now), not the original "
      "connection's own timestamp -- these are genuinely different points in time",
      retro_evidence[0].timestamp == NOW)
check("dev3 (clean domain) gets NO retro_hunter evidence written back",
      not any(e.source == "retro_hunter" for e in store.get_evidence_for_device("dev3")))

# --- Phase 1a: network-wide reputation propagation -- destination-scoped, not
# device-scoped, written once per confirmed destination regardless of how many
# devices touched it ---
confirmed_rep = store.get_destination_reputation("evil-later.example.com")
check("a confirmed destination gets its reputation cache set to tier 5 "
      "('corroborated', per ReputationVector's own tier docstring)",
      confirmed_rep is not None and confirmed_rep["tier"] == 5)
check("the reputation cache is timestamped at discovery time (now)",
      confirmed_rep is not None and confirmed_rep["cached_at"] == NOW)
check("the CLEAN destination never gets a reputation cache entry at all",
      store.get_destination_reputation("always-clean.example.com") is None)

# --- confidence-sorted output ---
store.insert_evidence(Evidence(device_id="dev5", destination_id="less-bad.example.com",
                                 evidence_type="dns_entropy", independence_family="dns_behavior",
                                 timestamp=NOW - 1 * DAY, source="s", value=1.0))


def multi_confidence_lookup(domain):
    if domain == "evil-later.example.com":
        return {"confidence": 4.5, "tags": [], "source": "ThreatFox"}
    if domain == "less-bad.example.com":
        return {"confidence": 2.0, "tags": [], "source": "URLHaus"}
    return None


hunter2 = RetroHunter(store, threat_intel_lookup=multi_confidence_lookup)
findings2 = hunter2.hunt(days_back=14, now=NOW)
check("findings are sorted by confidence, highest first",
      findings2[0].confidence >= findings2[-1].confidence and findings2[0].confidence == 4.5)

# --- clean no-op behavior ---
hunter_no_matches = RetroHunter(store, threat_intel_lookup=lambda d: None)
no_findings = hunter_no_matches.hunt(days_back=14, now=NOW)
check("a threat-intel lookup that never matches anything produces an empty finding list cleanly",
      no_findings == [])

empty_store = GraphStore(str(_PathForSysPath(tmpdir) / "empty.db"))
hunter_empty = RetroHunter(empty_store, threat_intel_lookup=fake_threat_intel_lookup)
check("hunting against a store with zero evidence at all produces an empty list, no crash",
      hunter_empty.hunt(days_back=14, now=NOW) == [])
empty_store.close()

# --- Phase 7: check_local_intel_history() -- cross-device local-intel correlation ---
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402

li_dir = tempfile.mkdtemp(prefix="v13_retro_test_local_intel_")
local_intel = LocalConfirmedIntel(li_dir)

intel_store = GraphStore(str(_PathForSysPath(tmpdir) / "intel_test.db"))
intel_store.insert_evidence(Evidence(device_id="li_dev_a", destination_id="already-confirmed.example.com",
                                       evidence_type="dns_query", independence_family="dns_behavior",
                                       timestamp=NOW - 3600, source="test", confidence=0.5, value=1.0))
intel_store.insert_evidence(Evidence(device_id="li_dev_b", destination_id="already-confirmed.example.com",
                                       evidence_type="dns_query", independence_family="dns_behavior",
                                       timestamp=NOW - 3600, source="test", confidence=0.5, value=1.0))
intel_store.insert_evidence(Evidence(device_id="li_dev_c", destination_id="203.0.113.44",
                                       evidence_type="dns_query", independence_family="dns_behavior",
                                       timestamp=NOW - 3600, source="test", confidence=0.5, value=1.0))
intel_store.insert_evidence(Evidence(device_id="li_dev_d", destination_id="never-flagged.example.com",
                                       evidence_type="dns_query", independence_family="dns_behavior",
                                       timestamp=NOW - 3600, source="test", confidence=0.5, value=1.0))

# li_dev_a is the confirming device itself -- its OWN prior touch is not a new finding.
local_intel.record("domain", "already-confirmed.example.com", "li_dev_a", reason="STAGE_1_HARD_STOP")
local_intel.record("ip", "203.0.113.44", "li_dev_z", reason="STAGE_1_HARD_STOP")

intel_hunter = RetroHunter(intel_store, threat_intel_lookup=lambda d: None)
li_matches = intel_hunter.check_local_intel_history(local_intel, days_back=14, now=NOW)
li_matches_by_device = {m["device_id"]: m for m in li_matches}

check("check_local_intel_history finds the OTHER device (li_dev_b) that touched an "
      "already-confirmed domain -- the actual cross-device correlation point",
      "li_dev_b" in li_matches_by_device
      and li_matches_by_device["li_dev_b"]["matched_kind"] == "domain"
      and li_matches_by_device["li_dev_b"]["confirmed_by"] == ["li_dev_a"])
check("...but does NOT flag the confirming device itself (li_dev_a) -- it already "
      "triggered its own confirmation at the time, matching v1's exact exclusion rule",
      "li_dev_a" not in li_matches_by_device)
check("check_local_intel_history correctly classifies an IP-shaped destination as "
      "'ip', not 'domain', via the same _looks_like_ip() GraphStore's own "
      "insert_evidence() already uses",
      "li_dev_c" in li_matches_by_device and li_matches_by_device["li_dev_c"]["matched_kind"] == "ip")
check("a device that never touched anything in the local-intel store produces no match",
      "li_dev_d" not in li_matches_by_device)
check("the finding shape carries first_confirmed/count/reason through from the real "
      "LocalConfirmedIntel entry, not just a bare match flag",
      li_matches_by_device["li_dev_b"]["reason"] == "STAGE_1_HARD_STOP"
      and li_matches_by_device["li_dev_b"]["count"] == 1
      and li_matches_by_device["li_dev_b"]["first_confirmed"] is not None)

no_intel_matches = intel_hunter.check_local_intel_history(LocalConfirmedIntel(tempfile.mkdtemp()), days_back=14, now=NOW)
check("an empty (freshly-created) local-intel store produces zero matches, no crash",
      no_intel_matches == [])

intel_store.close()
store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 retro-hunter checks PASSED.")
