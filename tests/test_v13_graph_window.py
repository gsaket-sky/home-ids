"""
Standalone runtime test for v13's RollingWindowView (src/v13/graph/window.py,
Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: window-bounded evidence retrieval, domain_counts (the RollingWindow.domains
replacement), and domain_seen_before -- the cross-cycle "familiar destination"
query HEE_ROADMAP.md item 4 named as a real graph-store benefit not achievable
against v-current's in-memory-only RollingWindow.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_graph_window.py`
"""
import sys
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.graph.store import GraphStore  # noqa: E402
from v13.graph.window import RollingWindowView  # noqa: E402
from v13.evidence.model import Evidence, NO_DESTINATION  # noqa: E402

tmpdir = tempfile.mkdtemp(prefix="v13_window_test_")
db_path = str(_PathForSysPath(tmpdir) / "test_window.db")
store = GraphStore(db_path)
window = RollingWindowView(store)

NOW = 1_000_000.0

# Evidence spread across time: two recent (within 5min), one older (within 1hr but
# not 5min), one very old (outside both windows).
store.insert_evidence(Evidence(device_id="dev1", destination_id="a.com", evidence_type="dns_entropy",
                                 independence_family="dns_behavior", timestamp=NOW - 60, source="s"))
store.insert_evidence(Evidence(device_id="dev1", destination_id="b.com", evidence_type="dns_entropy",
                                 independence_family="dns_behavior", timestamp=NOW - 120, source="s"))
store.insert_evidence(Evidence(device_id="dev1", destination_id="a.com", evidence_type="malicious_ja3",
                                 independence_family="tls_fingerprint", timestamp=NOW - 1800, source="s"))
store.insert_evidence(Evidence(device_id="dev1", destination_id="c.com", evidence_type="dns_entropy",
                                 independence_family="dns_behavior", timestamp=NOW - 7200, source="s"))
store.insert_evidence(Evidence(device_id="dev1", destination_id=NO_DESTINATION, evidence_type="arp_sweep",
                                 independence_family="network_recon", timestamp=NOW - 30, source="s"))

# --- evidence_in_window ---
# 5 items inserted at NOW-60, NOW-120, NOW-1800, NOW-7200, NOW-30 (arp_sweep).
# Short window (300s) covers -60/-120/-30 = 3 items; long window (3600s) adds -1800 = 4;
# only the -7200 item falls outside both.
short = window.evidence_in_window("dev1", RollingWindowView.SHORT_WINDOW_SECONDS, now=NOW)
check("short window (5min) includes the three items within 300s (including arp_sweep at -30s)",
      len(short) == 3, f"got {len(short)}")

long = window.evidence_in_window("dev1", RollingWindowView.LONG_WINDOW_SECONDS, now=NOW)
check("long window (1hr) includes four items, excludes only the 2hr-old one",
      len(long) == 4, f"got {len(long)}")

# --- domain_counts ---
counts = window.domain_counts("dev1", window_seconds=RollingWindowView.LONG_WINDOW_SECONDS, now=NOW)
check("domain_counts counts a.com twice within the long window", counts.get("a.com") == 2)
check("domain_counts excludes NO_DESTINATION sentinel evidence from domain tallies",
      NO_DESTINATION not in counts)
check("domain_counts excludes the out-of-window c.com hit",
      "c.com" not in counts)

full_counts = window.domain_counts("dev1", window_seconds=1_000_000, now=NOW)
check("a wide enough window does pick up c.com", full_counts.get("c.com") == 1)

# --- domain_seen_before: the cross-cycle familiarity query ---
seen_before = window.domain_seen_before("dev1", "a.com", lookback_seconds=100_000, now=NOW)
check("domain_seen_before finds a.com's older (1800s ago) hit within a wide lookback", seen_before)

not_seen = window.domain_seen_before("dev1", "z.com", lookback_seconds=100_000, now=NOW)
check("domain_seen_before correctly returns False for a domain never contacted", not not_seen)

excluded_current_incident = window.domain_seen_before(
    "dev1", "a.com", lookback_seconds=100_000, now=NOW,
    exclude_window_seconds=RollingWindowView.SHORT_WINDOW_SECONDS,
)
check("domain_seen_before still finds a.com familiar even when excluding the current "
      "5-min incident window (the 1800s-old hit is outside that exclusion)",
      excluded_current_incident)

only_recent_hit = window.domain_seen_before(
    "dev1", "b.com", lookback_seconds=100_000, now=NOW,
    exclude_window_seconds=RollingWindowView.SHORT_WINDOW_SECONDS,
)
check("domain_seen_before correctly reports NOT familiar when b.com's only hit is "
      "itself inside the excluded current-incident window",
      not only_recent_hit)

# --- evidence_type_counts ---
type_counts = window.evidence_type_counts("dev1", window_seconds=RollingWindowView.LONG_WINDOW_SECONDS, now=NOW)
check("evidence_type_counts tallies dns_entropy correctly within the long window",
      type_counts.get("dns_entropy") == 2)

# --- devices_targeting (Phase 1a: cross-device correlation) ---
store.insert_evidence(Evidence(device_id="dev2", destination_id="shared.com", evidence_type="dns_entropy",
                                 independence_family="dns_behavior", timestamp=NOW - 60, source="s"))
store.insert_evidence(Evidence(device_id="dev3", destination_id="shared.com", evidence_type="dns_entropy",
                                 independence_family="dns_behavior", timestamp=NOW - 4000, source="s"))  # outside short window
store.insert_evidence(Evidence(device_id="dev1", destination_id="shared.com", evidence_type="dns_entropy",
                                 independence_family="dns_behavior", timestamp=NOW - 60, source="s"))

targeting_all = window.devices_targeting("shared.com", RollingWindowView.SHORT_WINDOW_SECONDS, now=NOW)
check("devices_targeting includes dev1 and dev2 (both within the short window)",
      set(targeting_all) == {"dev1", "dev2"}, f"got {targeting_all}")
check("devices_targeting excludes dev3 (its only touch is outside the window)",
      "dev3" not in targeting_all)

targeting_excl_self = window.devices_targeting(
    "shared.com", RollingWindowView.SHORT_WINDOW_SECONDS, now=NOW, exclude_device_id="dev1",
)
check("devices_targeting with exclude_device_id leaves out the calling device itself",
      targeting_excl_self == ["dev2"], f"got {targeting_excl_self}")

targeting_wide_window = window.devices_targeting("shared.com", window_seconds=10_000, now=NOW)
check("a wide enough window does pick up dev3", "dev3" in targeting_wide_window)

store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 graph-window checks PASSED.")
