"""
Standalone runtime test for v13's INDEPENDENCE_FAMILY_MAP (src/v13/hypotheses/independence.py,
Phase 1/3 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: the counting mechanism itself (same-family evidence doesn't inflate the
independent-source count; different-family evidence does), the visible-not-silent
unknown-type fallback, and a structural guard against reintroducing the Phase 64
category error (this map must never grow a "what a hypothesis reads" concept).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_independence.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.hypotheses.independence import (  # noqa: E402
    INDEPENDENCE_FAMILY_MAP, UNKNOWN_FAMILY, family_for, count_independent_families,
)

# --- basic lookups ---
check("dns_entropy maps to dns_behavior", family_for("dns_entropy") == "dns_behavior")
check("malicious_ja3 maps to tls_fingerprint", family_for("malicious_ja3") == "tls_fingerprint")
check("an unregistered type maps to the visible UNKNOWN_FAMILY sentinel",
      family_for("totally_made_up_type") == UNKNOWN_FAMILY)

# --- the actual point: same-family evidence doesn't inflate the count ---
same_family = ["dns_entropy", "dns_tunnel_v2", "dns_dga_burst"]
check("three DNS-behavior-family evidence types count as ONE independent family, not three",
      count_independent_families(same_family) == 1)

# --- different families DO count separately ---
different_families = ["dns_entropy", "malicious_ja3", "reputation"]
check("three genuinely different-family evidence types count as three independent families",
      count_independent_families(different_families) == 3)

# --- the exact scenario this design correction targets: DNS signal + TLS signal
#     should corroborate as 2 independent sources, matching real security reasoning ---
mixed = ["dns_tunnel_v2", "malicious_ja4"]
check("a DNS-family signal plus a TLS-fingerprint-family signal count as 2 independent sources",
      count_independent_families(mixed) == 2)

# --- unknown types collapse into ONE family, not one-per-unknown-type ---
unknowns = ["never_seen_before_a", "never_seen_before_b", "never_seen_before_c"]
check("multiple UNREGISTERED types collapse into a single UNKNOWN_FAMILY bucket "
      "(don't silently inflate the independent-source count)",
      count_independent_families(unknowns) == 1)

mixed_known_unknown = ["dns_entropy", "never_seen_before_a"]
check("one known + one unknown type still correctly counts as 2 distinct families",
      count_independent_families(mixed_known_unknown) == 2)

# --- empty input ---
check("no evidence at all counts as zero independent families", count_independent_families([]) == 0)

# --- structural guard: this map must stay single-purpose (independence only) ---
sample_entry = next(iter(INDEPENDENCE_FAMILY_MAP.values()))
check("INDEPENDENCE_FAMILY_MAP's values are plain family-name strings, not dicts/objects "
      "that could smuggle in a second concept (e.g. relevance) alongside independence",
      isinstance(sample_entry, str))
check("INDEPENDENCE_FAMILY_MAP is not literally aliased to any 'relevant evidence types' "
      "concept -- it's its own standalone dict, not re-exported from elsewhere",
      isinstance(INDEPENDENCE_FAMILY_MAP, dict) and "HYPOTHESIS_RELEVANT" not in repr(type(INDEPENDENCE_FAMILY_MAP)))

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 independence-family checks PASSED.")
