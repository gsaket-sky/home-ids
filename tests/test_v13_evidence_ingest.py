"""
Standalone runtime test for v13's evidence ingest adapter (src/v13/evidence/ingest.py,
Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: v1 -> v2 field mapping, the NO_DESTINATION fallback when v1 carries no
domain, fallback_context enrichment, independence_family always coming from the
caller/lookup (never read off v1's own independence_group -- the specific
conflation this adapter exists to avoid reintroducing), and batch conversion's
visible (not silent) default-family fallback.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_evidence_ingest.py`
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


from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from v13.evidence.ingest import convert, convert_list  # noqa: E402
from v13.evidence.model import NO_DESTINATION  # noqa: E402

# --- basic field mapping ---
v1 = V1Evidence(type="dns_tunnel_v2", source="dns_features", timestamp=123.0, device="dev1",
                  value=4.5, confidence=0.85, independence_group="dns_behavior",
                  provenance="detector:dns_tunnel_v2", domain="evil.example.com")
v2 = convert(v1, independence_family="dns_behavior_family")
check("device_id maps from v1.device", v2.device_id == "dev1")
check("evidence_type maps from v1.type", v2.evidence_type == "dns_tunnel_v2")
check("destination_id maps from v1.domain when present", v2.destination_id == "evil.example.com")
check("confidence/value/timestamp/source map straight through",
      v2.confidence == 0.85 and v2.value == 4.5 and v2.timestamp == 123.0 and v2.source == "dns_features")

# --- independence_family comes from the caller, NEVER from v1's own independence_group ---
check("independence_family comes from the explicit caller arg, not v1.independence_group "
      "(the specific Phase 64 conflation this adapter exists to avoid)",
      v2.independence_family == "dns_behavior_family" and v2.independence_family != v1.independence_group)

# --- NO_DESTINATION fallback: the honest-scope case (zeek_exfiltration/zeek_beaconing-shaped) ---
v1_no_domain = V1Evidence(type="zeek_exfiltration", source="zeek_features", timestamp=200.0,
                            device="dev2", value=1.0, confidence=0.9, domain=None)
v2_no_domain = convert(v1_no_domain, independence_family="exfil_family")
check("v1 evidence with domain=None converts to NO_DESTINATION when no fallback_context given",
      v2_no_domain.destination_id == NO_DESTINATION)

# --- fallback_context enrichment ---
v2_with_fallback = convert(v1_no_domain, independence_family="exfil_family",
                             fallback_context={"dest_ip": "203.0.113.9"})
check("fallback_context supplies a destination when v1 has none",
      v2_with_fallback.destination_id == "203.0.113.9")

v2_prefers_domain = convert(v1_no_domain, independence_family="exfil_family",
                              fallback_context={"dest_ip": "203.0.113.9", "dest_domain": "cdn.example.net"})
check("fallback_context prefers dest_domain over dest_ip when both present",
      v2_prefers_domain.destination_id == "cdn.example.net")

v1_has_domain = V1Evidence(type="dns_tunnel_v2", source="dns_features", timestamp=210.0,
                             device="dev2", value=1.0, confidence=0.9, domain="real.example.com")
v2_ignores_fallback = convert(v1_has_domain, independence_family="dns_behavior_family",
                                fallback_context={"dest_ip": "203.0.113.9"})
check("fallback_context is only consulted when v1.domain is absent, never overrides a real one",
      v2_ignores_fallback.destination_id == "real.example.com")

# --- baseline carried into features, not dropped ---
v1_with_baseline = V1Evidence(type="dns_entropy", source="dns_features", timestamp=220.0,
                                device="dev3", value=4.1, baseline=2.0, domain="x.com")
v2_baseline = convert(v1_with_baseline, independence_family="dns_behavior_family")
check("v1.baseline is preserved in v2.features rather than silently dropped",
      v2_baseline.features.get("baseline") == 2.0)

v1_no_baseline = V1Evidence(type="dns_entropy", source="dns_features", timestamp=230.0,
                              device="dev3", value=4.1, domain="x.com")
v2_no_baseline = convert(v1_no_baseline, independence_family="dns_behavior_family")
check("v1 with no baseline produces an empty features dict, not a spurious None entry",
      v2_no_baseline.features == {})

# --- batch conversion with a lookup map ---
v1_list = [
    V1Evidence(type="dns_tunnel_v2", source="s", timestamp=1.0, device="d", value=1.0, domain="a.com"),
    V1Evidence(type="totally_unregistered_type", source="s", timestamp=2.0, device="d", value=1.0, domain="b.com"),
]
lookup = {"dns_tunnel_v2": "dns_behavior_family"}
v2_list = convert_list(v1_list, lookup, default_independence_family="general")
check("convert_list uses the lookup map when the type is registered",
      v2_list[0].independence_family == "dns_behavior_family")
check("convert_list falls back to the default family for an unregistered type",
      v2_list[1].independence_family == "general")
check("convert_list marks a defaulted family VISIBLY, not silently",
      v2_list[1].features.get("independence_family_defaulted") is True)
check("convert_list does NOT mark a properly-looked-up family as defaulted",
      "independence_family_defaulted" not in v2_list[0].features)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 evidence-ingest checks PASSED.")
