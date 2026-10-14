"""
W-13 (DETECTION_CORE_REWORK P0, owner decision 2026-10-14): `argus/hypotheses/independence.py` is the SINGLE evidence-family
registry.

There were two models. The decision engine counted independent sources over INDEPENDENCE_FAMILY_MAP, while the detector
Evidence also carried a free-form `independence_group` string (a second, coarser vocabulary: "zeek_network", "lan_recon",
"dns_behavior" ...) that still drove three things: the evidence expiry (reputation lives 24 h), the noise filter for
safe-listed devices (it dropped everything in the groups zeek_network / lan_recon), and the family names saved on every
alert (`hee_evidence_families`, which mixed both vocabularies). A detector could invent a group name; an evidence type
missing from the registry silently got whatever group its detector wrote.

Now an evidence item's family is `family_for(type)`, nothing else; the second registry (EVIDENCE_FAMILIES /
ATTACK_EVIDENCE_FAMILIES) and the `independence_group` field are gone. The behaviours that used the groups are re-stated on
types / registry families, and this file pins that they are unchanged.

Run directly: `python tests/test_evidence_single_family_registry.py`
"""
import re
import sys
import time
from pathlib import Path as _P
SRC = _P(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import intelligence.hypotheses.evidence as legacy  # noqa: E402
from intelligence.hypotheses.evidence import Evidence, EvidenceStore  # noqa: E402
from argus.hypotheses.independence import INDEPENDENCE_FAMILY_MAP, family_for, UNKNOWN_FAMILY  # noqa: E402

# --- one registry -------------------------------------------------------------------------------------------------
check("the second registry is gone: no EVIDENCE_FAMILIES / ATTACK_EVIDENCE_FAMILIES",
      not hasattr(legacy, "EVIDENCE_FAMILIES") and not hasattr(legacy, "ATTACK_EVIDENCE_FAMILIES"))
check("Evidence has no free-form independence_group field",
      "independence_group" not in Evidence.__dataclass_fields__ and not hasattr(Evidence(
          type="dns_rate", source="x", timestamp=0.0, device="d", value=1.0), "independence_group"))
check("an Evidence's family is the registry's, for every registered type",
      all(Evidence(type=t, source="x", timestamp=0.0, device="d", value=1.0).family == fam
          for t, fam in INDEPENDENCE_FAMILY_MAP.items()))
check("an unregistered type has the registry's unknown family (never a detector-invented name)",
      Evidence(type="not_registered_type", source="x", timestamp=0.0, device="d", value=1.0).family == UNKNOWN_FAMILY)

# every evidence type the code creates by literal name is registered (a new detector cannot fragment the count silently)
created = set()
for path in list((SRC / "intelligence" / "detectors").glob("*.py")) + [SRC / "core" / "pipeline.py"]:
    text = path.read_text(encoding="utf-8")
    created |= set(re.findall(r'Evidence\(\s*type="([a-z0-9_]+)"', text))
    created |= set(re.findall(r'\badd\(\s*"([a-z0-9_]+)"', text))
created -= {"x"}
missing = sorted(t for t in created if t not in INDEPENDENCE_FAMILY_MAP)
check("every evidence type created by name in the detectors and the pipeline is in the registry", not missing, str(missing))

# --- expiry: reputation lives 24 h, everything else 10 min -----------------------------------------------------------
store = EvidenceStore()
now = time.time()
store.add(Evidence(type="reputation", source="x", timestamp=now - 7200, device="d", value=4.0))
store.add(Evidence(type="dns_rate", source="x", timestamp=now - 7200, device="d", value=4.0))
store.add(Evidence(type="dns_rate", source="x", timestamp=now - 60, device="d", value=4.0))
alive = sorted(e.type for e in store.get_for_device("d"))
check("reputation evidence (family reputation) still lives 24 h; behavioural evidence 10 min",
      alive == ["dns_rate", "reputation"], str(alive))

# --- the safe-device noise filter, pinned to what the old group assignments dropped ------------------------------------
# Legacy: dropped when type OR independence_group was in {ml_anomaly, dns_rate, dns_entropy, dns_unique_ratio,
# zeek_network, lan_recon, dns_evasion_anomaly}. Types that carried group zeek_network: malicious_ja3/ja4, the four
# zeek_notice_<tier>, zeek_lateral_scan, zeek_exfiltration, zeek_beaconing, zeek_conn_abuse, zeek_long_conn,
# arp_spoof_pending; group lan_recon: arp_sweep.
EXPECTED_DAMPENED = frozenset({
    "ml_anomaly", "dns_rate", "dns_entropy", "dns_unique_ratio", "dns_evasion_anomaly",
    "malicious_ja3", "malicious_ja4",
    "zeek_notice_weak", "zeek_notice_medium", "zeek_notice_strong", "zeek_notice_highly_deterministic",
    "zeek_lateral_scan", "zeek_exfiltration", "zeek_beaconing", "zeek_conn_abuse", "zeek_long_conn",
    "arp_spoof_pending", "arp_sweep",
})
check("the evidence types a safe-listed device's behavioural noise filter drops are exactly the legacy set",
      legacy.SAFE_DEVICE_DAMPENED_TYPES == EXPECTED_DAMPENED,
      str(sorted(legacy.SAFE_DEVICE_DAMPENED_TYPES ^ EXPECTED_DAMPENED)) if hasattr(legacy, "SAFE_DEVICE_DAMPENED_TYPES") else "missing")
for kept in ("honeypot_access", "arp_spoofing", "reputation", "geofencing_violation", "suricata_signature_match",
             "dns_dga_burst", "dns_tunnel_v2", "local_device_discovery"):
    check(f"{kept} is NOT dampened for a safe-listed device (threat intel / hard-stop evidence is kept)",
          kept not in legacy.SAFE_DEVICE_DAMPENED_TYPES if hasattr(legacy, "SAFE_DEVICE_DAMPENED_TYPES") else False)

# --- the family names saved on an alert are the registry's ------------------------------------------------------------
import core.pipeline as pipeline  # noqa: E402
evs = [Evidence(type="zeek_notice_medium", source="x", timestamp=now, device="d", value=1.0),
       Evidence(type="dns_rate", source="x", timestamp=now, device="d", value=1.0),
       Evidence(type="reputation", source="x", timestamp=now, device="d", value=4.0)]
fams = pipeline.evidence_families_for_alert(evs, ["peer_cohort_deviation"]) if hasattr(
    pipeline, "evidence_families_for_alert") else None
check("hee_evidence_families is one vocabulary: the registry's families, plus the decision's own",
      fams == ["dns_behavior", "network_behavior", "peer_cohort_deviation", "reputation"], str(fams))
check("no legacy group name can appear in it (zeek_network, lan_recon, blindspot_audit, suricata)",
      fams is not None and not (set(fams) & {"zeek_network", "lan_recon", "blindspot_audit", "suricata", "general"}))

print("SINGLE FAMILY REGISTRY", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
