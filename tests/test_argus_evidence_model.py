"""
Standalone runtime test for v13's Evidence v2 model (src/v13/evidence/model.py,
Phase 1 -- Documentation/V13_ARCHITECTURE_DEPENDENCY_MAP.md).

Covers: mandatory destination_id (fixes reviewer #17 at the root -- no evidence can
exist without an explicit target, not even accidentally via a default), mandatory
independence_family as a field genuinely separate from evidence_type (the core
design correction carried into every v13 module), confidence bounds validation, and
round-trip serialization (to_row/from_row) matching graph/schema.sql's column names
exactly.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_evidence_model.py` (or the project's real
venv equivalent, e.g. `venv/bin/python3` on the deployed box).
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


from argus.evidence.model import Evidence, NO_DESTINATION, new_evidence_id  # noqa: E402

# --- construction with all required fields succeeds ---
ev = Evidence(
    device_id="dev_abc123",
    destination_id="evil.example.com",
    evidence_type="dns_tunnel_v2",
    independence_family="dns_behavior",
    timestamp=1000.0,
    source="dns_features",
    confidence=0.9,
    value=4.2,
    provenance="test",
    features={"entropy": 4.7},
)
check("constructs successfully with all required fields", ev.device_id == "dev_abc123")
check("evidence_id auto-generated and non-empty", bool(ev.evidence_id) and len(ev.evidence_id) == 32)
check("two auto-generated evidence_ids are distinct", new_evidence_id() != new_evidence_id())

# --- mandatory destination_id: fixes reviewer #17 at the root ---
try:
    Evidence(device_id="d1", destination_id="", evidence_type="x", independence_family="y",
              timestamp=0.0, source="s")
    check("empty destination_id is rejected", False, "no exception raised")
except ValueError as e:
    check("empty destination_id is rejected", "destination_id" in str(e))

try:
    Evidence(device_id="d1", destination_id=None, evidence_type="x", independence_family="y",
              timestamp=0.0, source="s")
    check("None destination_id is rejected", False, "no exception raised")
except (ValueError, TypeError):
    check("None destination_id is rejected", True)

ev_no_dest = Evidence(device_id="d1", destination_id=NO_DESTINATION, evidence_type="arp_sweep",
                        independence_family="network_recon", timestamp=0.0, source="s")
check("NO_DESTINATION sentinel is accepted for genuinely non-destination-shaped evidence",
      ev_no_dest.destination_id == NO_DESTINATION)

# --- mandatory independence_family, genuinely separate from evidence_type ---
try:
    Evidence(device_id="d1", destination_id="x.com", evidence_type="dns_tunnel_v2",
              independence_family="", timestamp=0.0, source="s")
    check("empty independence_family is rejected", False, "no exception raised")
except ValueError as e:
    check("empty independence_family is rejected", "independence_family" in str(e))

ev2 = Evidence(device_id="d1", destination_id="x.com", evidence_type="dns_tunnel_v2",
                independence_family="dns_behavior", timestamp=0.0, source="s")
check("independence_family is stored as its own distinct field from evidence_type",
      ev2.independence_family != ev2.evidence_type)

# --- other mandatory fields ---
for missing_field, kwargs in [
    ("device_id", dict(device_id="", destination_id="x.com", evidence_type="t", independence_family="f", timestamp=0.0, source="s")),
    ("evidence_type", dict(device_id="d1", destination_id="x.com", evidence_type="", independence_family="f", timestamp=0.0, source="s")),
]:
    try:
        Evidence(**kwargs)
        check(f"empty {missing_field} is rejected", False, "no exception raised")
    except ValueError:
        check(f"empty {missing_field} is rejected", True)

# --- confidence bounds ---
try:
    Evidence(device_id="d1", destination_id="x.com", evidence_type="t", independence_family="f",
              timestamp=0.0, source="s", confidence=1.5)
    check("confidence > 1.0 is rejected", False, "no exception raised")
except ValueError:
    check("confidence > 1.0 is rejected", True)

try:
    Evidence(device_id="d1", destination_id="x.com", evidence_type="t", independence_family="f",
              timestamp=0.0, source="s", confidence=-0.1)
    check("confidence < 0.0 is rejected", False, "no exception raised")
except ValueError:
    check("confidence < 0.0 is rejected", True)

# --- effective_weight ---
ev3 = Evidence(device_id="d1", destination_id="x.com", evidence_type="t", independence_family="f",
                timestamp=0.0, source="s", confidence=0.8)
check("effective_weight combines confidence and freshness",
      abs(ev3.effective_weight(freshness=0.5) - 0.4) < 1e-9)

# --- round-trip serialization matches graph/schema.sql's column names ---
row = ev.to_row()
expected_cols = {"evidence_id", "device_id", "destination_id", "evidence_type",
                  "independence_family", "value", "confidence", "timestamp",
                  "source", "provenance", "features_json"}
check("to_row() produces exactly the schema.sql evidence table columns",
      set(row.keys()) == expected_cols, f"got {set(row.keys())}")

restored = Evidence.from_row(row)
check("from_row(to_row(x)) round-trips device_id", restored.device_id == ev.device_id)
check("from_row(to_row(x)) round-trips destination_id", restored.destination_id == ev.destination_id)
check("from_row(to_row(x)) round-trips independence_family", restored.independence_family == ev.independence_family)
check("from_row(to_row(x)) round-trips features dict", restored.features == ev.features)
check("from_row(to_row(x)) round-trips evidence_id", restored.evidence_id == ev.evidence_id)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 Evidence v2 model checks PASSED.")
