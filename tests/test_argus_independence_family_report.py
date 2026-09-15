"""
Standalone runtime test for src/v13/ops/independence_family_report.py (v13
full-architecture plan, Phase 8c -- INDEPENDENCE_FAMILY_MAP validation report).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_argus_independence_family_report.py`
"""
import json
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


from argus.graph.store import GraphStore  # noqa: E402
from argus.evidence.model import Evidence  # noqa: E402
from argus.ops.independence_family_report import (  # noqa: E402
    generate_report, run_once, _independent_source_counts, _v1_equivalent_family,
)

NOW = 1_000_000.0
tmpdir = tempfile.mkdtemp(prefix="v13_indep_report_test_")
store = GraphStore(str(_PathForSysPath(tmpdir) / "test.db"))


def _mk_decision(device_id, evidence_specs, timestamp=NOW):
    """evidence_specs: list of (evidence_type, independence_family) tuples."""
    ev_ids = []
    for etype, fam in evidence_specs:
        ev = Evidence(device_id=device_id, destination_id="x.example.com", evidence_type=etype,
                       independence_family=fam, timestamp=timestamp, source="test", confidence=0.9, value=1.0)
        store.insert_evidence(ev)
        ev_ids.append(ev.evidence_id)
    return store.insert_decision(
        device_id=device_id, timestamp=timestamp, state="HIGH", decision_path="hypothesis_high",
        confidence=0.8, risk_score=8.0, raw_payload={}, evidence_ids=ev_ids,
    )


# --- _v1_equivalent_family: the three v13-split families collapse to v1's single one ---
check("malicious_ja3 (v13: tls_fingerprint) collapses to v1's 'zeek_network'",
      _v1_equivalent_family("malicious_ja3") == "zeek_network")
check("zeek_exfiltration (v13: data_transfer_pattern) collapses to v1's 'zeek_network'",
      _v1_equivalent_family("zeek_exfiltration") == "zeek_network")
check("zeek_notice_medium (v13: network_behavior) collapses to v1's 'zeek_network' -- "
      "all 4 zeek_notice_{tier} evidence types (utils.py's ZEEK_NOTICE_EVIDENCE_TYPES) "
      "still collapse the same way, this split is orthogonal to the tier fragmentation",
      _v1_equivalent_family("zeek_notice_medium") == "zeek_network")
check("REGRESSION GUARD: every one of the 4 zeek_notice_{tier} evidence types "
      "collapses to v1's 'zeek_network', not just the one checked above",
      all(_v1_equivalent_family(t) == "zeek_network" for t in
          ("zeek_notice_weak", "zeek_notice_medium", "zeek_notice_strong", "zeek_notice_highly_deterministic")))
check("an unaffected type (dns_entropy) keeps its OWN v13 family unchanged -- "
      "v-current's own grouping already agrees with v13's here",
      _v1_equivalent_family("dns_entropy") == "dns_behavior")


# --- the actual point: a divergence where the finer split changed the outcome ---
did_split_matters = _mk_decision("1.1.1.1", [
    ("malicious_ja3", "tls_fingerprint"),
    ("zeek_exfiltration", "data_transfer_pattern"),
], timestamp=NOW)
v13_count, v1_count = _independent_source_counts(["malicious_ja3", "zeek_exfiltration"])
check("v13's finer split counts 2 independent sources (tls_fingerprint + data_transfer_pattern)",
      v13_count == 2)
check("v1's coarser grouping counts only 1 (both collapse into 'zeek_network')",
      v1_count == 1)

divergences = [{
    "kind": "DIFFERENT_PATH", "device_ip": "1.1.1.1", "timestamp": NOW,
    "v13_decision_path": "hypothesis_high", "vcurrent_decision_path": "hypothesis_suspicious",
}]
rows = generate_report(store, divergences)
check("generate_report finds the matching decision and computes both counts",
      len(rows) == 1 and rows[0]["v13_independent_sources_actual"] == 2
      and rows[0]["v13_independent_sources_v1_equivalent"] == 1)
check("family_split_contributed=True -- the finer split crossed the 2-source "
      "corroboration bar where the coarser v1 grouping would not have",
      rows[0]["family_split_contributed"] is True)


# --- a divergence where the family split is NOT the reason (both sides agree) ---
_mk_decision("2.2.2.2", [
    ("dns_entropy", "dns_behavior"),
    ("reputation", "reputation"),
], timestamp=NOW + 10)
divergences_unaffected = [{
    "kind": "DIFFERENT_PATH", "device_ip": "2.2.2.2", "timestamp": NOW + 10,
    "v13_decision_path": "hypothesis_high", "vcurrent_decision_path": "hard_stop",
}]
rows_unaffected = generate_report(store, divergences_unaffected)
check("a divergence whose evidence families are unaffected by the v13/v1 split "
      "reports family_split_contributed=False -- both count the same 2 sources",
      len(rows_unaffected) == 1 and rows_unaffected[0]["family_split_contributed"] is False
      and rows_unaffected[0]["v13_independent_sources_actual"] == 2
      and rows_unaffected[0]["v13_independent_sources_v1_equivalent"] == 2)


# --- non-DIFFERENT_PATH divergences are ignored entirely ---
other_divergences = [
    {"kind": "AGREE", "device_ip": "1.1.1.1", "timestamp": NOW},
    {"kind": "V13_ONLY", "device_ip": "1.1.1.1", "timestamp": NOW},
    {"kind": "VCURRENT_ONLY", "device_ip": "1.1.1.1", "timestamp": NOW},
]
check("AGREE/V13_ONLY/VCURRENT_ONLY divergences are never included -- only "
      "DIFFERENT_PATH is this report's actual subject",
      generate_report(store, other_divergences) == [])


# --- a divergence with no matching decision (aged out / never written) is skipped, not fatal ---
orphan_divergence = [{
    "kind": "DIFFERENT_PATH", "device_ip": "9.9.9.9", "timestamp": NOW, "v13_decision_path": "x",
}]
check("a divergence whose v13 decision can't be found produces no report row, no crash",
      generate_report(store, orphan_divergence) == [])


# --- run_once(): the CLI-facing wrapper, reads/writes real files ---
run_dir = _PathForSysPath(tempfile.mkdtemp(prefix="v13_indep_report_run_"))
run_db_path = run_dir / "v13_graph.db"
run_store = GraphStore(str(run_db_path))
ev1 = Evidence(device_id="3.3.3.3", destination_id="x.example.com", evidence_type="malicious_ja4",
                independence_family="tls_fingerprint", timestamp=NOW, source="test", confidence=0.9, value=1.0)
ev2 = Evidence(device_id="3.3.3.3", destination_id="x.example.com", evidence_type="zeek_beaconing",
                independence_family="data_transfer_pattern", timestamp=NOW, source="test", confidence=0.9, value=1.0)
run_store.insert_evidence(ev1)
run_store.insert_evidence(ev2)
run_store.insert_decision(device_id="3.3.3.3", timestamp=NOW, state="HIGH", decision_path="hypothesis_high",
                            confidence=0.8, risk_score=8.0, raw_payload={}, evidence_ids=[ev1.evidence_id, ev2.evidence_id])
run_store.close()

divergence_path = run_dir / "v13_divergence.jsonl"
with open(divergence_path, "w", encoding="utf-8") as f:
    f.write(json.dumps({
        "kind": "DIFFERENT_PATH", "device_ip": "3.3.3.3", "timestamp": NOW,
        "v13_decision_path": "hypothesis_high", "vcurrent_decision_path": "hard_stop",
    }) + "\n")

config = {
    "compare": {"output_path": str(divergence_path),
                 "independence_report_path": str(run_dir / "independence_report.jsonl")},
    "ingest": {"graph_db_path": str(run_db_path)},
}
result_rows = run_once(config)
check("run_once() reads the real divergence log + graph db and produces one row",
      len(result_rows) == 1 and result_rows[0]["family_split_contributed"] is True)
report_file = run_dir / "independence_report.jsonl"
check("run_once() writes the report file to disk",
      report_file.exists())
written_rows = [json.loads(l) for l in report_file.read_text().splitlines() if l.strip()]
check("the written report file matches what run_once() returned",
      written_rows == result_rows)

# a re-run with the SAME divergence log overwrites cleanly (idempotent), not append-growing
run_once(config)
written_rows_again = [json.loads(l) for l in report_file.read_text().splitlines() if l.strip()]
check("a second run_once() with the same input produces the SAME single row, "
      "not a growing/duplicated file (fresh recompute, not an append log)",
      written_rows_again == written_rows)

# --- no graph db yet: a clean no-op, not an error ---
no_db_dir = _PathForSysPath(tempfile.mkdtemp(prefix="v13_indep_report_nodb_"))
no_db_config = {
    "compare": {"output_path": str(no_db_dir / "v13_divergence.jsonl")},
    "ingest": {"graph_db_path": str(no_db_dir / "v13_graph.db")},
}
check("run_once() is a clean no-op when the graph db doesn't exist yet",
      run_once(no_db_config) == [])

store.close()

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All v13 independence-family-report checks PASSED.")
