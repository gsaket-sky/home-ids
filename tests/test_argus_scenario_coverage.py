"""
Scenario catalogue and framework coverage gate (DETECTION_CORE_REWORK.md J4, MASTER_TODO 0d P0).

  * the catalogue is valid: every scenario has a twin of the other kind, a target outcome per intel setup, framework
    references; every pending scenario names its phase and what it needs; every known gap names its phase, why and
    today's bounds;
  * the framework maps have no open decision: every ATT&CK in-scope technique (generated, version-pinned) and claim has a
    status; every active D3FEND claim has an attack scenario and a benign twin; every NIST behaviour has a scenario;
  * spec and frozen golden agree: every active scenario compiles into cases that are in cases.json with the same input
    (a spec edit without a reviewed re-freeze fails here), and no frozen scenario case is orphaned;
  * the compiled cases pass the guard (pins and bounds) -- with "failing" intel deciding exactly like "off" (a failing
    feed is never a verdict, R6);
  * the generated ATT&CK list is the one the pinned bundle produces (rule and pin recorded in the file).

Run directly: `python tests/test_argus_scenario_coverage.py`
"""
import json
import sys
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.golden import coverage, guard, scenarios  # noqa: E402

scs = scenarios.load_scenarios()
rep = coverage.report(scs)
check("the catalogue and the framework maps have no open problem", not rep["problems"], "\n  " + "\n  ".join(rep["problems"]))
check(f"at least 30 active scenarios ({rep['scenarios']['active']})", rep["scenarios"]["active"] >= 30)
check("every active attack scenario has an active or pending benign twin and vice versa",
      all(any(t.id == s.spec["twin"] for t in scs) for s in scs))
counts = rep["attack"]["counts"]
check(f"every ATT&CK in-scope technique and claim has a status ({counts})",
      sum(counts.values()) == rep["attack"]["in_scope"] + len(
          set(json.loads(coverage.COVERAGE_PATH.read_text(encoding="utf-8"))["attack"]["claims"])
          - {t["id"] for t in json.loads(coverage.ATTACK_SCOPE_PATH.read_text(encoding="utf-8"))["techniques"]}))
scope = json.loads(coverage.ATTACK_SCOPE_PATH.read_text(encoding="utf-8"))
check("the ATT&CK scope file records its pinned source and rule",
      scope["source"]["version"] and len(scope["source"]["sha256"]) == 64 and "DC0078" in scope["rule"])
check("the D3FEND claims record their pinned ontology",
      len(json.loads(coverage.D3FEND_PATH.read_text(encoding="utf-8"))["source"]["sha256"]) == 64)

# --- the sources a case records are the registry's own ----------------------------------------------------------------
import tempfile  # noqa: E402
from core.source_availability import build_source_availability  # noqa: E402

registry = build_source_availability(
    config={}, zeek_collector=None, ti_engine=None, geoip_engine=None, abuseipdb=None, virustotal=None,
    heartbeats=lambda: {}, state_dir=_P(tempfile.mkdtemp(prefix="scn_sources_")))
registered = set(registry.snapshot(0.0))
for _intel in scenarios.INTEL_SETUPS:
    check(f"the {_intel!r} intel setup names exactly the registry's sources",
          set(scenarios.registry_sources(_intel)) == registered, sorted(set(scenarios.registry_sources(_intel)) ^ registered))

# --- spec <-> frozen golden ------------------------------------------------------------------------------------------
frozen = {c.case_id: c for c in guard.load_cases()}
compiled = scenarios.compile_all(scs)
missing = [c.case_id for c in compiled if c.case_id not in frozen]
check("every compiled scenario case is frozen in cases.json", not missing, missing[:5])
drift = [c.case_id for c in compiled if c.case_id in frozen and (
    json.dumps(guard.gathered_to_json(c.gathered), sort_keys=True)
    != json.dumps(guard.gathered_to_json(frozen[c.case_id].gathered), sort_keys=True)
    or c.expect != frozen[c.case_id].expect or c.params != frozen[c.case_id].params)]
check("frozen scenario inputs and bounds equal what the specs compile to (no unreviewed spec edit)", not drift, drift[:5])
edited = dict(next(s for s in scs if s.id == "recon_then_lateral").spec)
edited["timeline"] = [dict(edited["timeline"][0], evidence=[{"type": "arp_sweep", "value": 31.0, "confidence": 0.9}]),
                      edited["timeline"][1]]
moved = scenarios.compile_case(scenarios.Scenario(edited), "burst", "off")
check("the drift check sees an unreviewed spec edit (sweep size 30 -> 31)",
      json.dumps(guard.gathered_to_json(moved.gathered), sort_keys=True)
      != json.dumps(guard.gathered_to_json(frozen[moved.case_id].gathered), sort_keys=True))
orphans = sorted(set(k for k in frozen if k.startswith("scn:")) - {c.case_id for c in compiled})
check("no frozen scenario case without a spec", not orphans, orphans[:5])

# --- the compiled cases pass; a failing feed decides like no feed --------------------------------------------------------
report = guard.run_guard([frozen[c.case_id] for c in compiled if c.case_id in frozen])
check("every scenario case decides as pinned and inside its bounds", report.passed, report.describe())
by_id = {r.case_id: r.summary for r in report.results}
mismatch = [cid for cid in by_id if cid.endswith("/failing")
            and {k: v for k, v in by_id[cid].items()} != by_id.get(cid[:-len("failing")] + "off")]
check("with feeds failing every scenario decides exactly as with feeds off (R6)", not mismatch, mismatch[:5])
check("every target outcome is exercised by an active scenario",
      {o for sc in scs if not sc.pending for i in sc.intel_setups() for o in [sc.target(i)[0]]} == set(scenarios.OUTCOMES))

print(f"coverage: ATT&CK {rep['attack']['version']} {counts}; D3FEND {rep['d3fend']['version']} "
      f"{rep['d3fend']['active']}/{rep['d3fend']['claims']} active; NIST {rep['nist']['behaviours']} behaviours; "
      f"scenarios {rep['scenarios']}; open gaps by phase: "
      + ", ".join(f"{k} {len(v)}" for k, v in rep["open_gaps_by_phase"].items()))
print("SCENARIO COVERAGE", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
