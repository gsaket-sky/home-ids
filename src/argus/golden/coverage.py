"""
Framework coverage gate for the scenario catalogue (DETECTION_CORE_REWORK.md J4, MASTER_TODO 0d P0).

Three framework maps, each checked against the scenarios (argus/golden/scenarios.json):
  * MITRE ATT&CK -- the in-scope list generated from MITRE's STIX data (frameworks/attack-enterprise.json, version-pinned,
    tools/golden/attack_scope.py) plus the product's explicit claims (coverage.json). Every in-scope technique is
    covered (an active scenario), planned (a pending scenario, or a planned entry with phase and need), not_observable
    or out_of_scope (with a reason). A parent technique takes the best status of its sub-techniques.
  * MITRE D3FEND -- the defences the product claims (frameworks/d3fend.json, version-pinned): an active claim needs an
    active attack scenario proving it fires and an active benign scenario proving it stays quiet.
  * NIST SP 800-94 / 800-61 / 800-92 -- the behaviour list (frameworks/nist.json): each behaviour has a scenario.

`report()` returns the map and every problem; tests/test_argus_scenario_coverage.py fails on any problem, so a new
ATT&CK release (regenerated list), a new claim or a new scenario reference cannot land without a decision.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from argus.golden.scenarios import PHASES, Scenario, load_scenarios, validate

_DIR = Path(__file__).parent
ATTACK_SCOPE_PATH = _DIR / "frameworks" / "attack-enterprise.json"
D3FEND_PATH = _DIR / "frameworks" / "d3fend.json"
NIST_PATH = _DIR / "frameworks" / "nist.json"
COVERAGE_PATH = _DIR / "coverage.json"
_RANK = {"covered": 3, "planned": 2, "not_observable": 1, "out_of_scope": 1}


def _load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _refs(scenarios: Sequence[Scenario], framework: str, active: Optional[bool] = None,
          kind: Optional[str] = None) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    for sc in scenarios:
        if active is not None and sc.pending == active:
            continue
        if kind is not None and sc.spec.get("kind") != kind:
            continue
        for ref in sc.frameworks.get(framework, ()):
            out.setdefault(ref, []).append(sc.id)
    return out


def attack_map(scenarios: Sequence[Scenario], scope: Dict[str, Any], coverage: Dict[str, Any]) -> Dict[str, Any]:
    entries = coverage["attack"]["entries"]
    claims = coverage["attack"]["claims"]
    active, pending = _refs(scenarios, "attack", active=True), _refs(scenarios, "attack", active=False)
    ids = [t["id"] for t in scope["techniques"]] + sorted(set(claims) - {t["id"] for t in scope["techniques"]})
    status: Dict[str, Dict[str, Any]] = {}
    for tid in ids:
        if tid in active:
            status[tid] = {"status": "covered", "scenarios": active[tid]}
        elif tid in pending:
            status[tid] = {"status": "planned", "scenarios": pending[tid]}
        elif tid in entries:
            status[tid] = dict(entries[tid])
    for tid in ids:                                # a parent takes the best status of its sub-techniques
        if "." in tid:
            continue
        subs = [status[s] for s in ids if s.startswith(tid + ".") and s in status]
        best = max(subs, key=lambda s: _RANK.get(s["status"], 0), default=None)
        own = status.get(tid)
        if best and _RANK.get(best["status"], 0) >= 2 and (own is None or _RANK[best["status"]] > _RANK[own["status"]]):
            status[tid] = {"status": best["status"], "via": "sub-technique"}
    return status


def report(scenarios: Optional[Sequence[Scenario]] = None) -> Dict[str, Any]:
    scenarios = load_scenarios() if scenarios is None else scenarios
    scope, coverage, d3fend, nist = _load(ATTACK_SCOPE_PATH), _load(COVERAGE_PATH), _load(D3FEND_PATH), _load(NIST_PATH)
    problems: List[str] = list(validate(scenarios))

    # --- ATT&CK
    in_scope = {t["id"] for t in scope["techniques"]}
    claims = coverage["attack"]["claims"]
    entries = coverage["attack"]["entries"]
    known = in_scope | set(claims)
    all_refs = _refs(scenarios, "attack")
    for ref in sorted(set(all_refs) - known):
        problems.append(f"ATT&CK {ref} (scenario {all_refs[ref][0]}) is neither in the generated scope nor a claim")
    for tid in sorted(set(claims) - set(all_refs)):
        problems.append(f"ATT&CK claim {tid} has no scenario")
    for tid, e in sorted(entries.items()):
        if tid not in known:
            problems.append(f"ATT&CK entry {tid} is not in scope")
        if e.get("status") not in ("planned", "not_observable", "out_of_scope"):
            problems.append(f"ATT&CK entry {tid}: status must be planned, not_observable or out_of_scope")
        if not e.get("reason"):
            problems.append(f"ATT&CK entry {tid}: needs a reason")
        if e.get("status") == "planned" and e.get("phase") not in PHASES:
            problems.append(f"ATT&CK entry {tid}: a planned entry needs a phase")
        if tid in all_refs:
            problems.append(f"ATT&CK entry {tid} is stale: scenario {all_refs[tid][0]} references it")
    amap = attack_map(scenarios, scope, coverage)
    for tid in sorted(known - set(amap)):
        problems.append(f"ATT&CK {tid} has no status (needs a scenario or a coverage entry)")

    # --- D3FEND
    claimed = {c["id"]: c for c in d3fend["claims"]}
    d_refs = _refs(scenarios, "d3fend")
    for ref in sorted(set(d_refs) - set(claimed)):
        problems.append(f"D3FEND {ref} (scenario {d_refs[ref][0]}) is not a claimed defence")
    act_attack = _refs(scenarios, "d3fend", active=True, kind="attack")
    act_benign = _refs(scenarios, "d3fend", active=True, kind="benign")
    for cid, c in sorted(claimed.items()):
        if c.get("status") == "active":
            if cid not in act_attack:
                problems.append(f"D3FEND {cid}: active claim without an active attack scenario")
            if cid not in act_benign:
                problems.append(f"D3FEND {cid}: active claim without an active benign twin")
        elif c.get("status") != "planned" or c.get("phase") not in PHASES:
            problems.append(f"D3FEND {cid}: status must be active, or planned with a phase")

    # --- NIST
    listed = {b["id"] for b in nist["behaviours"]}
    n_refs = _refs(scenarios, "nist")
    for ref in sorted(set(n_refs) - listed):
        problems.append(f"NIST {ref} (scenario {n_refs[ref][0]}) is not in the behaviour list")
    for bid in sorted(listed - set(n_refs)):
        problems.append(f"NIST {bid} has no scenario")

    counts: Dict[str, int] = {}
    for s in amap.values():
        counts[s["status"]] = counts.get(s["status"], 0) + 1
    gaps: Dict[str, List[str]] = {}
    for sc in scenarios:
        for gap in sc.spec.get("known_gaps", ()):
            gaps.setdefault(gap["phase"], []).append(sc.id)
        if sc.pending:
            gaps.setdefault(sc.spec["pending"]["phase"], []).append(sc.id + " (pending)")
    return {
        "problems": problems,
        "attack": {"version": scope["source"]["version"], "in_scope": len(in_scope), "claims": len(claims),
                   "counts": counts, "map": amap},
        "d3fend": {"version": d3fend["source"]["version"], "claims": len(claimed),
                   "active": sum(c.get("status") == "active" for c in claimed.values())},
        "nist": {"behaviours": len(listed)},
        "scenarios": {"active": sum(not s.pending for s in scenarios), "pending": sum(s.pending for s in scenarios)},
        "open_gaps_by_phase": {k: sorted(set(v)) for k, v in sorted(gaps.items())},
    }
