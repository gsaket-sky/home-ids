"""
Continuous golden guard on the pure decision engine (DETECTION_CORE_REWORK.md section H2, MASTER_TODO 0d P0).

A golden case is a frozen decision input -- one `GatheredCycle` and the `DecisionParameters` it is decided with, both
stored as data in `cases.json` next to this file -- plus what the decision must be:

  * `expect`: the safety bounds that must hold under ANY parameter values a challenger or champion uses -- an attack
    must reach at least a given state, a confounder must stay at or below one, and containment may only rest on the
    named bases. A miss here means "an attack went unseen" or "a harmless pattern now alerts / contains".
  * `pinned`: the exact decision summary under the case's own parameters (`decision_summary()`). Any code change that
    moves it fails the guard until the new pin is reviewed and committed -- never accepted automatically.

`decide()` is pure and re-entrant (live_engine, U7), so a case runs in well under a millisecond with no graph, no
learner and no wall clock: the whole set runs on every change (CI, tests/test_argus_golden_guard.py) and wherever a
parameter value is about to be used (autotune proposals and promotions). Inputs are frozen rather than rebuilt from a
generator so that a changed generator can never silently move a golden: an input changes only through a reviewed diff
of this file's data, like a pin.

Updating pins after a deliberate behaviour change (the only way they change):
  python src/argus/golden/guard.py --check
  python src/argus/golden/guard.py --propose <out.json> --reason "<why the decisions change>"
The proposal is written to <out.json> with every changed case's new pin and the reason recorded on it; the per-case
diff is printed. Review it, then replace cases.json with it in the same commit as the behaviour change.

Test data is network-agnostic: documentation address ranges (RFC 5737 / RFC 3849) and reserved names (RFC 2606) only.
"""
import argparse
import dataclasses
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

if __name__ == "__main__":  # pragma: no cover -- run as a script: make `src/` importable
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from argus.evidence.model import Evidence  # noqa: E402
from argus.ops import live_engine  # noqa: E402
from argus.ops.live_engine import DecisionParameters, GatheredCycle, PeerStats, _ReputationCandidate  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
from mitigation.containment_gate import authorize_containment  # noqa: E402

FORMAT_VERSION = 1
DEFAULT_CASES_PATH = Path(__file__).with_name("cases.json")

STATE_ORDER: Tuple[str, ...] = ("BENIGN", "ANOMALOUS", "SUSPICIOUS", "HIGH", "CRITICAL")
CASE_KINDS = frozenset({"attack", "benign", "boundary"})

_EVIDENCE_FIELDS = ("device_id", "destination_id", "evidence_type", "independence_family", "timestamp", "source",
                    "confidence", "value", "provenance", "features")
_REP_FIELDS = tuple(f.name for f in dataclasses.fields(ReputationVector))
_PARAM_FIELDS = tuple(f.name for f in dataclasses.fields(DecisionParameters))


# --- (de)serialisation -----------------------------------------------------------------------------------------------

def evidence_to_json(ev: Evidence) -> Dict[str, Any]:
    """Every field decide() can read. `evidence_id` is left out: it is random per conversion and nothing decided reads it."""
    return {name: getattr(ev, name) for name in _EVIDENCE_FIELDS}


def evidence_from_json(data: Mapping[str, Any], index: int) -> Evidence:
    unknown = set(data) - set(_EVIDENCE_FIELDS)
    if unknown:
        raise ValueError(f"unknown evidence field(s): {sorted(unknown)}")
    return Evidence(**{**data, "features": dict(data.get("features") or {})}, evidence_id=f"golden-{index}")


def rep_to_json(rep: Optional[ReputationVector]) -> Optional[Dict[str, Any]]:
    return None if rep is None else {name: getattr(rep, name) for name in _REP_FIELDS}


def rep_from_json(data: Optional[Mapping[str, Any]]) -> Optional[ReputationVector]:
    return None if data is None else ReputationVector(**data)


def params_to_json(params: DecisionParameters) -> Dict[str, Any]:
    return {name: getattr(params, name) for name in _PARAM_FIELDS}


def params_from_json(data: Mapping[str, Any]) -> DecisionParameters:
    unknown = set(data) - set(_PARAM_FIELDS)
    if unknown:
        raise ValueError(f"unknown DecisionParameters field(s): {sorted(unknown)}")
    return DecisionParameters(**data)


def gathered_to_json(g: GatheredCycle) -> Dict[str, Any]:
    derived = []
    for item in g.graph_derived:
        if isinstance(item, _ReputationCandidate):
            derived.append({"reputation_candidate": item._asdict()})
        else:
            derived.append({"evidence": evidence_to_json(item)})
    return {
        "device_id": g.device_id, "ts": g.ts, "device_type": g.device_type, "is_safe": g.is_safe,
        "baseline_familiarity": g.baseline_familiarity,
        "features": None if g.features is None else dict(g.features),
        "rep_vector": rep_to_json(g.rep_vector),
        "fresh_v2": [evidence_to_json(e) for e in g.fresh_v2],
        "windowed_v2": [evidence_to_json(e) for e in g.windowed_v2],
        "graph_derived": derived,
        "peer_stats": None if g.peer_stats is None else g.peer_stats._asdict(),
        "baseline_v2": [evidence_to_json(e) for e in g.baseline_v2],
        "domain_age_v2": [evidence_to_json(e) for e in g.domain_age_v2],
        "sources": dict(g.sources),
    }


def gathered_from_json(data: Mapping[str, Any]) -> GatheredCycle:
    counter = iter(range(1_000_000))

    def evs(items):
        return tuple(evidence_from_json(e, next(counter)) for e in items or ())

    derived: List[Any] = []
    for item in data.get("graph_derived") or ():
        if "reputation_candidate" in item:
            derived.append(_ReputationCandidate(**item["reputation_candidate"]))
        else:
            derived.append(evidence_from_json(item["evidence"], next(counter)))
    features = data.get("features")
    return GatheredCycle(
        device_id=data.get("device_id"), ts=float(data["ts"]), device_type=data.get("device_type", ""),
        is_safe=bool(data.get("is_safe", False)), baseline_familiarity=float(data.get("baseline_familiarity", 0.0)),
        features=None if features is None else MappingProxyType(dict(features)),
        rep_vector=rep_from_json(data.get("rep_vector")),
        fresh_v2=evs(data.get("fresh_v2")), windowed_v2=evs(data.get("windowed_v2")), graph_derived=tuple(derived),
        peer_stats=None if data.get("peer_stats") is None else PeerStats(**data["peer_stats"]),
        baseline_v2=evs(data.get("baseline_v2")), domain_age_v2=evs(data.get("domain_age_v2")),
        sources=MappingProxyType(dict(data.get("sources") or {})),
    )


# --- cases -----------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Expectation:
    """Safety bounds that hold under any parameter values. None = not bounded. `containment`: the bases containment
    may rest on (None in the tuple = "no containment"); None = not checked."""
    state_at_least: Optional[str] = None
    state_at_most: Optional[str] = None
    containment: Optional[Tuple[Optional[str], ...]] = None

    def __post_init__(self):
        for s in (self.state_at_least, self.state_at_most):
            if s is not None and s not in STATE_ORDER:
                raise ValueError(f"unknown decision state {s!r}")

    def to_json(self) -> Dict[str, Any]:
        return {"state_at_least": self.state_at_least, "state_at_most": self.state_at_most,
                "containment": None if self.containment is None else list(self.containment)}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "Expectation":
        c = data.get("containment")
        return cls(data.get("state_at_least"), data.get("state_at_most"), None if c is None else tuple(c))


@dataclass(frozen=True)
class GoldenCase:
    case_id: str
    title: str
    kind: str                       # attack | benign | boundary
    origin: str                     # where the case comes from (real incident, scenario file, design section)
    gathered: GatheredCycle
    params: DecisionParameters
    expect: Expectation
    pinned: Mapping[str, Any] = field(default_factory=dict)
    note: str = ""                  # why the pin is what it is -- a known defect is named here with its phase
    pinned_reason: str = ""         # the reason given when the pin was last (re)accepted

    def __post_init__(self):
        if self.kind not in CASE_KINDS:
            raise ValueError(f"case {self.case_id}: unknown kind {self.kind!r}")

    def to_json(self) -> Dict[str, Any]:
        return {"case_id": self.case_id, "title": self.title, "kind": self.kind, "origin": self.origin,
                "note": self.note, "expect": self.expect.to_json(), "params": params_to_json(self.params),
                "gathered": gathered_to_json(self.gathered), "pinned": dict(self.pinned),
                "pinned_reason": self.pinned_reason}

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "GoldenCase":
        return cls(case_id=data["case_id"], title=data["title"], kind=data["kind"], origin=data.get("origin", ""),
                   gathered=gathered_from_json(data["gathered"]), params=params_from_json(data["params"]),
                   expect=Expectation.from_json(data["expect"]), pinned=dict(data.get("pinned") or {}),
                   note=data.get("note", ""), pinned_reason=data.get("pinned_reason", ""))


def load_cases(path: Optional[Path] = None) -> List[GoldenCase]:
    doc = json.loads(Path(path or DEFAULT_CASES_PATH).read_text(encoding="utf-8"))
    if doc.get("format_version") != FORMAT_VERSION:
        raise ValueError(f"golden cases format {doc.get('format_version')!r}, expected {FORMAT_VERSION}")
    cases = [GoldenCase.from_json(c) for c in doc["cases"]]
    ids = [c.case_id for c in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate golden case ids")
    return cases


def dump_cases(cases: Sequence[GoldenCase]) -> str:
    """Canonical text: stable key order and one value per line, so a reviewed diff shows exactly what moved."""
    doc = {"format_version": FORMAT_VERSION, "cases": [c.to_json() for c in sorted(cases, key=lambda c: c.case_id)]}
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


# --- running ---------------------------------------------------------------------------------------------------------

def decision_summary(decision: Mapping[str, Any]) -> Dict[str, Any]:
    """What a pin fixes: the verdict, why (path, the counted families and types, the competing hypotheses), what it is
    about (anchor destinations), and the containment it authorises. Wording (explanation, reasoning trail) and the
    confidence number derived from the path are not pinned."""
    hyps = decision.get("hypotheses") or {}
    return {
        "state": decision["state"],
        "action": decision["action"],
        "decision_path": decision["decision_path"],
        "single_signal_basis": decision.get("single_signal_basis"),
        "independent_sources": decision.get("independent_sources"),
        "evidence_families": list(decision.get("evidence_families") or []),
        "evidence_types": list(decision.get("evidence_types") or []),
        "attack_hypothesis": [hyps.get("attack", {}).get("name"), hyps.get("attack", {}).get("score")],
        "benign_hypothesis": [hyps.get("benign", {}).get("name"), hyps.get("benign", {}).get("score")],
        "hypothesis_destination_ids": list(decision.get("hypothesis_destination_ids") or []),
        "containment_basis": authorize_containment(decision).basis,
    }


@dataclass
class CaseResult:
    case_id: str
    kind: str
    summary: Dict[str, Any]
    violations: List[str]           # broken safety bounds (expect)
    pin_diff: Dict[str, Tuple[Any, Any]]   # field -> (pinned, now); empty when pins were not checked or match

    @property
    def passed(self) -> bool:
        return not self.violations and not self.pin_diff


@dataclass
class GuardReport:
    results: List[CaseResult]
    overrides: Dict[str, Any]
    pins_checked: bool
    elapsed_ms: float

    @property
    def failures(self) -> List[CaseResult]:
        return [r for r in self.results if not r.passed]

    @property
    def passed(self) -> bool:
        return bool(self.results) and not self.failures

    def describe(self, limit: int = 20) -> str:
        if self.passed:
            return f"golden guard: {len(self.results)} case(s) passed"
        lines = [f"golden guard: {len(self.failures)} of {len(self.results)} case(s) failed"
                 + (f" under {self.overrides}" if self.overrides else "")]
        for r in self.failures[:limit]:
            lines += [f"  {r.case_id} ({r.kind}): {v}" for v in r.violations]
            lines += [f"  {r.case_id} ({r.kind}): {k} pinned {a!r}, now {b!r}" for k, (a, b) in r.pin_diff.items()]
        return "\n".join(lines)


def _rank(state: str) -> int:
    return STATE_ORDER.index(state) if state in STATE_ORDER else -1


def check_expectation(expect: Expectation, summary: Mapping[str, Any]) -> List[str]:
    out = []
    state = summary["state"]
    if expect.state_at_least is not None and _rank(state) < _rank(expect.state_at_least):
        out.append(f"missed: state {state}, must be at least {expect.state_at_least}")
    if expect.state_at_most is not None and _rank(state) > _rank(expect.state_at_most):
        out.append(f"over-escalated: state {state}, must be at most {expect.state_at_most}")
    if expect.containment is not None and summary["containment_basis"] not in expect.containment:
        out.append(f"containment basis {summary['containment_basis']!r}, allowed {list(expect.containment)}")
    return out


def run_case(case: GoldenCase, overrides: Optional[Mapping[str, Any]] = None,
             check_pins: Optional[bool] = None) -> CaseResult:
    """Decides the case (with `overrides` replacing DecisionParameters fields) and checks it. Pins are checked only
    under the case's own parameters (default: when there are no overrides). A decide() error is a failure, never a pass."""
    overrides = dict(overrides or {})
    check_pins = (not overrides) if check_pins is None else check_pins
    params = dataclasses.replace(case.params, **overrides) if overrides else case.params
    try:
        decision, _merged = live_engine.decide(case.gathered, params)
        summary = decision_summary(decision)
    except Exception as e:  # noqa: BLE001 -- the guard reports, it never raises on a case
        return CaseResult(case.case_id, case.kind, {}, [f"decide() raised {type(e).__name__}: {e}"], {})
    violations = check_expectation(case.expect, summary)
    pin_diff: Dict[str, Tuple[Any, Any]] = {}
    if check_pins:
        if not case.pinned:
            violations.append("no pin recorded")
        for key in sorted(set(case.pinned) | set(summary)):
            if case.pinned.get(key) != summary.get(key):
                pin_diff[key] = (case.pinned.get(key), summary.get(key))
    return CaseResult(case.case_id, case.kind, summary, violations, pin_diff)


def run_guard(cases: Optional[Sequence[GoldenCase]] = None, overrides: Optional[Mapping[str, Any]] = None,
              check_pins: Optional[bool] = None) -> GuardReport:
    """Every case, decided under its own parameters with `overrides` applied. With overrides (a challenger, or a
    champion's tuned values) only the safety bounds are checked; without, the pins too."""
    cases = load_cases() if cases is None else cases
    started = time.perf_counter()
    results = [run_case(c, overrides, check_pins) for c in cases]
    pins = (not overrides) if check_pins is None else check_pins
    return GuardReport(results, dict(overrides or {}), pins, (time.perf_counter() - started) * 1000.0)


def guard_parameter_value(parameter: str, value: Any, cases: Optional[Sequence[GoldenCase]] = None
                          ) -> Optional[GuardReport]:
    """The guard for one candidate value of one tunable. None when `parameter` is not read by decide() (the golden
    set says nothing about it -- live_engine.DECIDE_PARAMETERS)."""
    if parameter not in live_engine.DECIDE_PARAMETERS:
        return None
    return run_guard(cases, overrides={parameter: value})


def propose(cases: Sequence[GoldenCase], reason: str) -> Tuple[List[GoldenCase], List[str]]:
    """New pins = what the current code decides. Returns the proposed cases and a per-case diff; a changed case gets
    `reason` recorded as its pinned_reason. Never writes anything (see the module docstring)."""
    if not reason.strip():
        raise ValueError("a pin change needs a reason")
    proposed, diff = [], []
    for case in cases:
        result = run_case(case, check_pins=True)
        if not result.summary:
            raise RuntimeError(f"{case.case_id}: {result.violations}")
        if result.pin_diff:
            diff.append(f"{case.case_id}:")
            diff += [f"  {k}: {a!r} -> {b!r}" for k, (a, b) in result.pin_diff.items()]
            case = dataclasses.replace(case, pinned=result.summary, pinned_reason=reason.strip())
        violations = check_expectation(case.expect, result.summary)
        diff += [f"  {case.case_id}: STILL VIOLATES ITS SAFETY BOUNDS: {v}" for v in violations]
        proposed.append(case)
    return proposed, diff


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Golden guard on the pure decision engine.")
    parser.add_argument("--cases", default=str(DEFAULT_CASES_PATH))
    parser.add_argument("--check", action="store_true", help="run every case, pins and bounds (exit 1 on failure)")
    parser.add_argument("--propose", metavar="OUT", help="write proposed pins to OUT (never to the cases file)")
    parser.add_argument("--reason", default="", help="why the decisions change (required with --propose)")
    args = parser.parse_args(argv)
    cases = load_cases(Path(args.cases))
    if args.propose:
        if Path(args.propose).resolve() == Path(args.cases).resolve():
            parser.error("--propose writes a separate file; review it, then replace the cases file in a commit")
        proposed, diff = propose(cases, args.reason)
        Path(args.propose).write_text(dump_cases(proposed), encoding="utf-8", newline="\n")
        print("\n".join(diff) if diff else "no pin changes")
        return 0
    report = run_guard(cases)
    print(report.describe())
    print(f"({len(report.results)} cases, {report.elapsed_ms:.1f} ms)")
    return 0 if report.passed else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
