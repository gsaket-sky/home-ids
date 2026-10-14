"""
Scenario catalogue (DETECTION_CORE_REWORK.md J4, MASTER_TODO 0d P0): attack and benign scenarios as DATA, compiled into
golden cases (argus/golden/guard.py) for the continuous guard.

A scenario spec (`scenarios.json`) states what happens and what must follow, in the target vocabulary of the escalation
ladder (design C), independent of how today's engine reaches it:

  outcome  none     -- nothing for a person (BENIGN / ANOMALOUS), never containment
           watch    -- one attack family: the watch list (today: SUSPICIOUS), never containment
           alert    -- corroborated: HIGH or above
           contain  -- HIGH or above AND containment on the named basis

Each spec has a timeline of stages (an offset per time shape: burst / spread / slow), entities by placeholder ("$C2"),
optional intel facts (used only in the "on" intel setup), framework references (ATT&CK technique ids, D3FEND defence
ids, NIST behaviour ids -- argus/golden/frameworks/), and its benign twin (an attack's look-alike that must stay quiet,
or the attack a benign spec mirrors).

Where today's engine knowingly falls short of the target, the spec carries a `known_gap` (the phase that closes it, why,
and today's bounds): the guard then enforces today's bounds -- a regression below today still fails -- and the
coverage report lists the open gap. Closing the phase removes the gap and the guard enforces the target. A spec that
needs a layer which does not exist yet (sessions, tunnel facts, a new detector) is `status: pending` with that phase;
it is part of the coverage map but compiles to no case.

Compilation is deterministic: the cycle is decided at the last stage's time (T0); earlier stages' items arrive as the
graph window's history (`windowed_v2`), the last stage's as this cycle's evidence (`fresh_v2`). Intel setups: "off"
(feeds disabled, no reputation), "failing" (feeds unavailable, no reputation -- must decide like "off": a failing feed
is never a verdict, R6), "on" (the spec's intel facts). Compiled cases are frozen into cases.json like any other golden
(tests/golden_case_builders.py merges them); the coverage test proves spec and frozen input still agree.
"""
import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from argus.evidence.model import Evidence, NO_DESTINATION
from argus.golden.guard import Expectation, GoldenCase
from argus.hypotheses.independence import family_for
from argus.ops.live_engine import CHAMPION_DEFAULTS, GatheredCycle, PeerStats, _ReputationCandidate
from intelligence.reputation.classifier import ReputationClassifier

SCENARIOS_PATH = Path(__file__).with_name("scenarios.json")
T0 = 1_800_000_000.0
DEVICE = "golden-device"
SHAPES = ("burst", "spread", "slow")
INTEL_SETUPS = ("off", "failing", "on")
OUTCOMES = ("none", "watch", "alert", "contain")
PHASES = ("P1", "P2", "P3", "P3b", "P4", "P5", "identity")
_SOURCES_BASE = {"zeek": "ok", "dns": "ok", "geoip": "ok"}
_FEED_STATE = {"off": "disabled", "failing": "unavailable", "on": "ok"}

_classifier = ReputationClassifier()


class SpecError(ValueError):
    pass


def outcome_expectation(outcome: str, basis: Optional[str] = None) -> Expectation:
    if outcome == "none":
        return Expectation(state_at_most="ANOMALOUS", containment=(None,))
    if outcome == "watch":
        return Expectation(state_at_least="SUSPICIOUS", state_at_most="SUSPICIOUS", containment=(None,))
    if outcome == "alert":
        return Expectation(state_at_least="HIGH")
    if outcome == "contain":
        if not basis:
            raise SpecError("outcome 'contain' needs a basis")
        return Expectation(state_at_least="HIGH", containment=(basis,))
    raise SpecError(f"unknown outcome {outcome!r}")


@dataclass(frozen=True)
class Scenario:
    spec: Mapping[str, Any]

    @property
    def id(self) -> str:
        return self.spec["id"]

    @property
    def pending(self) -> bool:
        return self.spec.get("status") == "pending"

    @property
    def frameworks(self) -> Mapping[str, Sequence[str]]:
        return self.spec.get("frameworks", {})

    def intel_setups(self) -> Tuple[str, ...]:
        return INTEL_SETUPS if self.spec.get("intel") else ("off", "failing")

    def shapes(self) -> Tuple[str, ...]:
        return tuple(self.spec.get("shapes") or ("burst",))

    def target(self, intel: str) -> Tuple[str, Optional[str]]:
        """`expect` is one outcome ({"outcome": ...}) or one per intel setup with a default
        ({"default": {...}, "on": {...}})."""
        exp = self.spec["expect"]
        if "outcome" not in exp:
            exp = exp.get(intel) or exp["default"]
        return exp["outcome"], exp.get("basis")

    def gap_for(self, shape: str, intel: str) -> Optional[Mapping[str, Any]]:
        for gap in self.spec.get("known_gaps", ()):
            applies = gap.get("applies", {})
            if shape in applies.get("shapes", SHAPES) and intel in applies.get("intel", INTEL_SETUPS):
                return gap
        return None


def _resolve(value: Any, entities: Mapping[str, str]) -> Any:
    if isinstance(value, str) and value.startswith("$"):
        if value[1:] not in entities:
            raise SpecError(f"unknown entity {value}")
        return entities[value[1:]]
    return value


def _evidence(item: Mapping[str, Any], entities: Mapping[str, str], ts: float) -> Evidence:
    etype = item["type"]
    family = family_for(etype)
    if not family:
        raise SpecError(f"evidence type {etype!r} has no family in the registry")
    return Evidence(device_id=DEVICE, destination_id=_resolve(item.get("dest", NO_DESTINATION), entities),
                    evidence_type=etype, independence_family=family, timestamp=ts, source="golden-scenario",
                    confidence=float(item.get("confidence", 0.9)), value=item.get("value", 1.0),
                    provenance=item.get("provenance", ""),
                    features={k: _resolve(v, entities) for k, v in (item.get("features") or {}).items()})


def compile_case(sc: Scenario, shape: str, intel: str) -> GoldenCase:
    spec, entities = sc.spec, sc.spec.get("entities", {})
    stages = spec["timeline"]
    offsets = [float(st["at"][shape] if isinstance(st["at"], Mapping) else st["at"]) for st in stages]
    last = max(offsets)
    fresh: List[Evidence] = []
    windowed: List[Evidence] = []
    for st, at in zip(stages, offsets):
        ts = T0 - (last - at)
        items = [_evidence(i, entities, ts) for i in st.get("evidence", ())]
        (fresh if at == last else windowed).extend(items)
    ctx = spec.get("context", {})
    derived: List[Any] = [_evidence(i, entities, T0) for i in ctx.get("derived", ())]
    rep = _classifier.classify("unlisted.example")
    intel_facts = spec.get("intel") or {}
    if intel == "on" and intel_facts:
        r = intel_facts.get("reputation") or {}
        if r:
            rep = _classifier.classify(_resolve(r["domain"], entities),
                                       **{k: v for k, v in r.items() if k != "domain"})
        fresh += [_evidence(i, entities, T0) for i in intel_facts.get("evidence", ())]
        derived += [_ReputationCandidate(_resolve(c["destination"], entities), float(c["tier"]),
                                         T0 - float(c["age"])) for c in intel_facts.get("cached", ())]
    peer = ctx.get("peer")
    device = spec.get("device", {})
    gathered = GatheredCycle(
        device_id=DEVICE, ts=T0, device_type=device.get("type", "laptop"), is_safe=bool(device.get("is_safe", False)),
        baseline_familiarity=float(device.get("familiarity", 0.0)),
        features=MappingProxyType({"zeek_honeypot_hits": 0, **ctx.get("features", {})}), rep_vector=rep,
        fresh_v2=tuple(fresh), windowed_v2=tuple(windowed), graph_derived=tuple(derived),
        peer_stats=PeerStats(**peer) if peer else None,
        baseline_v2=tuple(_evidence(i, entities, T0) for i in ctx.get("baseline", ())),
        domain_age_v2=tuple(_evidence(i, entities, T0) for i in ctx.get("domain_age", ())),
        sources=MappingProxyType({**_SOURCES_BASE, "threat_feeds": _FEED_STATE[intel]}),
    )
    outcome, basis = sc.target(intel)
    gap = sc.gap_for(shape, intel)
    if gap is not None:
        today = gap["today"]
        expect = Expectation(today.get("state_at_least"), today.get("state_at_most"),
                             None if today.get("containment") is None else tuple(today["containment"]))
        note = f"target {outcome}; known gap until {gap['phase']}: {gap['why']}"
    else:
        expect = outcome_expectation(outcome, basis)
        note = f"target {outcome}"
    fw = "; ".join(f"{k}: {', '.join(v)}" for k, v in sorted(sc.frameworks.items()) if v)
    return GoldenCase(case_id=f"scn:{sc.id}@{shape}/{intel}", title=spec["title"], kind=spec["kind"],
                      origin=f"scenario {sc.id} ({fw})", gathered=gathered, params=CHAMPION_DEFAULTS, expect=expect,
                      note=note)


def compile_all(scenarios: Sequence[Scenario]) -> List[GoldenCase]:
    return [compile_case(sc, shape, intel) for sc in scenarios if not sc.pending
            for shape in sc.shapes() for intel in sc.intel_setups()]


def validate(scenarios: Sequence[Scenario]) -> List[str]:
    """Structural problems in the catalogue (the coverage test fails on any)."""
    out: List[str] = []
    ids = [sc.id for sc in scenarios]
    by_id = {sc.id: sc for sc in scenarios}
    if len(ids) != len(set(ids)):
        out.append("duplicate scenario ids")
    for sc in scenarios:
        s = sc.spec
        for key in ("id", "title", "kind", "frameworks", "expect"):
            if key not in s:
                out.append(f"{sc.id}: missing {key}")
        if s.get("kind") not in ("attack", "benign"):
            out.append(f"{sc.id}: kind must be attack or benign")
        twin = s.get("twin")
        if not twin or twin not in by_id:
            out.append(f"{sc.id}: needs a twin that exists (attack -> benign look-alike, benign -> its attack)")
        elif by_id[twin].spec.get("kind") == s.get("kind"):
            out.append(f"{sc.id}: twin {twin} must be of the other kind")
        if sc.pending:
            p = s.get("pending") or {}
            if p.get("phase") not in PHASES or not p.get("needs"):
                out.append(f"{sc.id}: pending needs a phase ({'/'.join(PHASES)}) and what it needs")
            continue
        if not s.get("timeline"):
            out.append(f"{sc.id}: active scenario without a timeline")
        for shape in s.get("shapes") or ("burst",):
            if shape not in SHAPES:
                out.append(f"{sc.id}: unknown shape {shape}")
        try:
            for intel in sc.intel_setups():
                outcome, basis = sc.target(intel)
                outcome_expectation(outcome, basis)
                if s.get("kind") == "benign" and outcome != "none":
                    out.append(f"{sc.id}: a benign scenario's target is 'none'")
            for gap in s.get("known_gaps", ()):
                if gap.get("phase") not in PHASES or not gap.get("why") or "today" not in gap:
                    out.append(f"{sc.id}: a known gap needs phase, why and today's bounds")
            compile_all([sc])
        except (SpecError, KeyError, TypeError, ValueError) as e:
            out.append(f"{sc.id}: does not compile: {type(e).__name__}: {e}")
    return out


def load_scenarios(path: Optional[Path] = None) -> List[Scenario]:
    doc = json.loads(Path(path or SCENARIOS_PATH).read_text(encoding="utf-8"))
    return [Scenario(MappingProxyType(dict(s))) for s in doc["scenarios"]]


def scenario_case_ids(scenarios: Sequence[Scenario]) -> Dict[str, List[str]]:
    return {sc.id: [f"scn:{sc.id}@{shape}/{intel}" for shape in sc.shapes() for intel in sc.intel_setups()]
            for sc in scenarios if not sc.pending}
