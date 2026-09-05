# HEE Roadmap — items considered and deliberately not built

Companion to [`DECISION_LOGIC_DEPENDENCY_MAP.md`](DECISION_LOGIC_DEPENDENCY_MAP.md)'s
Gap 6 entry (third-party Hypothesis-Evidence-Engine architecture review). That entry
tracks what's *been shipped*; this document tracks what was **considered and explicitly
not built**, with the actual reasoning — so a future session doesn't have to re-derive
"was this forgotten, or deliberately skipped, and why" from scratch. Each item below was
raised during the Gap 6 audit or the Phase 63/63b follow-up (2026-09-04) and stayed open
on purpose, not by oversight.

**Living document**: when one of these items is picked up, move it out of here into
`DECISION_LOGIC_DEPENDENCY_MAP.md`'s Gap 6 row (or a new Gap entry) the same way every
other phase has been recorded, and delete its section here.

---

## 4. `EvidenceGraph` as the primary live store (not additive/on-demand)

`EvidenceGraph` (`hypotheses/evidence_graph.py`, Phase 61) is built fresh per-report
from `hee_evidence_types` (type names only — no persisted value/domain/confidence, so
destination-targeting edges never populate). Discussed 2026-09-04 whether it should
become the thing `HypothesisEngine.evaluate_all()` and `decision_engine.py` actually
read from, instead of the flat `EvidenceStore`.

**Why it should be done:** would enable genuine cross-cycle/multi-hop queries a flat
per-device list can't represent — "has this device seen this destination before via a
different evidence family," "do multiple devices' evidence point at the same
destination."

**Why it was not done:**
- **Duplicates existing, narrower, tested mechanisms.** "Is this destination familiar
  to this device" is already `fp_engine.get_baseline_familiarity()`. "Do multiple
  devices' evidence cluster on shared infrastructure" is already Phase 53's
  `_is_campaign_corroborated()`. A general graph would be a second way to answer
  questions this codebase already answers in purpose-built form.
- **Raises the stakes of a bug.** Today a bug in `EvidenceGraph` makes a report render
  wrong. Made primary, the same bug would produce a wrong verdict — a cosmetic/audit
  component becoming decision-load-bearing.
- **Storage growth with no database.** Every persisted-state file in this codebase
  (`ollama_analysis_cache.json`, `confidence_calibration.json`, the fp trust cache) is
  a hand-rolled JSON file with its own TTL/pruning logic — and staleness bugs in
  exactly that pattern are Gap 6's own root cause. A permanently-accumulating graph is
  one more file with the same failure mode, on Pi-class target hardware with no
  headroom to spare.
- **Breaks the current evaluation model.** Every `Hypothesis.evaluate()` is a pure
  function over "what's true this cycle," rebuilt fresh each run. Making the graph
  primary means rewriting that snapshot model, not just swapping a data structure —
  the kind of change this project's own standing practice says needs a plan first, not
  something folded in opportunistically.

**Effort to pick up:** large — architectural, touches every hypothesis class,
`decision_engine.py`, and `pipeline.py`. Not recommended unless a specific need
emerges that `fp_engine`/campaign-correlation genuinely can't answer.

---

## 5. Calibrated confidence as a `DeterministicValidator` PASS/FAIL gate

Phase 63b wired `ConfidenceCalibrator.get_calibrated()` into immunization TTL only
(self-activating once a bucket has 20 real samples). The alternative — offered and
explicitly not chosen — was letting a calibrated value reject a verdict outright, even
when raw LLM confidence and every structural check passed.

**Why it should be done:** closest match to the original review's own sketch
("Validator: PASS" driven by a calibrated number, not raw LLM self-assessment) — would
let a confidence bucket's real-world reliability actively veto a verdict, not just
adjust how long it's trusted.

**Why it was not done:** user's explicit choice (asked directly, 2026-09-04) — TTL
modulation over validator gating. Reasoning: a hard pass/fail gate resting on a coarse,
per-bucket aggregate statistic (not specific to the alert at hand) is riskier to
activate off a `MIN_SAMPLES_FOR_CALIBRATION=20` floor than a reversible TTL adjustment.
A wrong TTL self-corrects the next cycle; a wrong hard rejection blocks an otherwise
fully-corroborated, structurally-clean verdict for a reason unrelated to that specific
alert's own evidence.

**Effort to pick up:** small — the calibrator and its `get_calibrated()` contract
already support this; it's a new check in `ai_soc.py`'s `DeterministicValidator`,
mirroring the shape of every existing check there (reject + `LOGGER.warning` +
`VALIDATOR_SCHEMA_VERSION` bump).

---

## 8. Evidence-provenance taxonomy module (`evidence_taxonomy.py`)

**Why it should be done:** was the originally-planned shared source of truth for
evidence categorization across Gaps 1-3's shadow-mode work — unifying how evidence
types are classified/labeled across the whole decision path instead of each consumer
(relevance breakdown, evidence graph, attack-shaped-evidence set) maintaining its own
adjacent notion of evidence grouping.

**Why it was not done:** deliberately deferred until Gaps 1-3's shadow-mode data
resolved, to avoid building a shared abstraction against still-unflipped logic that
might need rework. **Re-verified 2026-09-05** (was previously marked "status
unverified" — checked directly, not assumed): Gap 1 and Gap 2 are both live, but Gap 3
is only 1-of-4 flipped (honeypot freshness live; `arp_spoof`/`geofence`/
`confirmed_exploit` remain shadow-only pending live divergence evidence — see
`DECISION_LOGIC_DEPENDENCY_MAP.md`'s Gap 3 row). The precondition ("Gaps 1-3 resolved")
is still not met — correctly still blocked, not stale.

**Effort to pick up:** unknown until Gap 3's remaining three hard-stops flip live (or
are explicitly abandoned).
