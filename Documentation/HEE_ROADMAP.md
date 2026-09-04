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

## 1. Structured required/supporting/contradicting checklist per hypothesis

The third-party review's own mockup rendered a hypothesis evaluation as an explicit
checklist (`Required evidence: Internal reconnaissance ... ABSENT`, `Supporting
evidence: ICMP ... PRESENT, NOT attack-specific`, etc.) rather than a paragraph.

**Why it should be done:** every `Hypothesis` subclass in `hypotheses/engine.py`
already computes this internally (`required_satisfied`, `strong_score`,
`contradicting_score` — e.g. `NetworkIntrusionHypothesis._evaluate_impl()`), it's just
never rendered. Exposing it would give an operator (or a future debugging session) a
direct, at-a-glance answer to "why did this hypothesis fire/not fire" without reading
`evaluate()`'s source — the single clearest audit-trail improvement left on the table.

**Why it was not done:** the underlying *safety* problem this would visualize is
already closed by two things that ship without it — Phase 59/63's relevance breakdown
(which evidence is even relevant to this hypothesis) and Phase 63's hypothesis-
independence check (which other hypotheses had to be ruled out). This item is a
presentation/rendering task on top of data that already exists and is already
consulted, not a decision-logic gap — it was correctly triaged as lower priority than
the two structural gaps (relevance coverage, hypothesis independence) that had a
confirmed live incident behind them, and the Phase 63 session was scoped to those two.

**Effort to pick up:** small. A new `render_checklist()`-style function reading the
same `required_satisfied`/`strong_score`/`contradicting_score` state each `Hypothesis`
already exposes, rendered into the `.md` report next to the existing "Evidence
relevance" line.

---

## 2. Full 4-way SUPPORTS/CONTRADICTS/NEUTRAL/IRRELEVANT evidence taxonomy

The review's suggested vocabulary classifies every evidence item against a hypothesis
as one of 4 values; the current breakdown (`_evidence_relevance_breakdown()`,
`ollama_soc.py`) uses 3 (`present_relevant` / `absent_relevant` / `present_irrelevant`).

**Why it should be done:** matches the reviewer's vocabulary precisely, and a genuine
CONTRADICTS value would be more explicit than the current split between "irrelevant"
and the separately-tracked `contradicting_evidence` self-consistency check.

**Why it was not done:** the same ground is already covered under different names —
`contradicting_evidence` (the LLM's own free-text list, checked for self-consistency
against `recommended_action` in `ai_soc.py:188-198`) already plays CONTRADICTS' role.
Renaming/restructuring two working, tested mechanisms into new vocabulary that
computes the same thing was judged not worth the churn — a real "would this actually
change any decision" test, not just a stylistic one, and it doesn't.

**Effort to pick up:** moderate, mostly rework — would touch the prompt schema, the
report renderer, and both regression suites that assert the current 3-way shape.

---

## 3. "Correct device identity" check in the immunization checklist

The review's 10-item immunization checklist includes "correct device identity"; the
current `DeterministicValidator`/`mark_false_positive()` path doesn't independently
verify it.

**Why it should be done:** an immunization scoped to the wrong device_id fragment could
under-protect (the real device keeps alerting under a different fragment) or apply
trust to a device that no longer canonically exists.

**Why it was not done — status corrected 2026-09-04:** this was previously believed
blocked on a larger, unfixed device-identity-fragmentation problem. That's now stale —
see [`DEVICE_IDENTITY_LIFECYCLE.md`](DEVICE_IDENTITY_LIFECYCLE.md): the retroactive-
merge fix shipped and was live-verified 2026-08-25 (`StateManager.merge_into_canonical()`
+ live triggers in `identity.py`). The one remaining residual gap is unrelated and
narrow (orphaned `device_fp_profiles.json` entries awaiting a maintenance-window
cleanup, not an identity-*correctness* problem). This item is **no longer blocked** —
it just hasn't been picked up since the Gap 6 audit predated the corrected status.

**Effort to pick up:** small. A check in `ai_soc.py`'s validator or `mark_false_positive()`
confirming the immunized `device_id` matches `DeviceIdentityManager`'s current
canonical resolution for that device before persisting the trust-cache entry.

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

## 6. Malicious-track calibration wiring

`ConfidenceCalibrator` maintains two separate tracks (benign, malicious). Phase 63b
consumes only the benign track's `get_calibrated()` output.

**Why it should be done:** would extend the same reliability-tracking benefit
symmetrically to the malicious verdict path, closer to the original review's treatment
of both classes equally.

**Why it was not done:** deliberately conservative by design —
`confidence_calibration.py`'s own module docstring gives the malicious track a
skewed-conservative prior (`Beta(1,3)`, mean 0.25) specifically because malicious
labels are inherently rare on a healthy home network (a feature, not a data gap to
route around). Malicious verdicts already trigger consequential, harder-to-reverse
actions (`record_confirmed_threat()`, sigma-shift tuning, blocking) — coupling a
statistically thin track to that path risks the worse-case failure direction (dampening
a real threat, or over-trusting an early noisy read to escalate one) more than the
benign-TTL case risked anything.

**Effort to pick up:** trivial mechanically (same `_apply_confidence_calibration()`
shape, `"malicious"` track instead of `"benign"`) — but should wait until the malicious
track has separately proven out with real volume, per its own design intent. Check
`ConfidenceCalibrator.sample_counts()["malicious"]` before considering this.

---

## 7. Withheld-pattern remediation (15 patterns from the 2026-09-03 run) + production deploy

**Why it should be done:** those 15 withheld patterns are sitting on pre-Phase-57
stale-schema cache entries (the same root-cause bug the 3 immunizations audited in Gap
6's root-cause investigation had) — until rebuilt under the new fingerprint+version
cache key, they benefit from none of the fixes shipped since (Phases 57 through 63b).

**Why it was not done:** deliberately deferred in `DECISION_LOGIC_DEPENDENCY_MAP.md`
until every remaining Gap 6 item landed, specifically so the cache rebuild only has to
happen once (carrying the final key from day one) instead of twice. **That condition is
now met** (Phase 63/63b landed 2026-09-04) — this is unblocked and actionable, not
stuck on anything further. Requires: full regression suite run (ask first, per standing
preference), production deploy, `ollama_analysis_cache.json` clear, `soc.service`
restart.

**Effort to pick up:** operational, not code — a deploy checklist item.

---

## 8. Evidence-provenance taxonomy module (`evidence_taxonomy.py`)

**Why it should be done:** was the originally-planned shared source of truth for
evidence categorization across Gaps 1-3's shadow-mode work — unifying how evidence
types are classified/labeled across the whole decision path instead of each consumer
(relevance breakdown, evidence graph, attack-shaped-evidence set) maintaining its own
adjacent notion of evidence grouping.

**Why it was not done:** deliberately deferred until Gaps 1-3's shadow-mode data
resolved, to avoid building a shared abstraction against still-unflipped logic that
might need rework. **Status unverified as of this writing** — check
`state/shadow_decisions.jsonl` accumulation and Gap 1/2/3's live-flip status in
`DECISION_LOGIC_DEPENDENCY_MAP.md` before assuming this is still correctly blocked.

**Effort to pick up:** unknown until the shadow-data status above is re-checked.
