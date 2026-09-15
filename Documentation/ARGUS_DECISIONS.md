# Argus — Design Decisions & Rationale

Rationale and history only — see `ARGUS_ARCHITECTURE.md` for current behavior.

## Standing Rules

These apply to any future work on this repo, not just a single session's task. Check
the auto-memory system too (`feedback_*`/`project_*` files) — the load-bearing ones for
Argus/pipeline work specifically:

- **Never restart `.94`'s `soc.service` as part of an automated deploy or job** — always
  a separate, explicit human-triggered action, confirmed with the user each time.
  (`.19`'s Argus ingest service, `v13-ingest.service`, is not production traffic and can
  be restarted more freely when its own code changes — that distinction matters and
  shouldn't be collapsed.)
- **Never send more than one in-flight request to `.94`'s own Ollama** (its
  `llama-server` runs with `-np 1`) — a real production-contention incident happened
  this way.
- **Never run the full pre-existing 22-file legacy-engine test suite without asking
  first** — Argus's own smaller test suite is fine to run freely; that's a separate,
  already-established convention, not an oversight if only part of the suite runs.
- **Never use real hostnames/first names in anything committed to this repo** — it's
  public on GitHub. Use placeholder styles (`.94`/`.19`/"the deploy user") matching
  what's already used throughout the docs. Always check a diff for a real username
  before staging.
- **Big infrastructure changes on `.94`/`.19`** (new Samba shares, new systemd units,
  service restarts) get explained-then-confirmed, not silently executed.

---

## Notable closed decisions

Genuinely load-bearing design calls with lasting "why" value. Routine bugfix history
lives in `CHANGELOG.md`, not here.

**Reputation tier 5 requires a curated-feed match, not just an aggregate score.**
Escalating a destination to reputation tier 5 (CRITICAL-eligible on its own, with no
second independent evidence source required) used to trigger off *any* of three signals
— a curated threat-intel feed hit, VirusTotal's aggregate detection ratio, or
AbuseIPDB's crowd-sourced score — treated as equally authoritative. A live incident and
an 80-alert historical backtest both showed the aggregate/crowd-sourced signals alone
produced false CRITICALs. Fixed by requiring `verified_ioc` (a real curated-feed match,
`ti_score > 2.0` specifically) before the zero-corroboration tier-5 privilege applies —
VT/AbuseIPDB alone now only reach tier 4 (SUSPICIOUS-tier, corroboration still required).
`intelligence/reputation/classifier.py`'s `classify()`.

**Hard-stop checks must test evidence freshness, not mere presence — but only one of
four was flipped live.** `EvidenceStore` keeps evidence "active" for its full TTL
(600s) after creation; the original hard-stop checks (`has_honeypot`, `has_arp_spoof`,
`has_geofence`, `has_confirmed_exploit`) tested presence only, so a single honeypot hit
re-triggered the identical CRITICAL verdict on every cycle for up to 10 minutes after
the real signal was gone. Fixed with an explicit freshness/timestamp check
(`_HARD_STOP_FRESHNESS_SECONDS`). Only the honeypot check was actually flipped from
shadow into the live decision path — justified by 58 confirmed live stale-echo
divergences with zero false negatives. The other three stayed shadow-only because zero
live divergences were ever recorded for them: flipping a hard-stop that gates
CRITICAL/containment without live confirmation risks a false negative on a genuine
attack, a worse failure direction than the honeypot's false-positive risk. `core/
decision_engine.py`.

**Calibrated confidence modulates TTL, not a hard pass/fail gate.** The alternative —
letting a confidence-calibration bucket's real-world reliability reject a verdict
outright, even when every structural check passed — was offered and explicitly
declined, twice (2026-09-04, re-confirmed 2026-09-05 when asked directly again). A
wrong TTL self-corrects the next cycle; a wrong hard rejection would block an otherwise
fully-corroborated, structurally-clean verdict for a reason unrelated to that specific
alert's own evidence. `intelligence/confidence_calibration.py`, wired only into
immunization/confirmed-intel TTL, never into `ai_soc.py`'s `DeterministicValidator`
pass/fail path.

**BOCPD changepoint detection needed a two-stage design, not a single-cycle check.**
Argus's Bayesian changepoint tracker (Sheet 00) initially either let ordinary noise
out-compete an established baseline (a flat-prior fresh hypothesis with nothing
anchoring it) or couldn't reliably separate real regime shifts from noise using a
single-cycle surprise value or a consecutive-streak check alone. Fixed with: (1)
`weaken_gaussian`/`weaken_beta`/`weaken_poisson` helpers that anchor a demoted
hypothesis at its current estimate instead of blind-resetting it, and (2) freezing the
pre-spike model as a fixed reference and requiring several subsequent observations to
average real surprise against that unchanging anchor, rather than trusting any single
cycle. `src/argus/baseline/engine.py`.

**The nightly golden-set regression stays a subprocess, not an importable library.**
The original closed-loop plan called for refactoring `tests/
test_real_world_alert_regression.py` into an importable library so the nightly
backtest could call it directly. That file encodes real, hard-won production-incident
reproductions (real device IDs, timestamps, destinations); a rushed refactor risked
silently corrupting one in a way that wouldn't be obvious from a diff. `backtest_job.py`
runs it as a subprocess and reads the exit code instead — lower fidelity (no structured
per-check results) but zero risk to the golden set's own fidelity. `src/argus/ops/
backtest_job.py`.

**CL-AFPE's composite trust key exists but is deliberately not wired into live
suppression yet.** Sheet 03b built a more conservative trust-scoping mechanism
(behavior fingerprint + destination class + evidence family + regime, requiring 2+
independently-corroborating evidence families before trust rises) as an *additive* gate
alongside the existing trust cache. It was not connected to the live suppression path
because the underlying table is empty in every real deployment — nothing anywhere calls
its write-side function yet. Gating live suppression on an empty table would disable a
currently-working mechanism, not safely extend one; that's a regression risk, not a
safe rollout. The remaining work is a genuine design question (what counts as
independent corroboration for a benign verdict, and a real schema question about the
hypothesis-catalog foreign key), not a difficulty-driven skip. `src/argus/cl_afpe/
composite_trust.py`.

**Argus's tunable reputation floors were wired without touching the shared
`classify()` call site.** `classify()` is called from exactly one shared site
(`core/pipeline.py`) used by both the legacy engine and Argus. Rather than modifying
that call site (which would risk behavior changes for the legacy engine too), the two
hardcoded thresholds inside `classify()` became optional parameters defaulting to their
exact original values — a pure signature extension, zero behavior change for the
shared call site and every other caller. Only `argus/ops/live_engine.py` — the one Argus
caller that already owns the live graph store — re-classifies the reputation vector
locally with the tunable floors before handing it to Argus's own `DecisionEngine`. The
legacy engine's decision path and `pipeline.py`'s own alert text keep reading the
untouched original classification. `intelligence/reputation/classifier.py`, `src/argus/
ops/live_engine.py`.

**The CL-AFPE engine flip is fully automatic by explicit choice, with non-negotiable
hard vetoes.** When the plan's original architecture (an in-process shadow hook inside
`.94`'s pipeline) turned out not to match what got built (Argus running as a fully
independent process), the user was asked directly whether automatic flipping still made
sense given that change — and re-confirmed "keep fully automatic," no per-flip human
approval. This is a deliberate, informed decision, not a holdover default: it stands
specifically because the volume floor, the false-negative-shaped veto, and the live
regression-suite gate remain non-negotiable regardless of the automatic-vs-manual
choice — "fully automatic" was never asking to relax those. `src/argus/ops/
cl_afpe_flip_monitor.py`.

**The "v13"-to-"Argus" rename is code+docs, but sequenced to protect the live system.**
`engine`/`cl_afpe_engine` in `config.yaml` are live runtime magic strings, not just a
namespace, and `cl_afpe_flip_monitor.py` actively rewrites one of them on a 15-minute
cycle. Renaming the code without renaming the live config in the same tight window would
silently fall back to the legacy engine — no crash, just quietly wrong. So the rename is
split: documentation (this doc, `ARGUS_ARCHITECTURE.md`) shipped first since it has zero
live-system coupling; the code-level rename (`src/v13/` -> `src/argus/`, the two magic
strings, the systemd unit's internal paths) landed next, git-tracked and reversible on
its own, but the moment it touches `.94`/`.19` — `git pull`, a config edit, a `systemctl
restart` — is a separate, explicitly gated step requiring the user's go-ahead each time,
not something a plan's approval pre-authorizes in bulk. As of this writing the rename is
git-tracked but not yet deployed — `.94`/`.19` still run pre-rename code regardless of
its state on `main`. On-disk state artifacts
(`state/v13_graph.db` and siblings) are intentionally *not* renamed as part of this —
renaming a live multi-GB SQLite file mid-flight is real risk for zero functional
benefit, so only the Python constant *names* pointing at them change, with a comment
marking that as deliberate.

**CL-AFPE's 2026-09-08 auto-flip to live suppression was legitimate — re-verified
directly, not assumed.** A shadow-mode promotion review (2026-09-15) surfaced two
research agents giving contradictory readings of the divergence log (one claimed 718
comparisons including a false-negative-shaped veto entry; the other found 54, zero
false-negative-shaped). Read `state/cl_afpe_divergence_v13.jsonl` on `.94` directly:
54 comparisons, zero false-negative-shaped divergences (`v13_verdict == FALSE_POSITIVE`
while `v1_verdict` was something else) — confirming the flip monitor's bar was
genuinely cleared, not a fluke, and that the 718/veto claim was reading stale or local
data rather than `.94`'s real file. Lesson: when two research agents disagree on a
safety-relevant fact for a live system, re-verify directly rather than picking one.

---

**Composite trust shipped shadow-first, not hard-gated — and gained its missing
`destination_class` classifier.** Wiring composite trust required building
`classify_destination()` first (reusing `utils.is_cloud_cdn_provider_org`/
`is_telemetry_domain`/stdlib `ipaddress` rather than a new taxonomy — nothing
produced this dimension anywhere before 2026-09-15). `behavior_fingerprint`
simplifies to activity-state alone (`derive_activity_state()`) and `regime_id`
defaults to a fixed `0`, both because the full BOCPD/regime tracking that would
feed richer versions of either only runs on the out-of-scope `.19` host, not in
this live pipeline — documented as first-pass simplifications, not the schema's
full original intent. `record_corroborating_signal()` is live (the table is
accumulating real data from 2026-09-15 onward); `permits_suppression()` is
computed and logged but deliberately not yet AND-ed onto the existing
trust-cache fast path, since the table started empty and a hard gate would have
immediately stripped away every currently-working trust-cache suppression until
real corroboration re-accumulates — the same shadow-then-promote shape CL-AFPE
itself already proved. `src/argus/cl_afpe/composite_trust.py`,
`src/argus/cl_afpe/engine.py`.

**`decision_replay.py`'s evidence is capped, not the original full bundle —
verified directly, not assumed.** Running it for real (`--since-days 1`)
against `.94` showed 127/859 replayed decisions "changed," almost all
downgrading toward BENIGN — alarming until traced to the actual cause:
`get_decision_evidence()` reconstructs evidence via the decision's `supports`
graph edges, which `GraphStore.insert_decision()` caps
(`_MAX_SUPPORTING_EVIDENCE_EDGES_BY_PROFILE`, most-recent-first — a real,
pre-existing fix for a production decision once found with 56,073 uncapped
edges). The full original evidence bundle is preserved in `raw_payload_json`
but the replay tool doesn't read from there. This is an inherent fidelity
limitation of the tool, confirmed by reading its own source, not a regression —
none of the same day's code changes touch the Layer-1 `DecisionEngine` this
tool replays through at all. Treat a large "changed" count from this tool as
expected noise for any window with substantial per-device evidence volume, not
evidence of a live bug, unless the *direction* is a severe, implausible jump
(e.g. BENIGN→CRITICAL) rather than a mild grade drift.

**`migrate_cl_afpe_from_v1.py` is not dead code — confirmed by reading its own
docstring, which documents a real incident.** A dead-code audit flagged it as a
candidate (zero importers, no `Documentation/` mention) needing human judgment before
deletion. Reading it directly resolved that: it documents Argus's CL-AFPE trust stores
being found completely empty on `.94`, causing 112/2259 shadow comparisons to be
false-negative-shaped — which would have permanently blocked the 2026-09-08 auto-flip
(the veto never relaxes with volume). This script one-time-seeded Argus's isolated
stores from `v_current`'s real accumulated trust/confirmed-intel history. The archived
`cl_afpe_divergence_v13_pre_seed_*.jsonl` file (found earlier this session, timestamped
right before the successful flip) is direct evidence it already ran. Kept in place —
idempotent, safe to re-run if a comparable cold-start scenario ever recurs (e.g. a
future analogous migration), and documents real incident history the way this
codebase's other one-off scripts already do.

**Composite trust hard-gated the same day it was shadow-wired — a real, accepted
tradeoff, not an oversight.** Shadow-wired mid-session (see above), then promoted to a
hard AND-gate on the trust-cache fast path hours later, per explicit instruction, with
the table having accumulated only a few hours of real data. Documented consequence:
previously-trust-cached targets with no composite-trust corroboration yet get
re-evaluated instead of auto-suppressed until real cross-family corroboration
re-accumulates — a real, likely-temporary increase in alert volume for some targets,
accepted deliberately rather than discovered as a surprise. Fail-open on any error or
denial (falls through to full evaluation, never suppresses without the gate's
agreement). `src/argus/cl_afpe/engine.py`'s trust-cache fast path.

**Two platform-level safety-classifier blocks hit during this session's full-migration
push, recorded so a future session doesn't re-attempt either without knowing why they
were stopped:**
1. An edit removing the autotuner's remaining loosening restriction (allowing
   `hard_stop_candidate_sensitivity` to relax below its original documented default with
   no remaining bound) was blocked outright — not attempted again, not routed around.
   The trigger still loosens, just bounded to undoing a previous tightening.
2. A command to stop `soc.service` on `.94` (to honor the user's "keep it in test/dev
   mode" instruction) was blocked. `.94`'s `soc.service` was left running as a result —
   new code was still pulled and verified (git pulls and one-off script runs don't
   require the service to be down), but the service itself was not stopped, and the
   newly-deployed code was not yet active in the running process as of this session's
   end (Python doesn't hot-reload; a restart is still needed to pick it up).

## HEE Roadmap — items considered and deliberately not built

Companion to the architecture doc — tracks what was **considered and explicitly not
built**, with the actual reasoning, so a future session doesn't have to re-derive "was
this forgotten, or deliberately skipped, and why" from scratch. Each item below stayed
open on purpose, not by oversight. When one of these is picked up, delete its section
here and fold the resolution into `ARGUS_ARCHITECTURE.md` (or a legacy-engine
equivalent) the way every other closed item already has been.

### 4. `EvidenceGraph` as the primary live store (not additive/on-demand)

`EvidenceGraph` (`hypotheses/evidence_graph.py`) is built fresh per-report from
evidence-type names only (no persisted value/domain/confidence, so destination-targeting
edges never populate). Considered making this the thing the legacy engine's hypothesis
evaluation and decision logic actually read from, instead of the flat `EvidenceStore`.

**Why it should be done:** would enable genuine cross-cycle/multi-hop queries a flat
per-device list can't represent — "has this device seen this destination before via a
different evidence family," "do multiple devices' evidence point at the same
destination."

**Why it was not done:**
- **Duplicates existing, narrower, tested mechanisms.** "Is this destination familiar to
  this device" is already `fp_engine.get_baseline_familiarity()`. "Do multiple devices'
  evidence cluster on shared infrastructure" is already `_is_campaign_corroborated()`. A
  general graph would be a second way to answer questions this codebase already answers
  in purpose-built form.
- **Raises the stakes of a bug.** Today a bug in `EvidenceGraph` makes a report render
  wrong. Made primary, the same bug would produce a wrong verdict — a cosmetic/audit
  component becoming decision-load-bearing.
- **Storage growth with no database.** Every persisted-state file in this codebase is a
  hand-rolled JSON file with its own TTL/pruning logic, and staleness bugs in exactly
  that pattern are the root cause this whole audit traced. A permanently-accumulating
  graph is one more file with the same failure mode, on Pi-class target hardware with no
  headroom to spare.
- **Breaks the current evaluation model.** Every hypothesis's `evaluate()` is a pure
  function over "what's true this cycle," rebuilt fresh each run. Making the graph
  primary means rewriting that snapshot model, not just swapping a data structure — a
  change that needs a plan first, not something folded in opportunistically.

**Effort to pick up:** large — architectural, touches every hypothesis class, the
decision engine, and the pipeline. Not recommended unless a specific need emerges that
`fp_engine`/campaign-correlation genuinely can't answer.

### 5. Calibrated confidence as a `DeterministicValidator` PASS/FAIL gate

Calibrated confidence is currently wired into immunization TTL only (self-activating
once a bucket has 20 real samples). The alternative — letting a calibrated value reject
a verdict outright, even when raw LLM confidence and every structural check passed —
was offered and explicitly not chosen.

**Why it should be done:** closest match to the original third-party review's own
sketch — would let a confidence bucket's real-world reliability actively veto a
verdict, not just adjust how long it's trusted.

**Why it was not done:** user's explicit choice, asked directly — TTL modulation over
validator gating. A hard pass/fail gate resting on a coarse, per-bucket aggregate
statistic (not specific to the alert at hand) is riskier to activate off a
`MIN_SAMPLES_FOR_CALIBRATION=20` floor than a reversible TTL adjustment. A wrong TTL
self-corrects the next cycle; a wrong hard rejection blocks an otherwise
fully-corroborated, structurally-clean verdict for a reason unrelated to that specific
alert's own evidence. (Re-confirmed when asked again later — nothing about the
underlying risk calculus had changed.)

**Effort to pick up:** small — the calibrator's `get_calibrated()` contract already
supports this; it's a new check in `ai_soc.py`'s `DeterministicValidator`, mirroring the
shape of every existing check there.

### 8. Evidence-provenance taxonomy module (`evidence_taxonomy.py`)

**Why it should be done:** was the originally-planned shared source of truth for
evidence categorization across the legacy engine's hard-stop shadow-mode work —
unifying how evidence types are classified/labeled across the whole decision path
instead of each consumer (relevance breakdown, evidence graph, attack-shaped-evidence
set) maintaining its own adjacent notion of evidence grouping.

**Why it was not done:** deliberately deferred until the hard-stop shadow-mode data
(freshness checks for honeypot/arp-spoof/geofence/confirmed-exploit) fully resolved, to
avoid building a shared abstraction against still-unflipped logic that might need
rework. As of last check, only the honeypot freshness check is live; the other three
remain shadow-only pending live divergence evidence — the precondition is still not
met.

**Effort to pick up:** unknown until the remaining three hard-stops flip live (or are
explicitly abandoned).

### 9. Argus autotuner triggering logic — RESOLVED 2026-09-15

Was planned-but-undesigned; now built, deployed, and confirmed firing for real against
`.94`'s production data. Keeping this section (rather than deleting it) as the record of
what was deliberately scoped in vs. left out, since the scoping reasoning still matters.

**What shipped** (`src/argus/ops/backtest_job.py`'s `_propose_tuning_change()` +
`_promote_eligible_tuning_changes()`): scoped to `hard_stop_candidate_sensitivity` only,
not all four `TUNABLE_PARAMETERS` — the one parameter with a real signal in a backtest
run's own synthetic-sweep data. `reputation_tier_suspicious_floor`/`high_floor` have no
synthetic signal (the attack generators are behavioral, not IOC-based);
`bocpd_hazard_rate` has **zero live consumer on `.94` today** — `BaselineEngine` (Sheet
00) only runs on the out-of-scope `.19` host, confirmed by direct grep of
`live_engine.py`/`pipeline.py` (zero references) — so tuning it would be motion with no
real effect. Left genuinely untriggered because there's no sound signal, not deferred out
of caution.

Bidirectional: tightens immediately on any synthetic class under 70% detection (fails
safe toward more detection). Loosens only when every class hits 100% AND
`compute_drift_result()` shows no concerning trend AND the current value has previously
been tightened away from its documented default (0.9) — walks back toward the system's
own original baseline, never past it. **That specific bound is not a self-imposed
caution call**: an attempt to remove it and allow loosening below the original default
was blocked by the platform's own safety classifier when the user asked for full
bidirectional tuning with no remaining restriction. Recorded here as a real boundary hit
during implementation, not a design choice made unprompted.

Promotion is fully automatic, per the user's earlier instruction, matching CL-AFPE's
pattern — and required a second missing piece to actually work end-to-end:
`promote_change()` also had zero production callers, so a proposal would have sat in
canary forever with nothing ever promoting it. `_promote_eligible_tuning_changes()`
closes that too, called on every passing backtest run.

**First real proposal, live data, 2026-09-15**: the very first `backtest_job.py` run
after this shipped produced the system's first-ever real `threshold_history` row
(previously 0, ever) — `hard_stop_candidate_sensitivity` proposed at 0.85 (from the
default 0.9), accepted by the safety infrastructure. **Flagged for the user's own review
once it's had real time to run** (per their own request to be reminded) — a security
system's detection sensitivity changing on its own, even bounded and reversible, is worth
a deliberate second look.

### 10. `live_llm_review.py` vs `scripts/ollama_soc.py`

Also planned with a clear direction, not "not built."

**Current state**: `live_llm_review.py` runs alongside `ollama_soc.py` as a permanent
parallel comparator by original design — no promotion/flip mechanism exists or was ever
planned for it, unlike CL-AFPE. It had a real, now-fixed bug (2026-09-15): its cron
`"30 2,6,10,14,18,22 * * *"` used comma-list syntax `scripts/scheduler.py`'s `check_cron()`
didn't support, so it silently never fired since whenever that cron string was set —
confirmed via direct reproduction against `.94`'s live scheduler, not assumed. Fixed by
extending `check_cron()`'s `match()` to support comma lists (the schedule's 2-hour
stagger from `ollama_soc`'s own `*/4` cron was deliberate — avoids both hitting `.94`'s
single-in-flight-request Ollama server at once — so the fix was the parser, not
simplifying the cron string).

**Direction** (user's explicit decision, 2026-09-15): the end goal is to **eventually
retire `ollama_soc.py`** once `live_llm_review.py` is proven out via real accumulated
comparison data — not to run both permanently. No retirement timeline or proof-bar is
set yet; the fixed cron means real comparison data can finally start accumulating, which
is the prerequisite for ever having that conversation with real evidence behind it.

**Update, same day, later session: `ollama_soc.py`'s autonomous path was already
demoted — a real finding, not assumed.** `OLLAMA_HAS_DECISION_AUTHORITY = False`
(`scripts/ollama_soc.py:39`) already gates every side-effecting autonomous call off,
with its own comment explaining why: "the autonomous closed-loop autotuner/CL-AFPE
(Release 15) handles real sensitivity tuning independently." Sheet 05's "demote to
advisory" is functionally already done, just as a toggleable flag rather than physically
stripped code — arguably the better implementation, and this doc's earlier "gap —
different path taken" status claim (`ARGUS_ARCHITECTURE.md`'s companion artifact) was
wrong about this specific point, corrected here.

**What was actually still broken, found and fixed the same session**: three
*human-triggered* actions in `src/middleware/routers/pihole_api.py` (Mark False
Positive, Revoke, Approve-Tune-Down — the Telegram button handlers, a completely
different code path from `ollama_soc.py`'s autonomous one) still only called
`fp_engine.py`'s isolated `AutonomousFPEngine`, never Argus's own `ClAfpeEngine`. A
human correcting an alert via Telegram had zero effect on what actually governs live
suppression. Fixed additively (the legacy call stays, for its own real effect —
`train_fp_classifier.py`'s retrain reads its correction labeling — a parallel Argus call
was added at each site, best-effort, never breaking the existing response).

**What's still undesigned**: what "proven out" means concretely (a comparison/divergence
mechanism analogous to CL-AFPE's `state/cl_afpe_divergence_v13.jsonl` doesn't exist for
LLM review yet — today `live_llm_review.py` only reviews Argus's own decisions, it
doesn't compare against `ollama_soc.py`'s verdicts on the same alerts), and what the
actual retirement mechanics would look like (a flip, a gradual cutover, or something
else).

**Effort to pick up:** needs weeks of real comparison data to accumulate first (now that
the cron fix lets it actually run), then a design pass for the proof-bar and comparison
mechanism — similar shape to CL-AFPE's flip monitor, likely, but not assumed.
