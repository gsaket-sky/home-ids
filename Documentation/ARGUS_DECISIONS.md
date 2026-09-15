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

---

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
