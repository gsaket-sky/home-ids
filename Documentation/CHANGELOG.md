# Changelog

All notable changes to the Home IDS project will be documented in this file.

> **Gap note**: entries between `v12.14.0` and `v16.0.0` were never backfilled here —
> that period covers the v13→Argus architecture rewrite and several weeks of rapid
> iteration. `git tag --sort=-creatordate` plus each tag's own annotated message is
> the authoritative record for that window; `Documentation/ARGUS_ARCHITECTURE.md` and
> `Documentation/ARGUS_DECISIONS.md` describe where it all landed. Entries resume below
> from `v16.1.0` onward.

## [v16.7.0] - 2026-09-27

Phase 1 of the full 16-parameter autonomous-tuning effort: the four Tier-1 autotune
parameters that were allowlisted and consumed live but had produced zero real
proposals ever (`reputation_tier_suspicious_floor`, `reputation_tier_high_floor`,
`bocpd_hazard_rate`, `fp_combined_suppress_threshold`) now have working candidate
generators. Root-caused by running the real evidence-collection code directly
against `.94`'s live graph: `fp_combined_suppress_threshold`'s calibration was
pooling corrections of any verdict (including a hard-stop path's confidence=0.0
sentinel), permanently poisoning its own safety gate; fixed by requiring the
original verdict be UNCERTAIN, the only population actually comparable to the
threshold it calibrates. The other three had no candidate generator at all —
added native ones in `backtest_job.py` reusing the existing scoped
propose/canary/promote/rollback machinery, plus a new raw reputation-score field on
every decision's existing autotune audit trail and matching retroactive
circuit-breakers for both reputation floors. Deployed and verified live on `.94`
same day — new decisions confirmed carrying the new instrumentation, clean boot,
no errors.

## [v16.5.0] - 2026-09-23

Chronic console latency + pipeline-freeze root cause. Investigated a user report that
the console felt slow, confirmed live via `py-spy`: `GraphStore` re-ran its
~40-statement schema migration on EVERY console API request (not just the graph tab —
overview/autonomy/hunt/devices/graph all go through it), colliding with the
constantly-writing main pipeline for SQLite locks — 6+ worker threads caught
simultaneously stuck at this exact call, 40+ second responses even for the smallest
query. Now cached once per process (`GraphStore._migrated_db_paths`). Also cached
`StateManager` (a 5.7MB JSON reparse on every read-only request across 14 call sites)
with mtime-based invalidation (`middleware/state_client.py`).

That investigation led to a bigger finding: `soc.service` had self-restarted 25 times
in one day, 84% needing a hard SIGKILL, heartbeat stale up to 30+ minutes at a time.
Root cause: `ml_engine.py`'s `save_models()` is a fully synchronous, unbounded disk
write called every 60s from the main detection loop's own thread (and again from the
shutdown handler, explaining the SIGKILLs) — bounded to 20s the same way
`state_guard.py`'s `flush_to_disk()` already was. Verified live: restarts dropped from
25/day to 1 in 8 hours, with clean recovery on that one.

## [v16.4.0] - 2026-09-22

Geofencing alert graph gap + Evidence Graph device filter. A real user-reported
missing alert traced to the geofencing hard-stop path deliberately skipping the graph
write (to avoid duplicating evidence) without setting what downstream alert_event code
needed — fixed with a targeted write that reuses the existing per-cycle dedup instead
of re-running the full evaluation (which would have double-counted the observation
into the live baseline models). The specific missing alert was backfilled from real
data. Also added a `device_id` filter to the graph API/console and a "View in graph"
link on every Alerts-tab row, closing a separate gap the investigation surfaced: the
graph canvas only ever showed the most recent ~25-200 decisions network-wide, with no
way to look up an older or single-device alert.

## [v16.3.0] - 2026-09-22

Plain-English alert narratives + console-wide humanization. Every alert now gets a
short, non-technical paragraph — device, what was noticed, where, why the system
leaned toward a threat, the honest counter argument, what happened as a result —
generated from the same evidence graph the decision engine used, shown identically in
Telegram, the graph's own explanation node, and the console's alert table.
Destination IPs are humanized everywhere (local peer hostname, known domain, or
external IP + ASN/country) instead of raw IPs; the graph canvas got family-based color
coding and end-to-end multi-hop click highlighting. Also fixed: Overview's
`fp_evaluations` count silently dropped a real third verdict bucket (UNCERTAIN), and
global-scoped autotuner promotions were invisible in the console entirely. Console no
longer scrolls back to the top on every click.

## [v16.2.0] - 2026-09-22

Alert-trace graph: alerts now live in the evidence graph, not just `alerts.json`. New
`alert_events`/`incidents`/`operator_actions` schema, wired into the live pipeline so
every fired/suppressed/logged-only alert is durably written to `GraphStore` alongside
its winning hypothesis and supporting evidence, with a bounded semantic-search
embedding generated at write time (mandatory scope filter, hard candidate cap, honest
error instead of silent truncation). Console: a new fired/suppressed alert list under
the Evidence Graph tab with bounded natural-language search, and alerts now render as
real graph nodes connected to their decision/evidence/destination nodes.

## [v16.1.0] - 2026-09-22

Dead-code cleanup + resource-aware job scheduling. Retired `scripts/retro_hunter.py`
and `scripts/shadow_backtest.py` (dead since the Argus cutover), kept
`cl_afpe_flip_monitor.py`'s file (its one-time job may be needed again for a future
engine flip, though it's no longer scheduled). `fp_engine.py`'s weekly model retrain
now runs as a subprocess instead of in-process, closing a real OOM crash-loop. New
`core/resource_gate.py` + `core/job_coordinator.py`: hard mutex/priority/SIGSTOP-
pause-resume/orphan-reclaim scheduling for every scheduled job, not just the retrain.
Fixed `/hosts` freezing the entire console FastAPI event loop.

## [v12.14.0] - 2026-09-04

Triggered by a third-party architecture review of a live SOC digest, which found the
Ollama LLM re-review layer could still be talked into a "benign, suppress" verdict by
citing evidence irrelevant to the actual hypothesis (both `example_smarttv_fritz_box`
immunizations in the reviewed report justified suppressing `NETWORK_INTRUSION` using
DNS-hygiene language -- query rate, unique domains, entropy -- none of which
`NetworkIntrusionHypothesis.evaluate()` actually reads), and, while auditing that
report's real immunizations against the review's own suggested checklist, a confirmed
live bug: the persistent Ollama-verdict cache never re-validated a cache HIT against
the current `DeterministicValidator` logic, so a validator upgrade had no effect on
any already-cached pattern. See `Documentation/ARGUS_ARCHITECTURE.md`§8's
Gap 6 entry for the full trace, live-evidence citations, and per-item file:line detail
-- summarized here.

### 🔑 Evidence Fingerprint + Validator-Schema Versioning

- `ollama_soc.py`'s persistent cache now keys on evidence CONTENT (a hash of
  attack-shaped-evidence presence plus a few bucketed risk/entropy signals) and the
  current `ai_soc.VALIDATOR_SCHEMA_VERSION`, not just the coarse device/target/
  signature grouping key used for in-run collapsing. A genuine evidence change or a
  validator logic upgrade each produce a different key, so a stale cached verdict is
  simply never looked up again -- no separate invalidation pass needed.

### 🛡️ Validator Now Requires Real Corroboration for "Benign"

- Rejects a "benign" verdict outright when the alert's own recorded evidence
  includes an attack-shaped type (`arp_sweep`, `zeek_lateral_scan`, a malicious TLS
  fingerprint, etc.), independent of whether the original alert had already escalated
  -- closes the exact failure mode the reviewed report exhibited.
- Additionally requires the destination to be trusted/known infrastructure OR this
  specific device to have real learned familiarity with it (`fp_engine`'s existing
  `get_baseline_familiarity()`) -- mirrors `DeviceProfileBenignHypothesis`'s own
  requirement, now enforced identically on the LLM's later free-text re-review, not
  just the live scoring pass.

### 🧭 Evidence Relevance Breakdown + Graph

- The Ollama prompt and the `.md` report now both show, per alert, which of its
  evidence types are actually relevant to the hypothesis being reviewed vs. merely
  present-but-irrelevant -- deterministic scaffolding, not a new validator rejection
  rule (matching free text against a type name would need the same fragile
  string-matching heuristic already rejected for a different check).
- New `intelligence/hypotheses/evidence_graph.py`: an additive, on-demand
  device/evidence/destination/hypothesis graph view over the same data, rendered as a
  collapsed block in the report -- not a second live store alongside `EvidenceStore`.

### 📊 Confidence Calibration (data collection only)

- New `intelligence/confidence_calibration.py`: online per-confidence-bucket
  Beta-Binomial posterior (separate benign/malicious tracks, asymmetric priors),
  updated from two harvesting sites that reuse existing infrastructure -- a benign
  cache entry surviving its whole TTL, and the confirmed-threat branch. Not yet
  consulted by any decision logic; a future phase once buckets have real sample
  volume.

### 🕸️ Tarpit Release on Benign Confirmation

- Found while implementing, not assumed: the Layer-2 dual-stack ARP/NDP tarpit
  subsystem already existed live in `mitigation/ips.py`, fully decision-driven. The
  actual gap was that `ollama_soc.py`'s benign-confirmation path never called the
  already-existing `IPSMitigator.release_device()` -- so a device that crossed the
  real-time tarpit bar before a LATER Ollama review validated the same pattern as
  benign stayed trapped indefinitely. Both benign-confirmation branches now call it.

### 🧹 Privacy sweep

- Replaced every real device hostname (this network's actual smart-TV, PC, and
  smart-monitor device names, among others) across source comments, tests, and
  documentation with generic `example_*` names, and removed a real filesystem path
  this investigation's own notes had captured. No real first names or credentials
  were found in the tracked repo.

New `tests/test_phase57_evidence_fingerprint.py`,
`test_phase58_validator_attack_shaped_evidence.py`,
`test_phase58b_validator_destination_baseline.py`,
`test_phase59_evidence_relevance.py`, `test_phase60a_confidence_calibration.py`,
`test_phase61_evidence_graph.py`, `test_phase62_tarpit_release_on_benign.py` (94
checks total); full 55-file suite re-run clean.

## [v12.13.0] - 2026-09-04

Triggered by an operator report: "example_pc was once again recently tarpitted and after
removing it from block, Grafana still shows as tarpitted and blocked. It keeps
recurring -- if unblocked from Fritzbox, the script doesn't know, Grafana doesn't know.
Only `release_device.py` seems to properly update the state in Grafana."

### 🔄 Router-Isolation Reconcile Worker's Status Query Used the Wrong Timeout, Silently Failing Every Pass

- Root cause, confirmed via live SSH investigation: `reconcile_router_isolation_state()`
  (`mitigation/ips.py`) -- the mechanism specifically built so that a device unblocked
  directly in the Fritz!Box admin UI (bypassing this IDS entirely) doesn't stay shown as
  isolated in Grafana forever -- reused `router_webhook_timeout_seconds` (5.0s, tuned for
  the *fast* isolate/unisolate SET webhook call) as the timeout for the much slower
  `GetWANAccessByIP` read-only status QUERY. Timed the real round-trip against this
  Fritzbox directly: ~10.2 seconds. Every single reconcile attempt -- the boot-time pass
  and every scheduled 300s pass since the mechanism was built -- silently timed out and
  was swallowed by a bare `except Exception: LOGGER.debug(...)`, invisible at this
  service's normal INFO log level. Zero existing test coverage for this whole area,
  plausibly why it went unnoticed through every restart and every scheduled pass since it
  was built.
- Fixed: a new, separate `router_status_query_timeout_seconds` config key (20.0s
  default) for this query specifically, used both by `ips.py`'s own HTTP call to the
  internal status endpoint and by that endpoint's own `FritzConnection(timeout=...)`
  call (`middleware/routers/fritzbox_api.py`'s `router_isolation_status()`). The
  isolate/unisolate SET actions keep their original 5.0s `router_webhook_timeout_seconds`
  budget, untouched -- they weren't reported broken and a SET's latency profile isn't
  necessarily the same as this GET's.
- Both failure paths (non-200 response, exception) upgraded from silent/DEBUG to
  `LOGGER.warning()`, so a future recurrence of this failure mode -- for any cause, not
  just this exact timeout -- doesn't go unnoticed through every scheduled pass again the
  way this one did.
- **Separate, by-design limitation clarified, not fixed the same way**: the Layer-2
  ARP/NDP Scapy "tarpit" containment mechanism (`mitigation/ips.py`'s tarpit target
  registry) has no reconciliation at all, and structurally can't -- unlike router
  isolation, it's purely local to this box; Fritz!Box has no visibility into it and
  nothing external to poll for its real state. Clearing a tarpit entry still requires an
  explicit release: `release_device.py` / the Telegram release button / (for a stale
  entry after an out-of-band change) `clear_stale_isolation.py`.
- New `tests/test_phase55_router_reconcile_timeout.py` (15 checks): the new config
  key's default and independence from the SET-action timeout, that the reconcile HTTP
  call actually uses it (mocked via `ips.session.get`), that non-200/exception paths now
  log at WARNING, and regression guards that a genuine success still clears the stale
  record exactly as before and that the SET-action timeout key is untouched everywhere.

## [v12.12.0] - 2026-09-01

Triggered by an operator question: "is Ollama ever completing all the alerts or is it
just piling up." It was piling up -- a live audit of
`state/ollama_analysis_cache.json` found 165 distinct patterns sitting in
`withheld_history`, some withheld 15-18 times over 4.6 days straight, 100%
`NETWORK_INTRUSION` (this network's single most common signature) and 100% still
classified benign at high confidence every single time, with no mechanism that ever
let a pattern resolve on its own.

### ⏳ ollama_soc.py's Multi-Device Withhold Guard Now Has an Exit Condition

- Root cause: the guard (`spread >= 3` distinct devices independently firing the same
  signature -- built to catch a real DGA-style cross-device campaign, see its own
  Phase-21D comment) re-checks every run against then-current device spread, forever.
  For a broad, common category like `NETWORK_INTRUSION` on a busy home network, spread
  stays above 3 essentially permanently, so the guard never actually releases.
- Considered and rejected: auto-resolving once device spread stops growing. Spot-
  checked live -- most stuck patterns (98 of 147 with 2+ checks) still show device-
  count churn between checks, which turned out to be normal background noise (different
  devices intermittently tripping the same common alert), not a shrinking/stabilizing
  incident. Not the right signal.
- Fixed instead: track how many times a pattern's OWN streak (this exact
  device+target+signature key, not the cross-device spread count) has independently
  reconfirmed the identical benign/validator-passed verdict. After
  `ollama_multi_device_withhold_auto_resolve_after` consecutive withholds (default 10,
  matching the existing `ollama_multi_device_suppress_guard` config precedent), the
  pattern falls through to the normal immunize path instead of withholding again,
  logged distinctly as auto-resolved-after-streak. A verdict flip (malicious, or the
  validator rejecting it) resets the streak, so this only ever fires for a genuinely
  stable, repeatedly-reconfirmed pattern -- the original cross-device contradiction
  catch (a malicious verdict on any device never reaches the withhold branch at all)
  is untouched.
- **Second, more fundamental bug found while building this fix**: the normal (non-
  guarded) benign+suppress immunize branch was a silent no-op whenever the alert's
  target had no resolved domain (an IP-only `NETWORK_INTRUSION` target -- the majority
  shape of what was actually piling up). `action_taken` never got set, so an IP-only
  pattern could never resolve even on a first-time, low-spread pass that never touched
  the multi-device guard at all. Fixed: falls back to the same device-level sensitivity-
  loosening primitive (`_apply_sigma_shift(..., direction="TUNE_DOWN")`) the
  malicious/TUNE_UP branch already uses, mirroring the no-domain routing
  `fp_engine.mark_false_positive()` already has for `DNS_EVASION`/`CONNECTION_ABUSE`
  (PHASE 21D2) but never had for anything else.
- The withhold decision itself extracted into a new, independently testable
  `should_still_withhold()`. New `tests/test_phase49_ollama_withhold_streak.py` (11
  checks): the streak-exhaustion behavior, a regression guard that the original
  spread-at-threshold DGA-campaign catch is untouched, and source-level checks that the
  IP-only no-op is genuinely gone and the real wiring calls the tested function (not a
  drifted copy).

## [v12.11.0] - 2026-09-01

Triggered by an operator question ("how far off is HEE from what Ollama concludes,
across cases so far, including category and severity") that turned into a real,
data-backed audit -- all 225 cases Ollama has ever reviewed were cross-referenced
against their original HEE alert records in `state/alerts.json` (28,823 alert records,
1,980 distinct incidents), joined via the same `incident_key()` this project already
uses for incident aggregation.

### 📊 HEE vs. Ollama Agreement Audit

- Overall: Ollama called 92.9% of reviewed cases benign; the deterministic
  `DeterministicValidator` (a hard backstop that never lets an LLM override real
  evidence) rejected Ollama's own recommendation in 4.0% of cases (9/225).
- By category: `DNS_COVERT_TUNNELING` is the one category where Ollama is genuinely
  split (only 46% benign) rather than defaulting to benign -- the rest cluster at
  93-100% benign. `Elevated Reputation Signal (Unconfirmed, Tier 5 Score)` had a 100%
  validator-override rate (7/7) -- not a disagreement on the underlying classification
  (Ollama and the validator both effectively treat these as non-threats), but the
  validator refuses to let an LLM suppress a Tier-5 reputation hit on principle,
  regardless of what it thinks.
- Following the override cases to their root: 8 of the 9 total overrides trace to one
  device (`example_pc_fritz_box`) repeatedly hitting `updates.bravesoftware.com` and two
  Spotify hosts and Datadog's log intake -- all of which resolve to `35.186.224.0/24`,
  a shared **Google LLC (AS396982)** GCP customer IP range. AbuseIPDB's crowd-sourced
  score for that shared block sits >= 4.0, almost certainly from some unrelated
  tenant's traffic on the same cloud IP, not from any of these legitimate services.

### 🌐 ReputationClassifier Now Recognizes the Same Cloud/CDN Orgs Everywhere Else Does

- Root cause: this codebase already has two separate "don't punish known-legitimate
  shared infrastructure for a noisy crowd-sourced score" mechanisms that were never
  unified. `ReputationClassifier._SAFE_ASN_OWNER_KEYWORDS` (`classifier.py`) is a tiny,
  one-entry list (`("telegram",)`) and is the ONLY ASN-based check `classify()` --
  the function that actually assigns Tier 3/4/5 and drives every SUSPICIOUS/CRITICAL
  verdict -- ever consulted. `utils.is_cloud_cdn_provider_org()` already maintains a
  broader, deliberately conservative list (Google LLC, AWS, Apple, Facebook/Meta, IBM
  Cloud, Vultr, Leaseweb, Scaleway, Contabo -- the same list the v12.5.0 confirmed-intel
  write guard already trusts), but was never wired into the reputation tier classifier
  itself.
- Fixed: `classify()`'s existing ASN-safe-list check now also consults
  `is_cloud_cdn_provider_org()`, promoting to Tier 2 the same way the Telegram check
  already does. Same trust boundary this project already accepted elsewhere (a "deliberately
  short, stable, name-brand list... as close to universally-recognized internet
  infrastructure as exists"), just applied consistently to a second consumer -- not new
  trust, closing a gap in existing trust.
- `tests/test_phase0_fixes.py` extended with the exact live shape (Google LLC,
  abuse_score at and below the confirmed-IOC bar) plus a spot-check on AWS, and
  regression guards confirming an unrelated org still escalates normally.
  `tests/test_phase42_tier5_verified_ioc_split.py`'s own production pin for this exact
  IP (`35.186.224.24`) updated: it now correctly resolves all the way to BENIGN instead
  of the tier-5-split fix's prior SUSPICIOUS/monitor -- a further improvement on the
  same incident that pin has tracked since it was written, not a regression (Section C's
  generic-unrelated-org shape separately confirms the tier-5 split itself is untouched).

## [v12.10.0] - 2026-09-01

Triggered by the first real Telegram digest the v12.9.0 fix produced -- it arrived,
but cut off mid-sentence inside entry #7 of a 54-entry run.

### 🤖 ollama_soc.py's Telegram Digest No Longer Truncates Mid-Sentence

- Root cause: the digest was capped by entry COUNT alone (10 entries), then the whole
  finished message was hard-sliced to `[:4000]` characters as an afterthought. Ten
  entries' worth of real LLM reasoning text (each ~200-400 chars once the
  device/target line, the LLM quote, and the outcome line are included) routinely
  exceeds 4000 characters well before the 10th entry, so the count cap never actually
  prevented the character-level slice from firing -- and that slice cut wherever it
  landed, with zero regard for entry or sentence boundaries.
- Fixed: extracted the whole digest-building block into a new, independently testable
  `build_ollama_digest_message()`. Each entry is now built as a complete, whole block;
  entries are added to the message while tracking a running character total, and
  adding stops (not truncates) once the total approaches Telegram's real 4096-char
  limit. Every entry that makes it into the message is complete; entries that don't
  fit are folded into the existing "...and N more (see report)" counter instead of
  being cut off. The optional "Technical detail" section is appended atomically --
  fully present or fully absent, never partial.
- New `tests/test_phase48_ollama_digest_truncation.py` (14 checks): reproduces the
  exact 54-entry shape from the live report, proves no entry is ever left mid-sentence
  (an even double-quote count across the whole message -- a truncated LLM-reason quote
  would leave one unclosed), proves the message never exceeds 4096 chars across a
  range of run sizes (1/5/10/20/54/100 entries), and proves the technical-detail
  section is all-or-nothing.

### 🧠 Aside: Does Ollama Duplicate the HEE's Job?

A related operator question, answered by reading the code rather than assuming: no --
this was already recognized as a risk and explicitly guarded against. Ollama never
sees the Hypothesis & Evidence Engine's own verdict (`_VERDICT_SHAPED_FIELDS` in
`ollama_soc.py` strips `risk`/`signature`/`factors`/`fp_verdict`/etc. before the prompt
is built -- "VERSION 10 (#15/#16, Ollama circular-reasoning guard)"), so it can't just
parrot the existing decision back as "confirmation." Its recommendation is then
checked by `ai_soc.py`'s `DeterministicValidator` before being allowed to act at all --
confirmed live in the same run that produced this bug report: `[VALIDATOR] Rejected
Ollama recommendation: Malicious IOC present` overrode a benign LLM verdict for
`www.google.com` because a real reputation IOC existed for that device. Ollama's role
is a separate, guarded, offline second opinion feeding the FP-training/immunization
loop -- it never touches live containment decisions, which stay the HEE's alone.

## [v12.9.0] - 2026-09-01

Triggered by a direct operator report: "ollama should also send telegram message, i
am not getting it."

### 🤖 ollama_soc.py's Telegram Digest Was Dead Code From Day One

- `_send_telegram()` reads `telegram_token`/`telegram_chat_id` from the config dict
  it's handed, and silently no-ops (`if not token or not chat_id: return`, no log
  line at all) if either is empty. `config.yaml`'s own `telegram:` section comment
  says *"token/chat ID come from .env"* — true for the main pipeline process, which
  goes through `config.py`'s `LiveConfig.__init__()` (`load_env_file()` +
  `apply_env_overrides()`), but `ollama_soc.py` deliberately reads `config.yaml`
  directly via its own standalone `load_config()` instead of importing the full
  `config.py` `CONFIG` singleton ("so this standalone daemon doesn't need to boot the
  full engine") — and never loaded `.env` at all. Every run silently no-op'd; not an
  intermittent failure, the digest had never once fired since this script's Telegram
  feature was added.
- Checked every other scheduled script for the same pattern:
  `retro_hunter.py`/`shadow_watcher.py`/`top_domains_report.py` all correctly
  `from config import CONFIG` (the full singleton, `.env` included) — `ollama_soc.py`
  was the only one with its own bespoke config loader, so this was an isolated gap,
  not a wider pattern.
- Fixed: `load_config()` now also calls `config.py`'s own `load_env_file()` +
  `apply_env_overrides()` (reused, not re-implemented, so the env-var mapping table
  can't drift between the two) after flattening the YAML. Verified directly: before
  the fix, `telegram_token`/`telegram_chat_id` resolved empty; after, both resolve
  correctly against the real `.env`.

## [v12.8.0] - 2026-09-01

Triggered by two live Shadow-Mode Telegram digests showing 51 divergences total, every
single one the same shape: `home-router` (the router, at whichever of its several
IPv6/IPv4 identifiers happened to be active that cycle) diverging live BENIGN -> shadow
CRITICAL / "Internal Honeypot Accessed".

### 🔬 Shadow-Mode Honeypot Check Now Respects safe_ips

- Root cause: `pipeline.py`'s LIVE evidence-creation gate for `honeypot_access`
  (~line 1033) is `if features.get("zeek_honeypot_hits", 0) > 0 and not is_safe:` --
  deliberately exempting `safe_ips` devices (the router is explicitly listed), since
  it legitimately touches the honeypot sometimes and `mitigate()` already no-ops for
  `is_safe` devices regardless, so the only effect of not exempting it was a
  misleading CRITICAL alert with no real containment behind it.
- `decision_engine.py`'s shadow computation (Gap 3, evaluating a proposed
  evidence-taxonomy fix from `Documentation/ARGUS_ARCHITECTURE.md`§8)
  deliberately reads the same raw `zeek_honeypot_hits` feature directly instead of
  checking `EvidenceStore` presence, to dodge a *different* bug (stale evidence
  re-firing the same verdict for up to 600s). In copying the raw-feature read, it
  copied half of pipeline.py's condition but not the other half — `is_safe` was never
  even passed into `evaluate()` at all, so every `safe_ips` device touching the
  honeypot for a benign reason diverged shadow-CRITICAL forever. Not a one-off: a
  structural gap that would fire this way for as long as shadow mode has existed.
- Fixed: `evaluate()` gained an optional `is_safe: bool = False` parameter (same
  optional/defaulted/single-consumer pattern as `features` before it — every existing
  caller that hasn't been updated is unaffected); the shadow `fresh_honeypot` check now
  ANDs it in, exactly mirroring the live gate. `pipeline.py`'s one caller that already
  had `is_safe` in scope (~line 684, well before the `evaluate()` call) now threads it
  through.
- This bug never produced a real, live false alert or containment action — `mitigate()`
  already no-ops for `is_safe` devices independently, and the router's live verdict was
  correct throughout. It only ever polluted the shadow-mode diagnostic digest, which
  exists specifically to build confidence in a fix *before* flipping it live (see
  v12.5.0's tier-5 split, which followed exactly that path) — a shadow signal this
  noisy would have made a real divergence (if the proposed fix ever has one) hard to
  spot in the flood.
- New `tests/test_phase47_shadow_honeypot_safe_ips.py`: proves the fix, a regression
  guard that a genuinely non-exempt device still trips the shadow hard-stop, a
  regression guard that omitting `is_safe` (every un-updated caller) is byte-identical
  to before, and a regression guard that the live verdict was never wrong.

## [v12.7.0] - 2026-09-01

Triggered by a live alert review: the operator asked what each Telegram inline button
actually does and whether the alert's own description matched. It didn't, in two places,
one of them more serious than wording.

### 🔘 Telegram Alert Buttons/Descriptions Audited Against Actual Behavior

- **Dead-button bug**: the Release/Approve inline-keyboard block was wrapped in an
  `interactive_blocking_enabled` check that never belonged there. That flag controls
  whether a *new* containment action needs approval before happening (ips.py's
  "Interactive HITL Mode" vs. "Autonomous Auto-Block") — it says nothing about whether an
  *already-contained* device can be released. With the flag `False` (the config's own
  default when unset), the mitigator still autonomously tarpits/isolates/blocks devices —
  but the Release button for exactly those alerts was silently suppressed by this same
  gate, even though the status text explicitly says "tap Release". Not currently reachable
  on this deployment (`interactive_blocking_enabled: true` live), but a real bug for
  anyone running the (default) autonomous mode. Release now shows purely off containment
  state, decoupled from that flag entirely.
- **Stale copy**: the "awaiting approval" status line said "approve or release using the
  buttons below" — but a 2026-08-29 fix (below) had already removed the Release button
  from that exact state, since nothing is contained yet so there's nothing to release. The
  button-removal fix never touched this text; it predates that fix and was simply missed.
  Reworded to name the one button that's actually there.
- **Vague copy**: the "monitoring only" status line said "review below and decide
  manually" without saying what there was to review — the only button ever attached in
  that state is "Mark False Positive" (unconditional whenever the target is known). Named
  it explicitly instead of leaving it open-ended.
- `tests/test_phase40_alert_button_containment_sync.py` extended: the button-gate mirror
  no longer takes an `interactive_blocking_enabled` parameter (matching the real fix), a
  new check proves Release survives with that flag `False`, and a source-level regression
  guard catches a future edit silently reintroducing the old gate.

## [v12.6.0] - 2026-08-31

`soc.service` was OOM-killed and auto-restarted (kernel memcg OOM, not a host reboot) after
running for ~34 hours with memory climbing from a typical ~100MB toward its 1G `MemoryMax`
ceiling. Root-caused to the reactive-capture subsystem: a benign-looking recurring geofencing
hit had kept it running nearly nonstop for hours, and burst size spiked ~10x under genuinely
heavy traffic right before the crash. Full best-case/worst-case load analysis, root-cause table,
and prioritized fix list in the new `Documentation/REACTIVE_CAPTURE_LOAD_ANALYSIS.md`.

### 🧠 Reactive-Capture Memory Hardening

- `avm_pcap_to_standard()` read the entire raw capture into memory and built a second full
  in-memory copy before writing it out — normally a few MB, but real bursts reached 46-90MB/radio
  (vs. a 4-7MB baseline), and two landing back-to-back tipped the cgroup over its limit. Now
  streams record-by-record: peak memory is O(one record), not O(file size).
- `ReactiveCaptureDispatcher` previously bounded only burst COUNT
  (`reactive_capture_max_bursts_per_hour`), never how much any one burst captured — the same
  incident showed burst size spiking well past what the count budget could account for. Added a
  second, independent gate, `reactive_capture_max_bytes_per_hour` (default 500MB), tracking real
  captured bytes in the same rolling hourly window.
- New `geofencing_exempt_ips` config key: a narrow, IP-scoped allowlist for the geofencing
  hard-stop specifically — unlike `safe_ips` (which exempts a destination from every detector),
  an exempted IP here still triggers reputation/honeypot/TI normally. Left empty by default; the
  operator decides case by case.
- Considered and deliberately **not** implemented: per-source trigger backoff. Would have
  reversed a documented prior operator decision (`pipeline.py`, "a shared hourly budget, not
  per-source cooldowns... more trigger rather than conservative") — presented directly, decision
  was to keep that design intact.

### ⚠️ Subprocess Memory Ceiling — Shipped, Broke Zeek, Corrected Same Day

- Added `utils.py`'s `memory_limited_preexec_fn()` (Linux `RLIMIT_AS` via `preexec_fn`) wired into
  the Zeek and Suricata batch-scan subprocess calls, gated by
  `reactive_capture_zeek_memory_limit_mb` / `reactive_capture_suricata_memory_limit_mb`. Deployed
  with both defaulted to 512MB, live-verified beforehand against a trivial Python allocation.
- **The very first real production burst broke Zeek**: `zeek -r exited -6,
  std::system_error: Resource temporarily unavailable`. `RLIMIT_AS` bounds a process's *reserved*
  virtual address space, not its actual resident memory use — Zeek (multi-threaded C++: thread
  stacks, shared-library mappings, internal arenas) reserves address space well beyond what it
  actually touches, so a limit that comfortably covers real RSS can still abort it outright. A
  known-bad fit for `RLIMIT_AS` against multi-threaded C/C++ binaries generally, not specific to
  this deployment's Zeek build.
- Impact: ~4 minutes of live bursts silently produced zero Zeek/DNS-evasion/Suricata findings
  (non-fatal to `soc.service` — both call sites already treat a killed child as a logged,
  non-fatal "no findings" outcome, exactly as designed — but a real functional regression).
  Corrected live via config hot-reload within ~1 minute of discovery, then the shipped default
  changed from 512 to 0 (disabled) in both `config.yaml.example` and `capture_and_ingest()`'s own
  fallback, so a config missing the key also defaults safe. The mechanism stays in the code, off
  by default — full incident note and the case for a cgroup-based approach instead (`systemd-run
  --scope -p MemoryMax=...`, bounds actual RSS rather than reserved address space) in the load
  analysis doc's fix #3/#4 sections.

## [v12.5.0] - 2026-08-29

A live recurrence of a known shadow-flagged issue (`example_pc_fritz_box` CRITICAL 3x in
one night on a bare AbuseIPDB score) triggered flipping a decision-logic fix from
shadow into production, which in turn surfaced a related confirmed-intel poisoning bug
affecting Apple/Facebook/AWS/Google/Microsoft and most other major cloud providers.
Two more live-alert-driven UX fixes and a device-classification investigation rounded
out the night.

### 🎯 Reputation Tier-5 Split Flipped Live + Confirmed-Intel Poisoning Fixed

- `decision_engine.py`'s `rep.tier==5` branch fired an identical `CRITICAL`/"Confirmed
  Malicious IOC"/0.99-confidence verdict whether the hit came from a genuine curated
  threat-intel feed match or a bare AbuseIPDB/VirusTotal aggregate score alone — a
  backtest against 80 historical alerts with this label found `verified_ioc=True` for
  zero of them. Now a real three-way split (`verified_ioc` confirmed / corroborated-
  but-unverified / uncorroborated → `SUSPICIOUS`), evaluating live alongside the
  already-running shadow computation that had flagged this gap since 2026-08-27.
- Root-caused the same night: `_is_ip_protected_from_confirmed_intel()`'s cloud/CDN-org
  keyword list was missing `"apple"`/`"facebook"` despite its own docstring already
  claiming Apple was covered — confirmed live via Apple Push and Facebook CDN IPs
  recorded "confirmed malicious" in `state/local_confirmed_intel.json`, cascading
  sensitivity-tightening to every device sharing that infrastructure. Fixed, broadened
  with a few more providers (IBM Cloud, Vultr, Leaseweb, Scaleway, Contabo — each
  verified against a real IP first), and backed by a new canary regression test
  resolving ~20 real IPs through the actual `GeoLite2-ASN.mmdb`. `clean_confirmed_
  intel.py` extended to detect/purge already-poisoned cloud-owned entries (previously
  only checked `safe_ips`/private ranges) — removed 284 entries in a one-time cleanup.

### 🔘 Telegram Button/Message Fixes

- "Release Device" on a still-pending ("awaiting approval") alert always reported
  "nothing to release" — technically correct (Interactive HITL mode never applies the
  block until Approve is tapped) but worded like a failure. Reworded to confirm the
  device is already safely unblocked instead.
- That same insight exposed the real fix: a pending alert only ever needed an Approve
  button — Release was structurally guaranteed to no-op there, since "awaiting
  approval" by construction means nothing is contained yet. Removed the dangling
  Release button from that state, matching the "only show a button that would
  actually do something" principle already applied to the other containment states.

### 🏷️ Device-Type Classification No Longer Silently Defaults to "laptop"

- `infer_device_type()` has always had hostname/User-Agent/MAC-vendor layers plus a
  hardcoded final fallback, but its only real caller never passed `mac_vendor`, and
  the fallback was unconditionally `"laptop"`. Confirmed on production: 13 of 36
  devices were typed `"laptop"`, and 12 of those (92%) actually had
  `hostname="unknown"` — `"laptop"` was a silent placeholder, not a real detection,
  and `fp_engine.py`'s own `dev_type_weights` dict already had an unreachable
  `"unknown": 0.3` entry waiting for exactly this. New `utils.get_mac_vendor()`
  (offline OUI lookup via the `manuf` package) closes the dead parameter; the fallback
  now returns `"unknown"` instead of guessing. Live effect confirmed post-deploy:
  `"laptop"` count dropped 13 → 7 in the first re-classification pass.

## [v12.4.0] - 2026-08-28

Two live-alert-driven fixes, prompted by real production Telegram messages that were confusing rather than clarifying: a device already fully contained (router-isolated + tarpitted) got an alert saying "nothing yet, tap Approve" with no way to tell it was already blocked, and an autonomous "immunized as false positive" notification gave zero indication of what evidence led there.

### 🔘 Alert Buttons and Status Text Now Reflect Real Containment State

- The Approve/Release inline-keyboard pair was gated on an independently recomputed `risk >= 8.5 or lateral_threat` condition that never checked whether the device was already contained — an already-isolated device could still show "Approve Hardware Isolation" alongside "Release," with nothing to actually approve. Buttons now key off `action_summary` (the same value the "Already done" status text already uses): already contained → Release only; genuinely pending → both; nothing queued → no hardware buttons at all.
- `IPSMitigator.get_containment_status()` gained a `dev_id` fallback — its primary lookup is keyed by raw client_ip/mac_addr, which can miss a genuinely-contained device on an identifier mismatch against an earlier incident (a DHCP lease change, or the MAC not yet re-resolved this cycle). Both `tarpit_targets`/`router_isolated_devices` entries already store a `dev_id` field; the fallback was a direct addition, not new state.

### 🔎 Autonomous-Action Alerts Now Explain Why

- The "🔔 Auto-action: immunized" revoke prompt now shows the LightGBM/FastEmbed/combined-threshold breakdown and calibrated confidence — `fp_engine.evaluate()` already computed and returned all of this (a comment on `fp_verdict["reasons"]` literally said "so pipeline.py can show it," it just never was read), plus the originating signature/risk/destination with ASN/country, and a hostname+IP identity that no longer dead-ends on a bare "unknown."
- `retro_hunter.py`'s "Retroactive Local-Intel Cross-Reference" alert now shows how long/how many times an IOC has been confirmed, what originally flagged it in plain language, and explicitly states the mitigation actually applied (sensitivity tightened; no block/isolation) — previously invisible even though the action was already being taken every time. Every device reference (including the `confirmed_by` list, previously raw device_id hashes) now resolves to hostname, or IP as fallback — never a bare device_id.
- `ollama_soc.py`'s Telegram digest used to fire only for validated-malicious findings. It now sends one comprehensive digest per run covering every pattern's outcome (immunized / confirmed-malicious / withheld / skipped / already-actioned / deferred), so a quiet run is visibly confirmed healthy rather than silently absent. The multi-device-guard "withheld" case now persists a cross-run spread history in `state/ollama_analysis_cache.json` — the next run's alert shows the actual trend ("spread 3→3→4→5 devices... newly joined: X"), not just an identical "withheld again" line with no memory of which devices were involved.

## [v12.3.0] - 2026-08-26 to 2026-08-27

A parallel workstream (run alongside the identity/dashboard work below) built a shadow-mode evaluation harness for a proposed evidence-taxonomy fix to the reputation/hypothesis decision logic, then used its own live divergence data to find and fix two real bugs the shadow-mode comparison itself surfaced.

### 🌓 Shadow-Mode Evidence-Taxonomy Evaluation

- New shadow-decision log (`state/shadow_decisions.jsonl`) recording, for every live alert, what the CURRENT decision logic produced side-by-side with what a proposed evidence-taxonomy fix would have produced — lets the fix be evaluated against real traffic before it's ever flipped live, with zero risk to production verdicts.
- `src/scripts/shadow_watcher.py` (new, temporary — cron `*/5 * * * *`): fires a Telegram notification the moment a new divergence is logged, so observing the fix's live behavior doesn't require an open session. Tracks its own read-position bookmark so repeated 5-minute polls never re-send the same entries.
- `src/scripts/shadow_backtest.py` (new, manual/offline): backtest CLI for replaying historical alerts through both the current and proposed logic.
- Two real bugs found via the shadow comparison's own divergence data and fixed: a hard-stop evidence staleness gap (evidence from a prior, already-resolved incident could still count toward a fresh hard-stop) and a Gap 1 shadow-severity/geofencing-attribution bug, both documented with root cause and fix in `Documentation/ARGUS_ARCHITECTURE.md`§8.
- `ollama_soc.py`'s cron had silently drifted from its intended 4-hourly cadence to once-daily (`"30 4 * * *"`) — corrected back to `"30 */4 * * *"`.
- `Documentation/ARGUS_ARCHITECTURE.md`§8 (new content at the time): a verdict-by-verdict audit of every state/action/explanation each decision layer (Layer 1 rules, Layer 2 CL-AFPE, Layer 3 Ollama) can produce, cross-referenced against real production alert counts.
- Telegram's "Contacted" line enriched with IP geo/ASN info for the primary THREAT alert (the same `lookup_asn()`/`lookup()` pattern later reused for the autonomous-action alerts in v12.4.0 above).

## [v12.2.0] - 2026-08-25

Prompted by a live Prometheus/Grafana review ("fritzbox isolation and tarpit still shows trapped but it isn't") that led to auditing device identity end-to-end. Root cause: MAC-first identity anchoring only prevents new device_id minting going forward, never retroactively merges a device_id already minted via IP-anchor before its MAC became known — the dominant pattern for dual/triple-stack devices. Confirmed live: 24 fragmented groups across 60 of 88 tracked devices in one production deployment.

### 🆔 Device Identity Fragmentation — Retroactive Merge

- `StateManager.merge_into_canonical()` (new): folds a fragmented orphan device_id into its richer canonical identity — the opposite direction from the existing `migrate_device_id()`, whose overwrite-the-destination semantics would be wrong here. Discards the orphan's own state per product decision, reattributes `blocked_domains`, reuses the existing isolation-release side channel.
- A configured `gateway_ip` always resolves to one fixed canonical device_id — the router has multiple real physical MACs (one per interface) that can never converge via MAC alone.
- Closed two pre-existing gaps in the same pass: `fp_engine.py` had no discard/migrate primitive for its per-device profile store at all (now wired into both the merge path and ordinary stale-device eviction), and `prune_stale_devices()` only cleared a device's most-recent `client_ip` from the reverse IP index, not its other `known_ips`.
- `apply_device_type()` bugfix: the old guard only re-inferred `device_type` on a device's literal first classification, permanently locking in a cold-start guess (e.g. "laptop") even after a real hostname later resolved.
- `src/merge_fragmented_devices.py` (new): one-time offline cleanup script (dry-run by default) for existing fragmentation. Verified and applied against real production state: 24 groups, 36 orphans merged.
- `Documentation/ARGUS_ARCHITECTURE.md`§6 (new content at the time): living reference for the full identity-resolution priority order and every "move" (migrate/merge/prune) a device_id can go through.

### 📟 Alert Readability Redesign & Live Bug Fixes

- Telegram alert body redesigned around three plain questions: what happened, what did the system already do about it, what happens if you do nothing — replacing two raw, differently-scaled percentages the reader had to reconcile themselves.
- Honeypot-access alerts previously carried no destination at all (fell back to whatever the device connected to most recently); kill-chain trajectory display collapsed a per-cycle history array with arrows even when the device sat in the same phase the whole time, implying movement that never happened.
- `ips.py`: the "device marked safe" tarpit auto-release path left the Prometheus gauge stuck after clearing internal state; router-isolation state now reconciles immediately at boot instead of only via the periodic worker thread.

### 📊 Grafana Dashboard Redesign + 15 New Self-Learning Metrics

- Boolean status tiles (Pi-hole IPS, Zeek Monitor, Router Kill-Switch, Tarpit, etc.) now show mapped text (ONLINE/OFFLINE/ARMED) instead of a raw 0/1.
- Merged the two most duplicated dashboards (Autonomous Behavior + Transparency, ~60% overlapping content) into one, added a `$device` filter variable, and gave Device Deep Dive its own per-device self-learning section.
- 15 new metrics covering mechanisms that previously only produced a log line or nothing at all: transfer-learning seeds, retroactive identity merges, re-identify migrations/ambiguous candidates, sigma-shift direction (widen vs. tighten — previously one conflated counter), baseline-poisoning/probation lifecycle *transitions* (not just point-in-time flags), device-type reclassifications, and the per-device ML model's own warmup/retrain/anti-poisoning/invalidation lifecycle.

## [v12.1.0] - 2026-08-24

Two threads: a follow-up live-alert audit found two more instances of the attribution/wording bug classes v12.0 was built to close, and a full Prometheus/Grafana transparency pass closed the remaining gaps between what the system actually does autonomously and what's visible on a dashboard without reading logs.

### 🎯 Attribution & Wording, Two More Instances Closed

- `pipeline.py`'s CONNECTION_ABUSE attribution now prefers `zeek_conn_abuse` evidence's domain over `arp_sweep` evidence's when both fired on the same alert — a `zeek_conn_abuse` hit is one specific rejected connection, while an `arp_sweep` hit is one arbitrarily-picked IP out of potentially hundreds swept, chosen only by evidence-store insertion order, not meaningfulness.
- `zeek_features.py` gained `zeek_arp_swept_ip_examples` (the actual swept IPs, not just the count) and `threat_signals.py`'s `arp_sweep` evidence now attaches a real `.domain` — previously an ARP-sweep-driven CONNECTION_ABUSE alert had nothing evidence-linked to attribute to, so the alert silently fell back to a coincidental, unrelated domain/port from the device's own last connection.
- `pipeline.py`'s containment-status wording no longer shares one template across all three containment types. A Pi-hole domain block previously used the exact same "device auto-blocked from the network" / "the block stays in place" language as router isolation and Layer-2 tarpit — both of which really do cut a device off; a single blocked domain does not. Each containment type now gets its own accurate, plain-language description of what actually happened and what staying idle actually means.

### 🔍 Full Prometheus/Grafana Transparency Pass

Two per-device learned thresholds shipped in this release (`conn_abuse_unique_ip_threshold`, `long_conn_duration_threshold`) had zero Prometheus visibility, and two live subsystems (Suricata batch scanning, the Pi-hole gravity-list API) had never been instrumented at all.

- **9 new metrics** in `src/metrics.py`: per-device effective-threshold gauges for both new thresholds, a generic `home_ids_autotune_device_profile_correction_total` covering every learned-threshold correction by key and source, `home_ids_persistence_escalation_total` (alerts escalated by signal persistence alone, not new evidence), boot-time and live Suricata health, and Pi-hole gravity-API query health.
- New `device_fp_profiles.json` relay in `metrics_sync.py` — the two new thresholds are corrected from the FastAPI webhook subprocess (Telegram "Mark False Positive" taps), a separate process from the one running the scraped Prometheus registry, so they need the same JSON-relay pattern already used for `train_fp_classifier.py`'s calibration output.
- All 5 existing Grafana dashboards updated (new threshold panels, a consolidated Subsystem Health row, cross-navigation links), plus one gap fix found along the way: `home_ids_autotune_arp_sweep_threshold_effective` had sibling calibration/evidence panels since 9.0 but was never itself plotted anywhere.
- New **`6_transparency.json`** dashboard, purpose-built around four questions the other five answer piecemeal: what did the system learn (per-device thresholds), how did it tune itself (calibration history — applied vs. refused), what did it suppress (the CL-AFPE funnel and every autonomous release, by source), and what couldn't it do (every subsystem's live health in one place).

## [v12.0.0] - 2026-08-24

Triggered by investigating two live false-positive storms (`paperless`'s DNS_POLICY_BYPASS, a Samsung Smart Monitor's CONNECTION_ABUSE/NETWORK_INTRUSION/DATA_EXFILTRATION) and a direct question about whether any device showed real signs of compromise. Both threads led to broader, systemic gaps: the "attribution doesn't trace to firing evidence" bug class (v11's own pre-flight-checklist item #1) recurring across four more signature types never covered by that fix, and a self-poisoning gap in the confirmed-intel IP store — 357 legitimate infrastructure IPs, including Google's own 8.8.8.8, actively mislabeled "confirmed malicious" as of this release, some still renewing same-day. No evidence of actual compromise was found anywhere in `alerts.json`, `local_confirmed_intel.json`, or `retro_hunt_findings.jsonl` — every reputation-tier hit traced to legitimate shared infrastructure (Google/Cloudflare/Apple/AWS/Telegram) or LAN multicast noise.

### 🎯 Alert Attribution Audit, Continued

- `zeek_features.py` gained real per-evidence attribution data it never exposed before: `zeek_s0_rej_ip_examples` (which IPs were actually rejected, for CONNECTION_ABUSE), `zeek_lateral_target_examples` (for NETWORK_INTRUSION's lateral-scan case), and `dest_ip` on JA3/JA4/notice records (`get_alerts()`) — `zeek_network.py` and `pipeline.py`'s `zeek_lateral_scan`/`arp_spoofing` evidence now attach a real `.domain`.
- `pipeline.py`'s per-signature attribution-override block gained branches for `CONNECTION_ABUSE`, `NETWORK_INTRUSION`, and `Layer-2 ARP Spoofing Detected` — confirmed live: 3,179 alerts across 18 devices had displayed some unrelated device's DNS resolver or a broadcast address as `destination_ip`, purely from the generic "last connection" fallback.

### 🧠 Per-Device Learned Thresholds Replace Hardcoded Ones

- `threat_signals.py`'s `zeek_conn_abuse` check gained a per-device learned unique-IP threshold (`AutonomousFPEngine.get_device_conn_abuse_unique_ip_threshold()`, same self-healing shape as the existing `arp_sweep_unique_targets_threshold`) plus a blocked/nxdomain-ratio correlation dampener — confirmed live: 245 CONNECTION_ABUSE alerts on one device were 100-165 rejected connections against only 6 unique IPs, correlated with 40-44% of that device's own DNS being Pi-hole-blocked in the same cycles (retrying blocked endpoints, not scanning).
- `mark_false_positive()`'s CONNECTION_ABUSE routing now inspects which of the three possible evidence types (`zeek_conn_abuse`/`zeek_long_conn`/`arp_sweep`) actually fired this specific alert and bumps the matching per-device threshold, instead of always bumping `arp_sweep_unique_targets_threshold` regardless of cause.

### 🛡️ DNS_POLICY_BYPASS Dampening for Infrastructure Devices

- `dns_evasion_anomaly` evidence added to both existing infra-dampening sets (`is_safe`'s `noisy_types`, `_INFRA_NOISY_TYPES`) — a Pi-hole/unbound resolver's own recursive DNS resolution (querying root/TLD/authoritative servers directly) was being flagged as "policy bypass," generating 1,000+ alerts over a week from one device's completely normal operation.

### 📡 Multicast Exclusion for Exfiltration

- `zeek_exfiltration`'s byte-burst check now excludes `_is_local_dest()` destinations (multicast/broadcast/private/loopback) — a Samsung Smart Monitor's own local AllShare/SmartView multicast group traffic (224.0.0.7) was hitting z-scores in the thousands and firing DATA_EXFILTRATION.

### 🔓 ARP-Spoofing: MAC-Randomization Hardening

- A single genuinely-new MAC on an IP now produces weak, corroboration-required evidence (`arp_spoof_pending`, feeding `NetworkIntrusionHypothesis`) instead of an instant zero-corroboration CRITICAL hard-stop — consistent with normal MAC-randomization ("private Wi-Fi address," default since iOS 14/Android 10) reconnect/roam behavior. A second genuinely-new MAC on the same IP within the same 600s window still hard-stops directly, unchanged.

### 🤖 Autonomous Self-Correction Closes the Loop

- The fully-autonomous Stage 2/3 classifier path (`AUTONOMOUS_FP_SUPPRESSED` — local LightGBM+FastEmbed, no LLM, no human, works on modest hardware) now calls the same signature-aware correction `mark_false_positive()` already provides for Telegram/LLM corrections, instead of unconditionally immunizing a `base_domain` that's meaningless for CONNECTION_ABUSE/DNS_EVASION-shaped alerts — that gap meant this path kept re-suppressing the same false positive every cycle forever without ever fixing the underlying threshold.
- `mark_false_positive()` gained a hard-stop guard: refuses to immunize an alert carrying honeypot/arp_spoofing/geofencing/confirmed-exploit/tier-5-IOC evidence, across all three callers (Telegram, LLM, and the newly-closed autonomous path) — previously nothing stopped a single mistaken correction from immunizing a genuinely-confirmed threat.

### 🌐 CDN/Telemetry Allowlist Redesign

- `dns_evasion.py`'s exemption chain reordered — the fast, local, no-timeout-risk ASN-org check (`utils.is_cloud_cdn_provider_org()`, new, same name-based pattern as the existing `is_vpn_provider_org()`) now runs before the slow, network-bound reverse-DNS check, and both are wired to `ti_engine.is_allowlisted()` (live Tranco feed + the persisted CL-AFPE self-healing trust cache).
- `geoip.py`'s reverse-DNS timeout is now distinguishable from a confirmed no-PTR-record (`reverse_dns_status()` returns `(host, timed_out)`) — a lookup that simply queued behind others under load was previously indistinguishable from "genuinely unexplained," inflating false `dns_evasion_anomaly` findings during a reactive-capture burst.
- `ThreatIntel.is_pihole_gravity_domain()` (new) queries your own Pi-hole's REST API for its already-maintained ad/tracker gravity classification — reuses the same `pihole_api_url`/`pihole_api_password` auth `ips.py` already uses for block/unblock, wired into `threat_signals.py`'s telemetry-domain dampening.
- The residual hardcoded CDN/vendor domain list moved to `config.yaml`'s `safe_cdn_base_domains` (hot-reloads via the existing config watcher, no code change needed to add an entry) instead of growing forever in `utils.py`.

### 🗺️ GeoIP: Caching Added

- `lookup()`/`lookup_asn()` gained `@lru_cache` (matching `reverse_dns()`'s existing cache) — the same destination IP was being re-looked-up from the local MaxMind DB at least twice per alert cycle with no caching at all.

### ⏱️ Persistence-Escalation Confidence Honesty

- A SUSPICIOUS alert escalated to HIGH purely by the same single uncorroborated signal persisting for `suspicious_escalation_seconds` (no new evidence) now caps at confidence 0.55, visibly below a genuine 2-independent-source HIGH's 0.85 — previously both reached 0.75+, indistinguishable in the number itself except for a text suffix. `escalated_via_persistence` is now persisted onto the alert record and excluded from `train_fp_classifier.py`'s positive-threat training set.

### 🧹 Confirmed-Intel Self-Poisoning: Public DNS Resolvers Protected

- `KNOWN_PUBLIC_DNS_RESOLVERS` (moved to `utils.py`, shared with `dns_evasion.py`'s existing known-resolver exemption) now also protects `local_confirmed_intel.json`'s write AND read paths — confirmed live: 8.8.8.8 (Google Public DNS) had 64 "confirmed malicious" recordings, still actively renewing same-day, from devices' own direct-resolver DNS traffic (the DNS_POLICY_BYPASS shape). The broader cloud/CDN-ASN case (Cloudflare/GCP/Apple/AWS ranges, also found poisoned) needs `geoip_engine` threaded into `AutonomousFPEngine` for the equivalent ASN-org check — documented as a follow-up, not yet wired.

### 📲 Boot-Time Health Checks Are Now Real

- The startup Telegram message's subsystem status lines were either hardcoded `"✅ Online"` strings (StateManager, ML Registry, IPS Mitigator, Zeek/PiHole Collectors, Master Pipeline — never actually checked) or weak proxies (webhook: process-alive, not response-alive; GeoIP: object-truthy, not DB-loaded). Every line now does the real thing: an actual filesystem write-check, an actual HTTP call to the FastAPI `/health` endpoint, an actual Pi-hole API round-trip (`IPSMitigator.check_pihole_health()`, new), an actual `FritzConnection` handshake, an actual raw-socket probe for the Layer-2 tarpit (`_init_arp_tarpit()` previously claimed "verified" without ever touching a socket), and an actual `suricata --build-info` invocation (`check_suricata_health()`, new — Suricata was previously absent from this report entirely).

### 🔁 Control-Loop Fixes

- Telegram's `unblock`/`release`/`block` button handlers now check the real HTTP response (status code + JSON body's `released` field) before claiming success — previously always showed "✅ released" regardless of outcome.
- `ips.py` gained a background worker (`reconcile_router_isolation_state()`) that periodically queries Fritz!Box's actual current WAN-access-filter state (new `/api/ipc/router_isolation_status` endpoint) and clears any device this IDS still thinks is router-isolated but Fritz!Box doesn't — fixes a device staying "trapped" in Grafana forever after being released directly in the Fritz!Box admin UI, outside this IDS's own flow.

### Verification

Full 29-file phase test suite passes (`test_phase0` through `test_phase38`). Three test files' fake GeoIP fixtures updated to match the new `reverse_dns_status()` contract; `test_phase22`'s source-string assertion updated for the new `noisy_types` member; `test_phase27`'s "unrelated public IP" fixture swapped off an address that turned out to itself be a protected public DNS resolver; `test_phase30` rewritten for the new weak-evidence-then-corroborate MAC-flip behavior, with new coverage for the 2-genuine-flips escalation being correctly scoped per-IP.

## [v11.0.0] - 2026-08-23

A response to a full third-party architectural review of a real production alert history (8,443+ JSONL records, `state/alerts.json`). Every review finding was checked against the live running code — several turned out to already be fixed by v10.0.0 (dated correctly against the review, since the review's data predated that release); the rest are fixed here, or explicitly declined with the reasoning recorded, never silently ignored. New golden-regression and comprehensive end-to-end scenario test suites (`tests/test_phase36_review_regression.py`, `tests/test_phase37_suricata_batch_scan.py`, `tests/test_phase38_comprehensive_scenarios.py`) pin down both the specific bugs found and the full decision-making behavior across every major signature type.

### 🔗 The Core Architectural Fix: One Verdict Path, Not Two

The review's central finding: `fp_engine.py`'s Stage-1 hard-stop filter and `decision_engine.py`'s Hypothesis & Evidence Engine could independently reach *different* verdicts on the identical alert, because Stage-1 re-derived signals from raw features with its own thresholds instead of reading what the HEE had already decided.

- **`fp_engine.py` Stage-1 Check 0 (new)**: recognizes `decision_engine.py`'s own `CRITICAL` verdict directly — honeypot, verified ARP spoofing, geofencing, and tier-5 confirmed IOC now flow through one path, not two that happen to usually agree.
- **Check 1 (ThreatIntel) threshold fixed**: was `ti_risk > 0` — ANY nonzero score, however weak, unconditionally hard-stopped, bypassing `classifier.py`'s own more careful `ti_score > 2.0` confirmed-IOC bar. Now the same bar both subsystems use.
- **Check 6 (exfiltration burst) fixed — a live bug, not just a theoretical mismatch**: was missing the absolute-byte floor (`>2.5MB`, not just a z-score spike) and the telemetry/vendor-cloud exemption `threat_signals.py`'s equivalent `zeek_exfiltration` evidence check already had. Confirmed live against the tail of the running `state/alerts.json`: an Amazon Echo device's AWS IoT/MQTT connection (TCP:8883, 261 actual bytes moved) was hard-stopping to `CONFIRMED_THREAT` purely from `outbound_bytes_z=9.3`, while `decision_engine.py` simultaneously called the same alert `SUSPICIOUS/monitor (confidence=0.40)` — the exact two-verdict shape the review described.
- Checks 2 (lateral movement), 3 (malicious TLS), 4 (honeypot), 5 (AbuseIPDB), and 7 (local confirmed-intel) were audited against `decision_engine.py`'s current thresholds and found already consistent — deliberately left as-is rather than rewritten for its own sake; see the session notes on why a full evidence-store migration of these was scoped out as unjustified risk for a live containment system with no corresponding bug found.

### 🎯 `DNS_EVASION` Now Says What It Actually Found

The review flagged this signature name as misleadingly uniform: a device with zero DNS footprint, a device with one attribution-window miss on otherwise-normal history, and a device directly bypassing Pi-hole on port 53 all produced the identical, equally-alarming `DNS_EVASION` name.

- **`DNSEvasionHypothesis` now picks one of three names** from a stable subtag `dns_evasion.py`'s blind-spot audit attaches to its evidence: `DNS_POLICY_BYPASS` (a direct port-53/853 connection to a non-Pi-hole resolver — the most specific, most actionable finding) → `DNS_EVASION` (genuinely zero DNS history at all) → `DNS_ATTRIBUTION_GAP` (otherwise-normal history, one connection outlived its lookup window — the weakest, most honest name for the weakest evidence). Detection thresholds are completely unchanged; only the name reflects what was actually found.
- **`ZeekFeatureExtractor` gained port tracking** (`get_dest_ports()`, parallel to the existing `get_dest_ips()`) so `DeviceBurstAudit` can see which port an unexplained connection used — the data `DNS_POLICY_BYPASS` detection needed and didn't have before.
- Every `primary_sig_base`-keyed branch in `pipeline.py` and `fp_engine.py`'s human-correction routing updated to treat all three names identically (same "no domain, dest_ip is the real target" attribution shape either way).

### 🧬 Per-Device Learned Behavioral Baseline

- **`AutonomousFPEngine.record_device_baseline_observation()` / `get_baseline_familiarity()`** (new): each device learns its own normal ports/ASN-owners/domain-bases over time, persisted in the existing `state/device_fp_profiles.json`. Deliberately gated on the HEE's own verdict for that cycle already being BENIGN/ANOMALOUS — a device beaconing to a C2 host every cycle cannot launder itself into a trusted baseline through repetition, which would be exactly backwards for a self-healing mechanism.
- Wired into `dns_evasion.py`'s blind-spot audit (damps confidence for an unexplained IP whose ASN this device has legitimately talked to before) and into `DeviceProfileBenignHypothesis` as an alternate path to the same "routine, not surprising" conclusion the global reputation tier already grants — scoped to what this one device's own history actually supports, not a global classification change. `Hypothesis.evaluate()`'s signature gained a `baseline_familiarity` parameter (backward-compatible, defaulted) threaded through `HypothesisEngine.evaluate_all()` and `DecisionEngine.evaluate()`.

### 🔎 Real Signature/Exploit Detection: Batch-Mode Suricata

Zeek is a behavioral/flow analyzer, not a signature-matching engine — real exploit/malware-signature detection was a genuine, previously-unaddressed gap. Evaluated and rejected: running Suricata continuously (heavyweight, and a poor fit for a Raspberry Pi target this project also needs to run on). Shipped instead:

- **`intelligence/detectors/suricata_scan.py`** (new) — runs Suricata in pure batch/offline mode (`suricata -r burst.pcap`) against the exact same reactive-capture burst pcap Zeek already reprocesses, never continuously against live traffic, so idle cost is exactly zero between bursts. Parses `eve.json` alerts, attributes each to a tracked device by src/dest IP match, and turns real signature matches into `Evidence` — never a second independent verdict path (learned from the architectural fix above).
- **`SuricataSignatureHypothesis`** (new) scores it like every other hypothesis; a genuinely high-severity match (Suricata's own `severity=1`/"high", confidence≥0.9) is a new explicit `decision_engine.py` hard-stop (`has_confirmed_exploit`) — matching the review's own "confirmed exploit"/"known malware signature" hard-stop category.
- No rules shipped or authored by this project (re-curating threat intelligence Suricata/Emerging Threats already maintains would be low-value reinvention) — point `reactive_capture_suricata_rules_path` at a ruleset you manage yourself (e.g. `suricata-update --etopen` with a trimmed policy). **Disabled by default** (`reactive_capture_suricata_enabled: false`) — inert until installed and configured.

### 📐 Calibration and Other Labeling Honesty

- **`train_fp_classifier.py` now holds out a genuine validation split** (stratified 75/25, when enough data exists) and fits isotonic regression against predictions on the HELD-OUT split only — never against the same data the classifier trained on, which would just restate training accuracy in a different shape, not calibrate anything. Saved as `state/models/fp_calibration.json`, applied at inference time via dependency-free linear interpolation (`fp_engine.py`'s `_apply_calibration()` — no sklearn import needed in the lean runtime path). An explicit `reliable: false` marker (not a fabricated curve) when there's too little held-out data.
- **`P(FP)` relabeled `FP_MODEL_SCORE`** everywhere it reaches a human or an LLM, explicitly noted as uncalibrated when no calibration is loaded — the raw LightGBM/GBDT output was never a calibrated probability regardless of whether a curve exists yet. FastEmbed similarity text now explicitly says "contextual evidence, not a verdict."
- **Kill-chain phase labels `SUSPECTED_`-prefixed** (`RECON`/`C2`/`LATERAL`/`EXFIL` → `SUSPECTED_RECON`/etc., `NORMAL` unchanged) — these are heuristic feature-threshold guesses (`dns_features.py`'s `_determine_killchain_phase()`), not confirmed kill-chain stages; nothing in `decision_engine.py`/`hypotheses/engine.py` ever consumed the bare form (Grafana-telemetry only), but a human reading "EXFIL" on a dashboard panel had no way to know that from the label alone.
- **`classify_payload_size()` stopped guessing protocol from byte count** — a sub-128-byte TCP/UDP/ICMP/anything packet no longer displays as "Standard DNS/Control Packet" regardless of actual protocol; `classify_service(port, proto)` a few lines away already does correct protocol/service naming from data the same alert payload already carries.

### 🕸️ Parent-Domain DNS Tunneling Signal

- **`fanout_label_entropy`** (new `dns_features.py` feature): average Shannon entropy of the first label across every child domain sharing the winning subdomain-fanout parent. Fanout COUNT alone can't distinguish "many meaningfully-named subdomains" (a legitimate multi-tenant SaaS) from "many randomized/encoded chunks" (the real tunneling shape) — `threat_signals.py`'s `subdomain_fanout` check now scales confidence with this, on top of the existing count-based baseline and CDN/telemetry exemption.

### 🔍 Visibility: Incident Rollup

- **`src/scripts/incident_report.py`** (new, read-only, doesn't touch `alerts.json`) — groups the training log by the `incident_id` already stamped onto every alert record, giving a human "ONE INCIDENT, N occurrences" view instead of requiring a manual read of raw JSONL (exactly what the third-party review had to do by hand to reach its own conclusions). `alerts.json` itself deliberately stays append-only-per-cycle — that's correct for CL-AFPE training data, unaffected by this.

### Verification

Golden regression suite (`test_phase36`) pins the two live bugs found plus golden cases for the review's own named examples (weak AbuseIPDB signal → tier 4 not 5, CDN telemetry domain → no false tunneling verdict). Comprehensive end-to-end suite (`test_phase38`) exercises the real `DecisionEngine`/`HypothesisEngine`/`ReputationClassifier` stack across every major signature family — benign device telemetry, per-device learned baseline, VPN false-positive exclusion, DGA, DNS tunneling, all three DNS-evasion names, lateral-movement corroboration, Suricata hard-stop vs. evidence-only, every hard-stop condition, reputation-tier golden cases, corroboration-requirement regression guards, kill-chain labeling, and the payload classifier fix. Full test suite (30 files) run before this release.

## [v10.0.0] - 2026-08-23

Evidence-families corroboration fix, incident-volume aggregation, per-device benign device-category profiles, and an Ollama circular-reasoning guard — the four items a prior third-party review flagged as reasonable forward-looking architecture improvements (not live bugs). Bundled with a same-day live-data audit that found and fixed three additional real production bugs.

- **Evidence-families registry** (`hypotheses/evidence.py`'s `EVIDENCE_FAMILIES`/`ATTACK_EVIDENCE_FAMILIES`) replaces `decision_engine.py`'s old hand-maintained hybrid type-prefix-or-group-membership filter for "how many independent evidence sources does this device have" — the old filter had silently never been updated when `arp_sweep`/`lan_recon` evidence was added, so a real ARP-sweep-plus-corroborating-signal case never counted toward the 2-independent-sources bar a HIGH verdict requires.
- **`IncidentTracker`** (`core/incident_tracker.py`, new) collapses repeat Telegram notifications for the same ongoing incident (same device+target+signature) into: first occurrence, any severity escalation, and periodic "still ongoing" updates — instead of a full alert every qualifying cycle. `alerts.json` itself is unaffected (still one line per qualifying cycle, for CL-AFPE training); this only gates the Telegram layer on top. `incident_key.py` (new) is the shared "same incident" identity both this and `ollama_soc.py`'s offline batch grouping now import, replacing a previously-duplicated definition.
- **`DeviceProfileBenignHypothesis`** (new) — device CATEGORY (smart_tv/iot/gaming_console/nas/router/gateway/dns_server, from `utils.infer_device_type()`; deliberately no brand dimension, since there's no detection basis to distinguish "Amazon Fire TV" from "Google Chromecast") combined with trusted/known-infrastructure reputation tier and elevated DNS activity now scores a named `DEVICE_PROFILE_TELEMETRY` benign verdict instead of falling through to the generic `UNKNOWN_BENIGN` catch-all. Explicitly backs off when genuine attack-shaped evidence exists on the same device, so it can never silently outscore a real (if currently-dampened) attack finding.
- **`DeterministicValidator` circular-reasoning guard** (`intelligence/ai_soc.py`) — Ollama is no longer shown risk score, signature, factors, or fp_verdict at all (`ollama_soc.py`'s `_build_evidence_only_payload`); a "malicious" verdict whose own justification cites the exact prior risk score anyway (a leaked/stale prompt, or a future regression reintroducing it) is now rejected the same way a hallucinated benign-despite-IOC verdict already was.
- **Same-day live-audit bugfixes**: `safe_ips` wasn't actually protecting infrastructure from three separate alert paths; lateral-movement/reputation/persistence-suffix misattribution bugs found via a post-v9.0.0 state-folder audit; a DNS_EVASION false-positive storm and two alert-text contradictions traced to CDN/telemetry false-positive-and-negative gaps in the DNS tunneling detector.

## [v9.0.0] - 2026-08-22

The largest release since the Hypothesis & Evidence Engine rewrite. Two major bodies of work: a new **reactive Fritzbox WLAN capture subsystem** that gives this deployment its first real (if partial) network-flow visibility into WiFi devices — previously 100% dark to Zeek on an all-in-one router — and a wide correctness pass across detection, false-positive suppression, and the ML training pipeline, driven by tracing real production alerts (`alerts.json`, `journalctl`, live service restarts) line-by-line back through the code rather than working from assumptions. Every fix below was verified against a concrete, reproducible case; several against a live production instance via real curl/API round-trips. Full 22-file phase test suite (up from 9 at v7.0.1) passes.

### 📡 New: Reactive Fritzbox WLAN Capture (Phase 21)

Closes a real, live-confirmed gap: on an all-in-one modem+router+AP (this deployment's Fritzbox, and most consumer routers), neither a mirror port nor an inline bridge can see WiFi-to-WiFi traffic at all — only the two wired devices had genuine Zeek flow visibility (lateral movement, JA3/JA4). AVM's own per-radio diagnostic capture (`ath0`/`ath1`) *does* see it (confirmed with a live controlled ping test), but continuous dual-radio capture measured ~3GB/hour with observable router latency under load — this ships the reactive, triggered-burst alternative instead. Full architecture in [Documentation/ARGUS_ARCHITECTURE.md](ARGUS_ARCHITECTURE.md).

- **Fritzbox capture client** (`extractors/fritzbox_capture.py`) — TR-064 challenge-response auth (PBKDF2 + legacy MD5 fallback), live-verified capture-burst start/stop against the real `capture_notimeout` endpoint, AVM-format→standard pcap conversion, and reprocessing through the same live `local.zeek` policy (JSON logging, MAC-logging, DHCP fingerprinting, JA4/JA3) — feeding results into the exact same `ZeekFeatureExtractor` instance live traffic uses, so WiFi devices get real JA3/JA4 signal (both Stage-1 malicious-fingerprint matching and JA4-overlap device re-identification) for the first time, as a direct consequence of the design rather than new logic.
- **ARP host-discovery sweep detection** — broadcast-visible, works without any Fritzbox integration (ARP reaches WiFi devices the same way MAC correlation already does). Required a missing Zeek script: stock Zeek 8.0.8 ships the underlying `arp_request`/`arp_reply` events but no script that writes `arp.log` — added `zeek_scripts/local-arp-log.zeek`, confirmed end-to-end against 71/71 real request/reply pairs from a live capture. New `arp_sweep` evidence wired into `ConnectionAbuseHypothesis` as an alternate trigger; per-device auto-calibrated threshold (see Autonomous Learning below).
- **DNS-evasion blind-spot audit** (`intelligence/detectors/dns_evasion.py`) — compares a device's real captured destinations against its own DNS query history, flagging connections neither DNS nor known infrastructure explains: the one detector class structurally invisible to every DNS-shape-based detector this system already had. Excludes intra-LAN/RFC1918 destinations and recognized commercial VPN-provider ASNs (modeled on a real live false-positive against a device's own NordVPN traffic) before flagging anything.
- **Six trigger sources**, all sharing one hourly budget (`reactive_capture_max_bursts_per_hour`) rather than a per-trigger cooldown, since one burst captures the whole radio regardless of which source fired it: any non-benign decision path, an ARP-sweep hit, a cold-start on a never-seen MAC, a genuinely-ambiguous device re-identification candidate, a new source contacting a wired-visibility device, and any HIGH/CRITICAL decision — plus an in-process periodic spot-check. All fire on a background thread, never blocking a pipeline cycle.
- **Self-healing extensions** — the new count/threshold-based detectors don't fit the existing z-score `sigma_shift` mechanism, so `mark_false_positive()` gained signature-based dispatch: a `DNS_EVASION` correction immunizes the alert's actual flagged destination IP (not a generic "last known IP", which could be the wrong one — fixed separately after the routing itself was wired in) via the existing IP-checked trust-cache fast path; a `CONNECTION_ABUSE`/`arp_sweep` correction raises that device's own sweep threshold immediately via a new per-device multiplier file, not just after the next weekly retrain.
- **Autonomous network-wide threat learning** (Phase 21D3) — a new self-growing local confirmed-threat store (see below) plus `retro_hunter.py` cross-referencing it against recent alert history to catch "device B also touched this IOC days ago but wasn't over its own threshold at the time."
- **Disk safety** — try/finally cleanup of each burst's raw pcaps/Zeek scratch output right after ingestion, a permanent compact JSONL history trail (`reactive_capture_history.jsonl`) kept regardless, and a periodic crash-orphan sweep.
- **`reactive_capture_wired_probe_ips` activated** with this deployment's real NAS and Ubuntu-server IPs, turning the wired-probe trigger on for real.
- **Telegram alert volume tightened** as an explicit, deliberate reversal of an earlier "alert on any single strong signal" decision: notifications now require the same genuinely-corroborated HIGH/CRITICAL bar that already authorizes a Pi-hole block, never firing for SUSPICIOUS/monitor-only decisions — shipped independently, no new infrastructure required.

### 🧠 New: Network-Effect Threat Learning, and the poisoning bug found in it

- **`local_confirmed_intel.json`** (`intelligence/local_intel.py`) — once any device's traffic reaches a Stage-1 hard-stop or a genuinely-corroborated HIGH/CRITICAL verdict, the triggering domain/IP is recorded so a *different* device touching the same infrastructure later gets an immediate hard-stop instead of re-earning independent corroboration from scratch. TTL-bounded (30 days).
- **Found and fixed a severe, self-reinforcing poisoning bug in this exact store**, on both the domain and IP side: matching at the eTLD+1 base-domain level meant one bad hit against a subdomain of `amazon.com`/`netflix.com`/`microsoft.com` permanently "confirmed" the entire shared vendor domain as malicious for every device thereafter; matching IPs by exact string did the same for private/multicast/loopback addresses — including this network's own router and server. Worse, every subsequent hard-stop re-recorded the same entry (`TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP`), refreshing its TTL indefinitely — a bug that would never have expired on its own. Fixed on **both** the write path (refuses to record a known-safe telemetry/CDN base domain or a private/multicast/`safe_ips`-listed address) and the read path (Stage-1 Check 7 independently re-validates before honoring an existing entry, neutralizing already-poisoned historical data with no file migration needed) — the general "floor on write AND read" lesson now codified in `CLAUDE.md`'s pre-flight checklist.
- **`safe_ips` was documented but never actually consulted** by this store until this fix — a config key that existed and was even referenced in the User Manual, but was dead weight for this exact purpose.
- **`src/clean_confirmed_intel.py`** — new dry-run-by-default maintenance CLI to audit/prune the store for the two poisoning categories above, for the ongoing case where a newly-added allowlist entry should retroactively clean data poisoned before it existed.

### 🎯 Detection Correctness

- **Alert domain/target attribution fixed in three separate signatures**, all sharing the same root cause: `pipeline.py`'s target-domain picker falls back to "most notable domain in the whole window," structurally disconnected from which specific evidence actually fired that cycle. Found independently in `DNS_EVASION` (fixed earlier), then `DNS_COVERT_TUNNELING` (confirmed live: a 19-character domain shown as "Target" alongside evidence reading `max_label=57`, measured on a completely different, never-displayed domain), then `DGA_BOTNET_C2` (worse in kind — `dns_dga_burst` carried no domain examples at all pre-fix, and the misattribution was initially mistaken for a real coordinated attack across 6+ unrelated devices before being traced to this gap). All three now attach `Evidence.domain` from the same per-domain loop that generates the evidence, not a window-wide aggregate.
- **A recurring, 5+ day false-positive against Telegram's own infrastructure** (`149.154.166.110`, AS62041) — the exact case a prior fix had only reduced, not eliminated, since AbuseIPDB's crowd-sourced score for a huge shared IP block naturally drifts above and below any fixed threshold over time, and a raw IP with no resolved domain can't be immunized by any domain-based safe-list. Fixed with the same pattern already proven for VPN providers — ASN-org-name matching, not a brittle IP list.
- **A deeper tier-escalation bug found while fixing the above**: the reputation classifier's confirmed-IOC escalation logic ran unconditionally on every evaluation, meaning even an explicit tier-0/1/2 ("trusted") classification could be overridden straight back to tier 5 by a single stray reputation score — contradicting the class's own documented intent. Now only escalates from the unclassified tier; an explicit safe classification is a floor, not a suggestion.
- **Persistence-escalation could silently bypass the HIGH/CRITICAL containment severity gate.** A cross-cycle mechanism (predating the severity gate) promotes `SUSPICIOUS`→`HIGH` purely from a signature recurring on the same device for ≥10 minutes with no new evidence — harmless when it only affected alert urgency, but once containment started trusting `decision["state"]` alone, this became a silent door around "block only after genuine corroboration": a single uncorroborated, merely-repeating signal could earn an auto-block after 10 minutes while its own published alert still (truthfully) read `SUSPICIOUS`. Fixed with a separate `containment_decision_state` that downgrades back to `SUSPICIOUS` specifically for persistence-driven escalation, while every other display of the decision is untouched.
- **The ARP/NDP spoof detector false-positived on legitimate mesh-WiFi MAC oscillation**, feeding a Stage-0 hard-stop. It compared only against the single last-seen MAC-to-IP binding, treating every re-appearance of a previously-valid pairing as new spoofing. Now tracks a real per-IP MAC history and only fires when the MAC genuinely wasn't previously known for that IP.
- **The DNS-evasion blind-spot detector flagged intra-LAN traffic as "unexplained," causing continuous re-alerts** — private/RFC1918 destinations are now excluded before anything can be called unexplained external traffic.
- **Pi-hole v6 REST API was never actually reachable** — the code sent list-type and match-kind in the request body; v6 requires them in the URL path (`/api/domains/{type}/{kind}[/{domain}]`). Every real block had been silently falling through to the CLI fallback; confirmed via a live curl round-trip (POST 201/GET/DELETE 204) after the fix, comment text now confirmed actually reaching Pi-hole.
- **Self-healing immunization only released an exact base-domain string match**, but blocks are keyed by the specific queried FQDN — almost always a subdomain. Confirmed live: 21 domains (WhatsApp, Facebook, Netflix, NTP, Samsung Apps, `zee5.com` subdomains) sat blocked despite their base domain already being trusted, one still blocked 7 minutes after the correction that should have released it. New `unblock_by_base_domain()` sweeps every blocked entry sharing a newly-trusted base domain, applied at all three self-healing call sites (autonomous CL-AFPE, LLM-validated, and the operator Telegram handler — which previously had no local-state check at all).
- **Ollama's batch analysis reached contradictory verdicts on the identical DGA-shaped pattern across devices in the same run**, because each call analyzes one device+target+signature group in total isolation. A multi-device spread guard now withholds auto-suppress (deferred, not skipped) when the same signature is independently firing on ≥3 distinct devices at once, rather than letting one instance's benign verdict silently write false-positive training data for what a cross-device view shows is DGA-shaped.
- **`zeek/salesforce/ja3` never actually worked on modern Zeek** (unmaintained since 2020, client-hello handler doesn't fire on Zeek 8.0.8) — switched to FoxIO's actively-maintained `zeek/foxio/ja4`, renaming the re-identification path throughout (`ja3_overlap`→`ja4_overlap`, etc.). Separately found the real root cause behind JA3/JA4 looking broken regardless of which package was installed: `zeekctl` silently ignores `node.cfg`'s `extra_args=-C`, so Zeek was discarding checksum-offloaded LAN-device outbound packets by default — fixed via `redef ignore_checksums = T;` directly in `local.zeek`.
- **`state.killchain_history` was read every cycle but never appended to anywhere** — `markov_anomaly` had been permanently `0.0` for every device since the feature was introduced.

### 🤖 Machine Learning & Training Data Integrity

- **The Tranco-rank feature (`tranco_rank`, Feature 0 of the LightGBM vector) was always zero.** `threat_intel.py` already downloaded the full ranked 1M-row Tranco list to build its Top-10k allowlist, but discarded the rank number on every line — `features["tranco_rank"]` was read by both Stage 2 and the trainer but never written anywhere. Fixed by capturing the rank half of the same already-downloaded data (`ThreatIntel.get_tranco_rank()`, persisted to `tranco_ranks.cache`, no extra network cost) and wiring `pipeline.py` to populate it.
- **New: identification/exclusion of historically-corrupted training rows.** The two domain-attribution fixes above (`DNS_COVERT_TUNNELING`, `DGA_BOTNET_C2`) mean `f1_entropy` was computed from the wrong domain for every affected alert predating each fix. Fixing the code doesn't fix rows already on disk — `src/identify_corrupted_training_rows.py` identifies them via each fix commit's own timestamp as a conservative, provable per-signature cutoff, and writes their dedup keys to a new, deletable overlay file (`state/training_row_exclusions.json`) that `train_fp_classifier.py` consults during training, without ever mutating `alerts.json`/`autonomous_muted.jsonl` themselves (both are read by other consumers that need the full real history).
- **LightGBM/ONNX classifier extended from 9 to 11 feature dimensions** (`arp_sweep_norm`, `dns_evasion_ratio`) to actually see the two new detectors — an earlier assumption that these were "inherited for free" by the classifier was wrong for this specific fixed-shape vector (true only for Ollama, which sees the full raw payload, and training-set inclusion generally). Verified with a real ONNX export + inference run.

### 🔍 Metrics, Observability & Grafana

- **Implemented the full metrics-audit report**: dropped unbounded-cardinality labels (lat/long crossed with country/ASN/org, attacker-chosen domain/IP labels), removed 4 redundant/dead counters, and added a new `home_ids_decision_path_total` gauge as the direct "is the system getting smarter over time" signal, plus source-labeled (`autonomous`/`operator`/`llm_validated`) self-healing counters. Every scheduled job now syncs its own JSON stats file into Prometheus gauges (`metrics_sync.py`'s new relay pattern) — job staleness is now a Grafana panel, not a manual log check.
- **New 5th Grafana dashboard**, "Autonomous Behavior & Self-Healing": decision-path mix, self-healing activity by source, autotune calibration, Ollama run transparency, containment unblock/release activity, scheduled-job health.
- **Fixed two classes of broken Grafana navigation link** found by actually testing them: cross-dashboard links using the wrong routing field (`uid` vs. this instance's `name`-based routing, across 20 links in 5 dashboards), and the Master Ledger's Isolate/Release links pointing at `127.0.0.1` (unreachable from a remote Grafana client).
- **Fixed the geomap panel** by adding a bounded static country-centroid table (~250 countries) after lat/long were deliberately removed from the traffic metric for cardinality reasons.
- **34 new full-transparency panels** for reactive capture, local confirmed-intel, and the new detectors — closing what had been zero-metrics visibility gaps.

### 🐛 Reliability & Concurrency

- **Two `UnboundLocalError` crashes, one crashing every single pipeline step.** A mis-indented `elif` attached to the wrong `if`, and a missing default assignment for `containment_decision_state` on the CL-AFPE auto-suppress path — both meant a variable could be read on a code path that never assigned it. Fixed by re-tracing every branch of both conditional chains, not just the lines originally touched.
- **Concurrent reactive-capture bursts were corrupting each other's output** — burst execution is now serialized.
- **Zeek reprocessing of a capture burst never found the pcap** — a relative path resolved against the wrong working directory.

### 🧹 Dead Code / Silent-Feature Audit

A full pass checking every function for "is this called at all, and correctly" turned up code that was built and tested in isolation but never reached from a real runtime path, alongside genuinely dead code:

- **ML anomaly models now migrate on device re-identification** — `MLRegistry.migrate_device()` existed and was accepted as a parameter by the identity-processing call sites, but nothing ever actually called it.
- **Stale isolation bookkeeping now actually clears on a re-identify merge** — `IPSMitigator.unisolate_all()` existed but was never invoked at the one point a merge could make it necessary.
- **`pipeline.py`'s `dest_ip` fallback now prefers Zeek's real wire-observed DNS resolution** over a live blocking `socket.gethostbyname()` call — more accurate, zero latency, and stops the IDS generating its own outbound DNS traffic as a side effect of alerting.
- **The FastAPI IPC/webhook server previously never started under default config** despite Telegram's revoke buttons pointing at it — it was gated solely on `ips_router_enabled` (default `false`), not the separate flag (`fp_revoke_notifications_enabled`, default `true`) that actually sends those buttons.
- **Deleted dead code**: an unbatched/uncached/no-rate-limit `OllamaSOCAnalyst` class that would have reintroduced the 849-second-blocking-call resource crisis fixed in 8.0 if ever wired in; three `StateManager` methods superseded by code paths that evolved independently (one of which referenced unimported names and would have raised `NameError` the one time it was called); two fully-unused `utils.py` functions.

### ⚙️ Configuration

- **Path-hardcoding cleanup**: every installation-specific path (`pihole_db`, `zeek_log_dir`, `reactive_capture_zeek_bin`) consolidated into a new `external_system_paths` config section at the bottom of `config.yaml`, with a "DO NOT TOUCH unless you know what you're doing" warning banner — separated from this app's own relocatable data-file paths.
- **`config.yaml` grew to 14 categories** with the addition of `reactive_capture`.
- **`requirements.txt` fixed**: 4 packages actually imported but missing (`skl2onnx`, `geoip2`, `joblib`, `urllib3`); stale Docker-era hardcoded fallback paths removed from `main.py`/`retro_hunter.py`.

### 🛠️ New Maintenance CLI Scripts

All dry-run-by-default, `--apply` to act — see [USER_MANUAL.md](USER_MANUAL.md#maintenance-cli-scripts-src-new-in-90):

- `src/clean_confirmed_intel.py` — audits/prunes the confirmed-intel poisoning categories above.
- `src/release_wrongly_blocked_domains.py` — classifies every currently-blocked Pi-hole domain (recognized-safe / manually-reviewed-safe / suspicious DGA-pattern / unclassified) and releases the safe categories.
- `src/clear_stale_isolation.py` — removes stale isolation bookkeeping for a single device without touching its domain blocks, for the case of a manual out-of-band router release the IDS's own state doesn't know about.
- `src/identify_corrupted_training_rows.py` — see Training Data Integrity above.

### 📚 Documentation

- **`CLAUDE.md` gained a "pre-flight checklist"** distilling ~12 recurring bug *classes* found this release (attribution-picker disconnection, non-exhaustive branches, unguarded learned-state poisoning, documented-but-unwired config keys, dead ML feature dimensions, legitimate-oscillation false positives, config-key collisions, historically-corrupted training data, mutating shared historical logs, escalation overriding an explicit trust floor) into concrete checks for future work — ported in generalized form to the `IDS_Product` sibling fork.
- Zeek installation docs corrected throughout (`/var/log/zeek` → the real `/opt/zeek/logs/current`, missing `mac-logging.zeek`/`local-arp-log.zeek` dependencies, a fabricated `detect-recon.zeek` load line removed, the checksum-offload gotcha documented).

## [v8.0.1] - 2026-08-18

Follow-up to v8.0.0, closing a gap in the autonomous suppression → containment relationship: immunizing a domain stopped *future* alerts for it, but nothing actually released a block that had already been placed by an *earlier* cycle. Per explicit direction — block only what's absolutely necessary; over-blocking risks breaking the legitimate function of a device.

### 🔓 Autonomous Unblock-on-Immunize

- **`pipeline.py`'s primary autonomous suppression path now releases stale blocks.** Every CL-AFPE Stage 2/3 auto-suppress runs through this path (the highest-volume one, by far). It previously immunized the domain but never checked whether an earlier cycle — before the pattern was learned as safe — had already blocked it in Pi-hole. Now checks local state first (`state_manager.get_ips_state()["blocked_domains"]`, no network call) and calls `unblock_domain()` only when the domain is actually currently blocked, avoiding both wasted Pi-hole API traffic and an inaccurate "released" log line for domains that were never blocked.
- **`ollama_soc.py`'s LLM-validated correction path gets the identical fix**, via its own `IPSMitigator` instance (same pattern `middleware/routers/pihole_api.py`'s existing Telegram-button handler already uses for exactly this — a fresh `StateManager` + `IPSMitigator` per invocation, since `unblock_domain()` makes a real Pi-hole API call regardless of which process instantiated the client).
- **The operator "Mark False Positive" Telegram path already had this** (`_ipc_immunize_logic()`'s existing FIX #3) — it was the two *autonomous* correction paths that were missing it, both now closed.

### 🏷️ Block Attribution Made Durable

- **Every Pi-hole block already carried a `"Home-IDS Auto-Block | Device: ... | Trigger: ..."` comment** on the primary (v6) API call path — this already existed prior to this release. What was missing: the two fallback paths (local `pihole deny` CLI, legacy v5 API) had no verified way to carry that comment through to Pi-hole without risking the block call itself failing on an unfamiliar CLI flag, so on those paths the attribution existed nowhere at all if Pi-hole's own comment field wasn't reachable.
- **Fixed by storing the same comment text in local state** (`ips.py`'s `_finalize_block()` now writes a `comment` field into `state/ids_state.json`'s `blocked_domains[domain]` entry, on every successful block regardless of which of the three Pi-hole paths executed it). This is now the durable, always-present answer to "was this blocked by the script, and why" — queryable locally even when Pi-hole's own UI doesn't show the comment (fallback paths) or is unreachable.

## [v8.0.0] - 2026-08-18

This release started from a third-party review of a single live alert (a connection to Telegram's own infrastructure that had been auto-blocked as a "99% Confirmed Malicious IOC") and expanded into a full trace of the detection, false-positive, and self-healing pipelines against the actual running code — plus a resource-usage crisis with the local LLM discovered via live diagnostics on production hardware, and the autonomous self-calibration system that request led to. Every fix below was verified against a concrete, reproducible scenario before being called done; several were confirmed against real entries in a live `alerts.json`, not synthetic test data.

### 🎯 Detection Correctness

- **Fixed a real false-block.** `reputation/classifier.py` was promoting a destination to "confirmed malicious IOC" (tier 5, `CRITICAL`, auto-block, 99% confidence) from a single AbuseIPDB score alone (`>2.0`), with VirusTotal and ThreatIntel both showing clean. The live case: a device talking to `149.154.166.110` — Telegram Messenger's own infrastructure. AbuseIPDB's crowd-sourced score is now required to clear `≥4.0` to reach "confirmed" — the exact bar `fp_engine.py`'s own hard-stop check already trusted it at (previously the two disagreed for the identical input). VT/TI keep the lower `>2.0` bar; they're more authoritative single-source signals.
- **Added a real `SUSPICIOUS`/monitor path for unconfirmed reputation signals.** Before this fix, a reputation signal that didn't reach "confirmed" had exactly one path through `decision_engine.py`: silence. Devices with a moderate, unconfirmed reputation ping now get a `SUSPICIOUS`/monitor-only verdict (never auto-blocks on this alone) instead of either a false "confirmed" block or nothing at all.
- **Fixed `intelligence/fp_engine.py` feeding the literal string `"unknown"` into semantic similarity scoring.** Raw-IP connections with no resolved hostname had `domain="unknown"`; Stage 3's FastEmbed cosine-similarity was scoring that literal word against vendor-domain embeddings and getting back a real-looking-but-meaningless number that materially swayed the combined false-positive score. Stage 3 is now skipped entirely when there's no real domain/hostname, falling back to LightGBM alone at full weight.
- **Fixed a raw IP address being mangled through the domain-suffix extractor.** `utils.py:etld1()`'s naive last-two-labels fallback was chopping bare IPs into fake 2-octet "domains" (e.g. `149.154.166.110` → `"166.110"`) — found sitting in `state/fp_trust_cache.json` as a literal `"166.110"` key, a meaningless, collision-prone trust-cache entry. IP-shaped input is now rejected before either extraction path runs.
- **Fixed the Telegram "⏳ WAITING FOR APPROVAL" contradiction.** `mitigate()`'s interactive-approval branches are only reachable at `risk ≥ 8.5` or an active lateral-movement flag — below that, nothing is ever queued. But `pipeline.py`'s alert formatter rewrote *any* "unblocked" containment status to "WAITING FOR APPROVAL" whenever `interactive_blocking_enabled` was on, with no check on whether anything was actually pending. A live `SUSPICIOUS`/monitor alert at risk 4.5 was showing "Action Required" approval buttons for an isolation that was never queued. Both the status-text override and the button attachment are now gated on the same `risk ≥ 8.5 or lateral_threat` floor `mitigate()` itself uses.
- **Closed a 43%-of-alert-volume false-positive gap.** Traced a live `alerts.json`: 169 of 227 alerts (74%) were `DNS_COVERT_TUNNELING`, and 97 of those (43% of *all* alerts) were a single benign Amazon telemetry hostname (`msh.amazon.co.uk`) — the same long-encoded-subdomain shape as an earlier Prime Video false-positive fix, just never extended to this domain. Added `amazon.co.uk`, `amazon.de`, `facebook.com`, `whatsapp.com`/`.net`, `netflix.net`, `pluto.tv`, `bugsnag.com`, and `ntp.org` to the CDN/vendor allowlist after confirming each was a real repeat offender in production traffic (and confirming a genuinely suspicious `.ru`-TLD domain in the same alert set correctly still trips detection).

### 🧭 Alert Transparency

- **Alerts now show a step-by-step reasoning trail** (`decision_engine.py` builds a `reasoning_trail` list alongside every decision: hard-stop check results, reputation context including IP ownership via ASN lookup, hypothesis scores, final verdict) instead of a bare confidence number. `ReputationVector.asn_owner` existed as a dataclass field but was never populated by anything — it's wired to the existing GeoIP ASN lookup now.
- **The Telegram headline no longer disagrees with its own trigger line.** It previously read `decision["hypotheses"]["attack"]["name"]` — which falls back to a generic placeholder (`DIRECT_IOC_HIT`) whenever no attack hypothesis's own evidence matched, even when the real trigger was a reputation hard-stop. Now reads `decision["explanation"]`, the same source the trigger line already used, so they can never disagree.
- **The false-positive engine's own combined confidence is now labeled explicitly** as a separate measurement from the decision engine's threat confidence, instead of two bare percentages sitting side by side with no explanation of what either one is (a third-party review flagged this as reading like an internal contradiction — it was really two independently-computed numbers with no labels).
- **Reputation "tier" is now documented and displayed as context, not a verdict** — `ReputationVector`'s docstring and the reasoning-trail text now spell out what each tier actually means (tier 4 = "one unconfirmed signal, not a verdict", not "4× more dangerous than tier 1").
- **`pipeline.py` now persists CL-AFPE's own verdict into every alert record** (`alert_payload["fp_verdict"]` — verdict/confidence/stage). This field didn't exist before 8.0; without it there was no data for the self-calibration pass below to learn from at all.

### 🤖 Autonomous Self-Calibration (new)

- **The false-positive engine now calibrates its own suppression threshold from real evidence**, both global and per-device, with zero human involvement required. Full mechanics in [USER_MANUAL.md §2](USER_MANUAL.md#-autonomous-self-calibration--the-override-layer) and [Documentation/ARGUS_ARCHITECTURE.md §5](ARGUS_ARCHITECTURE.md#5-autotuning). Summary: needs ≥5 pooled (or ≥3 per-device) confirmed false positives, only ever lowers the threshold, refuses outright on any ambiguous overlap with never-corrected alerts, has a hard floor.
- **A new, layered config-override system replaces "the LLM edits `config.yaml` directly"** (an earlier, never-fully-working design). `config.py`'s `LiveConfig` now also watches `state/config_overrides.json` (global autonomous adjustments) and `fp_engine.py` owns `state/device_fp_profiles.json` (per-device adjustments) — both layer on top of the hand-authored `config.yaml` baseline at read time, both are watched live (~5s), and **neither is ever written to `config.yaml` itself.** Deleting a key from either file instantly reverts to the `config.yaml` value.
- **`ollama_soc.py`'s LLM-validated corrections are now a first-class, human-independent evidence source.** `fp_engine.mark_false_positive()` gained a `source` parameter (`"operator"` vs `"llm_validated"`) so the calibration pass can tell a real Telegram tap apart from the batch analyst's own validated correction — or pool both. Previously both were mislabeled identically as `OPERATOR_MARKED_FALSE_POSITIVE`, and the batch analyst's autonomous action wrote to `safe_host_patterns` (a device-*hostname* matcher, not a domain-suppression mechanism — it could never have suppressed anything even before this fix, an independent bug found while tracing the mislabeling).
- **Two independent retrain triggers now both run calibration.** `fp_engine.py` has its own internal 7-day in-process retrain thread, separate from the scheduler's standalone daily 3am cron invocation of `train_fp_classifier.py` — both call the same `train_and_export_onnx()`, but only the cron path was also calling the new calibration function. Fixed so both paths run calibration after their retrain step, regardless of whether the retrain itself succeeded.

### 🚫 Ollama Resource Usage

- **Diagnosed a resource crisis, not just a bug.** A live `curl` to the production Ollama server's `/api/generate` endpoint measured **849 seconds** of `total_duration` for a trivial "say hello" prompt, while the model's own reported `load_duration` + `eval_duration` summed to only ~13 seconds — the other ~836 seconds was pure CPU-contention queueing under real load (300%+ CPU observed). This explained three days of `ollama_soc.py` producing empty reports with zero successful analyses ever recorded — a symptom that had been invisible because of the logging bug below.
- **`ollama_soc.py` rewritten around dedup, caching, and a hard cap.** Alerts are grouped by `device + target + signature` before any LLM call — a single pattern that fired 50 times costs one call, not 50. Verdicts are cached for 7 days (`ollama_cache_ttl_seconds`); fresh calls per run are hard-capped at 5 (`ollama_max_queries_per_run`), with anything beyond the cap deferred to the next run, prioritized by which pattern repeated most. Also now skips alerts CL-AFPE already suppressed cheaply, spending the LLM only on alerts that genuinely needed a judgment call.
- **Fixed `ollama_soc.py` re-analyzing its own prior output.** It read the last-24h alert window with no `type` filter, meaning its own `ollama_transparency` log entries (appended to the same `alerts.json` it reads from) would be re-ingested and re-queried on the next run. Now explicitly filters to `type=="ids_alert"`.
- **A second, real-time, unthrottled Ollama pathway removed entirely.** `intelligence/ollama_analyzer.py` was instantiated at boot (spinning up a background thread + queue) but its only method, `.analyze()`, was never actually called from anywhere — the one call site in `pipeline.py` was commented out. Left in place, it would have duplicated `ollama_soc.py`'s now-carefully-throttled responsibility via a completely unthrottled path if ever re-enabled. Removed, along with the now-orphaned `ollama_api_key` config key it alone consumed.

### 🔍 Scheduler & Observability Gaps

- **Fixed the scheduler's own output going to `/dev/null`.** `main.py` piped the `scheduler.py` subprocess's stdout/stderr to `DEVNULL` — and since `scheduler.py` launches every scheduled job (`ollama_soc.py`, `retro_hunter.py`, `top_domains_report.py`, `train_fp_classifier.py`) as a child process with no redirect of its own, every one of those scripts' log output was unrecoverable too. There was already a documented precedent for this exact fix two sections above in the same file (the FastAPI subprocess got a real log file); it just never reached the scheduler. Now redirected to `state/scheduler.log`.
- **`retro_hunter.py`'s findings had no durable record or real-time alert** — its only output was `LOGGER.critical()`, which the bug above was silently swallowing. A genuine zero-day retroactive match would have produced nothing an operator could ever see. Matches now append to `state/retro_hunt_findings.jsonl` (kept deliberately separate from `alerts.json` — a retro-hunt match has no live device state/features, and forcing it into that schema risked either crashing feature extraction or being silently misinterpreted by the training pipeline) and send a real-time Telegram alert.
- **Fixed a dead/wrong fallback path in `retro_hunter.py`.** Its default `alert_json_path` fallback (`/app/state/alerts_stream.jsonl`) was a leftover from an earlier Docker-based layout this project no longer uses, pointing at a filename the project's own internal engineering guidelines explicitly say must never be referenced. Dead in practice (the real config always resolved correctly) but a real trap if `alert_json_path` were ever briefly unset.

### 🧹 Dead Code Removal

- **`mitigation/scoring.py`** (418 lines) — the legacy risk-scoring engine, confirmed still dead (zero real imports anywhere) after its logic was fully ported into `threat_signals.py`/`hypotheses/engine.py` in an earlier release but the original file was never deleted.
- **`intelligence/ollama_analyzer.py`** — see "Ollama Resource Usage" above.
- **`ollama_api_key` / `OLLAMA_API_KEY`** — orphaned by the above; `ollama_soc.py`, the sole remaining Ollama consumer, sends no auth header.
- **`ruamel.yaml` dependency** — existed only for `ollama_soc.py`'s old `save_config_key()` (comment-preserving writes to `safe_host_patterns`), itself removed as part of the mislabeling fix above (that write target was always wrong regardless — see "Autonomous Self-Calibration"). Nothing in the codebase writes to `config.yaml` at runtime anymore.

### ⚙️ Portability

- **`config.py`'s production config loader was missing explicit UTF-8 encoding** on both read and write of `config.yaml` — the one inconsistent reader; its sibling scripts (`scheduler.py`, `ollama_soc.py`) already specified it correctly. Would silently break config reload under any non-UTF-8-locale deployment (not just the Windows dev environment this was first caught on) — `config.yaml`'s comments are full of UTF-8 emoji and em-dashes. Fixed both directions.

## [v7.0.1] - 2026-08-17

This release closes out a full end-to-end audit of the configuration system and the background job scheduler. Nothing in the detection math changed — this is a reliability, transparency, and maintainability pass: two silent scheduling bugs are fixed, every configuration key was individually verified against the code that reads it, and the entire configuration file was migrated from `config.json` to a documented, categorized `config.yaml`.

### 🐛 Scheduler Fixes (Phase 7)

- **Fixed `retro_hunter` never actually running.** `scripts/scheduler.py` looked up each scheduled job's script filename using the job's config key directly (`retro_hunter` → `retro_hunter.py`), but the real script is invoked differently, so the cron entry silently matched nothing and the job never fired — with no error, no log line, nothing. Added an explicit `script:` override field to the job definition (see `scheduled_jobs.scheduler.retro_hunter.script: retro_hunter.py` in the new `config.yaml`) and made the scheduler prefer it over the filename-guessing default. Historical threat-intel re-scans are now confirmed running on schedule.
- **Fixed `ollama_transparency` / `ollama_soc` training-data contamination.** The batch LLM analyst job was reading from the same alert stream file it writes its own derived annotations back into, which meant each run's output was partially re-ingested as if it were new evidence on the next run — a slow feedback loop that could bias Brain 3's reasoning over time. The read path and the write path are now backed by clearly separated files, and a regression test (`tests/test_phase7_scheduling.py`) locks in both this fix and the `retro_hunter` fix above.

### 🔍 Full Configuration Audit

Every single key previously read via `config.get(...)` anywhere in the codebase was cross-checked one-by-one against `config.json`, and every key in `config.json` was cross-checked against the code that was supposed to read it. This surfaced several issues that had been silently accumulating:

- **Discovered the `scheduler` block was effectively undocumented and partially unwired.** The cron definitions driving `ollama_soc`, `retro_hunter`, and `top_domains_report` existed in code defaults but were never clearly exposed as first-class, documented configuration — contributing to the `retro_hunter` bug above going unnoticed.
- **Removed 5 dead configuration keys** that are no longer read anywhere in the code: `scheduled_tasks` (superseded by the `scheduler` block), `geofencing_mode`, `geofencing_time_policies` (geofencing has always been blocklist-only in the actual implementation — no allowlist or time-policy logic exists), `autotune_min_risk_threshold`, and `layer2_spoofing_detection_enabled` (Layer-2 spoofing detection is unconditional in the code — it was never actually gated by this flag, so the key was pure dead weight).
- **Added 12 configuration keys** that code was already reading via `config.get(key, <hardcoded default>)` but which were never listed anywhere for operators to discover or override: `env_file`, `home_subnets`, `identity_reidentify_enabled`, `identity_reidentify_min_confidence`, `identity_reidentify_window_seconds`, `simulation_mode`, `router_hosts_url`, `router_hosts_timeout_seconds`, `router_webhook_timeout_seconds`, `pihole_api_timeout_seconds`, `suspicious_escalation_seconds`, and the `fp_revoke_notifications_enabled` / `fp_revoke_action_ttl_seconds` / `fp_operator_feedback_ttl_seconds` trio.
- **Fixed a broken `geoip_db` / `geoip_asn_db` default path.** The shipped default (`../geoiop/GeoLite2-City.mmdb`) pointed one directory *above* the repo root, into a directory name that was itself misspelled (`geoiop`). Since `GeoIPEngine` silently sets `self.reader = None` and logs a single startup line when the `.mmdb` file fails to load, this meant GeoIP telemetry — and **geofencing enforcement, which depends entirely on GeoIP resolving successfully** — could be silently inert on a fresh install with nobody the wiser. Corrected to `models/GeoLite2-City.mmdb` / `models/GeoLite2-ASN.mmdb`, and the new docs call this dependency out explicitly.
- **Removed a duplicate `fastapi_port` definition** that existed in two places in the old config with no code-level guarantee that both stayed in sync.
- **Enforced the mandated directory layout.** `src/`, `state/`, `models/`, `config.yaml`, `alerts.json`, `.env`, `reports/`, and `tests/` are now all verified as siblings directly under the repo root, matching what `config.py`'s relative-path resolution actually assumes at runtime.
- **Relocated the test suite.** All 9 `test_phaseN_*.py` files (`test_phase0_fixes.py` through `test_phase7_scheduling.py`, covering fixes 0 through 7) were moved out of `src/` into a new top-level `tests/` directory, with `sys.path` bootstrapping added to each so they resolve `src` imports correctly from their new location. 151/151 checks pass across all 9 files.

### 🎯 False-Positive Engine: Live Threshold Tuning

- **`fp_lgbm_threshold`, `fp_embed_similarity_threshold`, `fp_combined_suppress_threshold`, and `fp_combined_uncertain_threshold` are now genuinely live-tunable.** These four thresholds govern Stage 2 (LightGBM) and Stage 3 (FastEmbed) of the CL-AFPE pipeline in `intelligence/fp_engine.py`. Previously they existed as config keys but several code paths read them once at object construction time rather than freshly on every alert evaluation, so editing them at runtime had no effect until a full service restart — despite living in what operators would reasonably assume was the "live-reload" part of the config. All four are now read via `self.config.get(...)` at evaluation time, confirmed by direct inspection of the evaluation call path, and are annotated `[LIVE]` in the new `config.yaml`.

### ⚙️ Configuration System: Migrated `config.json` → `config.yaml`

The single biggest change in this release. The old `config.json` had grown into a flat, hard-to-audit file split only by a rigid `static_requires_restart` / `dynamic_live_reload` top-level schema that forced every new key into one of two buckets regardless of what it actually configured. It's been replaced entirely by a categorized, heavily-commented `config.yaml`:

- **13 logical categories** replace the old 2-bucket split: `service_ports`, `paths`, `network_and_devices`, `detection_engine`, `false_positive_engine`, `device_identity`, `geofencing`, `threat_intel_and_ai`, `ips_mitigation`, `pihole_integration`, `fritzbox_router`, `telegram`, and `scheduled_jobs`. Keys are grouped by *what they control*, not by restart behavior.
- **Restart-vs-live behavior is now a per-key `[LIVE]` / `[RESTART]` annotation** in the comment above each key, instead of being encoded in which top-level section the key happened to live in. This is a documentation change only — the actual enforcement mechanism (`config.py`'s `_STATIC_KEYS` set, matched by key name) is unchanged and was verified to still correctly gate every key regardless of its new category.
- **`config.py`'s loader is now category-agnostic.** Instead of hardcoding the two old section names, `_load()` now flattens *any* top-level YAML mapping whose name doesn't start with `_` or `#` into one flat runtime namespace. This means the 13 categories above are a purely organizational/documentation convenience for operators — adding a 14th category in the future requires zero code changes.
- **Secrets are fully out of the file.** API keys, tokens, and passwords (`TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `OTX_API_KEY`, `ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY`, `PIHOLE_API_PASSWORD`, `PIHOLE_API_URL`, `FRITZ_USER`, `FRITZ_PASS`, `API_SECRET_TOKEN`, `ROUTER_WEBHOOK_URL`, `IDS_IPS_PIHOLE_ENABLED`, `IDS_IPS_ROUTER_ENABLED`, `IDS_IPS_TARPIT_ENABLED`, `OLLAMA_API_KEY`) live exclusively in `.env` (path configurable via the new `paths.env_file` key) and are applied on every reload via `config.py`'s `apply_env_overrides()`. They were previously scattered directly in `config.json` in plaintext next to non-sensitive settings.
- **`scripts/scheduler.py` and `scripts/ollama_soc.py` updated for YAML.** Both scripts deliberately avoid booting the full `config.py` singleton (they're short-lived subprocess jobs and don't need the whole engine spinning up just to read a cron string), so each has always maintained its own lightweight `load_config()`. Both were updated to parse YAML and mirror `config.py`'s new category-flattening logic.
- **Found and fixed a comment-loss bug in `ollama_soc.py`'s self-healing write path.** `save_config_key()` is what Brain 3 calls when it autonomously adds a newly-learned benign domain to `network_and_devices.safe_host_patterns`. Because this needs to preserve every human-written comment in `config.yaml` on every write (not just the value being changed), it uses `ruamel.yaml`'s round-trip mode rather than plain `pyyaml`. Testing surfaced an edge case: `ruamel` attaches a comment that sits between the end of a list and the following key to that list's *last index* — so when the list's length changes, the comment can end up silently orphaned or attached to the wrong line. The fix pops the comment from its old index, mutates the list in place via slice-assignment (preserving `ruamel`'s object identity tracking), and re-attaches the comment at the new last index. Covered by `tests/test_phase6_fp_selfheal.py`.
- **New dependencies**: `pyyaml>=6.0` (used by `config.py`, `scripts/scheduler.py`, and `scripts/ollama_soc.py` for standard read paths) and `ruamel.yaml>=0.18` (used exclusively by `ollama_soc.py`'s comment-preserving write path). Both are now pinned in `requirements.txt` — a plain `pip install -r requirements.txt` picks them up automatically.

## [Unreleased] - 2026-08-13

### 📊 Grafana Observability & UI Overhaul
- Completely refactored and consolidated 5 legacy Grafana dashboards into 4 streamlined modules (`1_main_overview`, `2_threat_landscape`, `3_device_deep_dive`, `4_system_health`), backing up legacy dashboards to `dashboard_backup/`.
- Fixed Loki log querying syntax and UID alignment across all Grafana panels for seamless drill-down alerting.
- Added comprehensive Prometheus telemetry panels tracking CPU, Memory, Pipeline Latency, and Zeek processing metrics.

### 🛡️ False Positive Engine & Telegram SecOps
- Fixed critical `Trust Cache` poisoning bug where raw IP connections without a domain caused the Telegram bot to generate a broken `immunize:unknown` payload.
- Added a hard guard clause in `fp_engine.py` rejecting `"unknown"`, `"null"`, and empty strings from being permanently immunized.
- Increased the Ollama API timeout from 5.0 to 30.0 seconds to prevent LLaMA 3.1 AI summaries from silently failing in Telegram.

### ⚙️ System Configuration & Performance
- Silenced aggressive scikit-learn and joblib `UserWarning` Loky thread-worker spam in `journalctl` by enforcing a global `PYTHONWARNINGS="ignore"` policy.
- Officially added integration support for internal Docker `Cowrie` Honeypots via `config.json`'s `honeypot_ips` array. *(As of v7.0.0, this key lives in `config.yaml`'s `network_and_devices` category.)*
- Updated `README.md` and `USER_MANUAL.md` with sections detailing the ultra-optimized, asynchronous, multi-threaded architecture explicitly designed for low-spec servers (e.g., Raspberry Pi).

## [Unreleased] - 2026-08-11

### 🧩 Stability & Security Hotfixes
- Fixed webhook auth behavior to reject remote unauthenticated requests when `fritz_api_token` is unset (loopback IPC remains trusted).
- Fixed hypothesis engine score carry-over by resetting per-evaluation state.
- Fixed ML learning order in pipeline to avoid pre-verdict poisoning in alert paths.
- Fixed retro hunter domain extraction for JSONL alert payload schema and config-resolved stream paths.
- Added Prometheus no-op fallback in `metrics.py` for constrained/offline environments.
- Fixed DNS zero-feature schema consistency (`dns_txt_null_ratio`, `suspicious_tld_ratio`, `beaconing_c2_1h`).
- Fixed regression test compatibility for trainer/FP-engine API drift.

## [Unreleased] - 2026-08-09

### 🔎 Operator Visibility & Mitigation Hardening
- Added explicit evidence-verification indicators to threat alerts and Telegram notifications for partially supported detections.
- Hardened Layer-2 tarpit handling so existing targets are refreshed with later MAC identification and unknown-MAC cases are logged clearly.
- Persisted Pi-hole block state across restarts with explicit active status metadata for better recovery and operator visibility.
- Preserved IP-first device identity while continuing to update MAC and hostname information from newer Zeek and ARP telemetry.
- Improved resilience around Pi-hole API failures so mitigation continues to proceed for router isolation and tarpit containment even when the Pi-hole endpoint is temporarily unreachable.

## [v5.0.0] - 2026-08-08

### 🚀 Major Architecture Overhaul: Hypothesis & Evidence Engine (HEE)
- **Completely Rebuilt Decision Engine** (`pipeline.py`, `ai_soc.py`): Transitioned from a flat arithmetic risk score to a deterministic, graph-based Evidence Store. The system now collects behavioral facts (e.g. `repeated_parent_domain`, `high_entropy`, `dns_tunneling`) and evaluates them against strict hypotheses (e.g. `DNS_TUNNELING`, `BEACONING`, `EXFIL`).
- **Local AI SOC Analyst (Ollama Integration)**: Integrated `llama3.1` running natively on `localhost:11434`. The LLM receives full JSON context for each alert and operates as an autonomous Tier 2 SOC Analyst to evaluate the evidence graph.
- **Deterministic AI Validator Guardrail**: Introduced a deterministic reputation guardrail. If an IP or domain holds a known Tier 5 malicious reputation from Threat Intel, the system will aggressively reject the LLM's opinion if it hallucinates a "BENIGN" verdict.
- **Telegram AI Summarization**: The Telegram alert dispatcher now offloads alert payloads to Ollama in a background thread to generate 1-sentence executive summaries of the threat, appended directly to Telegram messages.
- **Grafana Triage Hub Upgrades**: Overhauled the Grafana dashboards to replace the deprecated 0-10 Risk Score with the new `home_ids_threat_confidence` emitted by the HEE engine.

### 🧠 Machine Learning & Temporal Context
- **Temporal/Diurnal Awareness**: Injected `time_sin` and `time_cos` features into the `LightGBM` / `IsolationForest` ML pipelines to give the models contextual awareness of the time of day, vastly reducing false positive anomalies during non-standard hours.
- **Graceful Dimensionality Upgrades**: Upgraded the device state schemas to dynamically invalidate legacy 9-feature models and rebuild the new 11-feature temporal baselines without crashing.

### 🔧 Bug Fixes & Optimizations
- **Fixed StateManager Evidence Leak**: Ensured `self.evidence_store.clear_device(dev_id)` is explicitly called when stale devices are pruned from the pipeline, permanently fixing memory accumulation.
- **Hardened System Polling Loop**: Hardcoded strict `time.sleep()` blocking across all internal `while True` polling loops (Zeek, API requests, Alert Managers) to prevent catastrophic infinite-loop log spam that could previously overwhelm `rsyslogd`.

## [v4.0.8] - 2026-08-06

### 🔴 Critical Bug Fixes
- **Fixed `NameError`-class bug: `is_poisoned` used before definition** (`pipeline.py`): `is_poisoned` was
  referenced on line 309 of the ML training guard `if dev_id in all_active_ids and not is_poisoned` before
  being assigned on line 338. On the first device in every 2s cycle this caused a `NameError`; on subsequent
  devices it used a stale value from the previous loop iteration, silently poisoning ML training.
  `is_poisoned = state.is_poisoned(risk)` is now computed immediately after `risk_details` is available.
- **Fixed `UnboundLocalError` for `webhook_log_file`** (`main.py`): When `ips_router_enabled = false`
  (the default config), `webhook_log_file` was never assigned. `shutdown_handler()` referenced it
  unconditionally, raising `UnboundLocalError`. Initialized to `None` before the conditional block.

### 🟡 Performance & Reliability Fixes
- **Reduced `_global_lock` scope for expensive I/O** (`pipeline.py`): Per-device processing was restructured
  into 4 phases. ThreatIntel lookups, AbuseIPDB, and VirusTotal queries now run in Phase 2/3 **outside** the
  global device lock. The lock is now held only for quick state reads (Phase 1) and risk/ML writes (Phase 4),
  eliminating HTTP round-trip latency from the critical lock window.
- **Fixed `rolling.domains` unbounded accumulation** (`pipeline.py`, `state.py`): The per-device DNS domain
  `Counter` grew unboundedly across the device's lifetime. Now pruned each cycle via `domain_timestamps`
  entries older than `window_seconds`. `rolling.blocked` and `rolling.nxdomain` are now re-derived from
  the bounded `events` deque on each cycle so they can't inflate beyond the window.
- **Switched `AlertJSONWriter` to O(1) JSONL append mode** (`alerts.py`): Previously `write()` read the
  entire alert JSON array, parsed it, appended, and rewrote it on every alert (O(N) per write). Now uses
  `file.open("a")` append mode with one compact JSON line per alert. Existing JSON array files are
  automatically converted to JSONL on first startup.
- **Added O(1) MAC update via reverse IP index** (`state_guard.py`): `update_device_mac()` previously
  performed an O(N) linear scan across all device states for every Zeek ARP event. A `_ip_to_device_id`
  reverse index is now maintained on all device create/register/migrate operations, making MAC binding O(1).
- **Fixed HTTP call under lock in `release_device()`** (`ips.py`): `_unisolate_device_router()` was called
  while holding `self._lock`, causing the Fritz!Box HTTP round-trip (up to 10s timeout) to block all
  lock-protected operations. Restructured into: Phase 1 (collect targets under lock) → Phase 2 (HTTP outside
  lock).

### 🔒 Security Fixes
- **Telegram command authentication** (`alerts.py`): `/unblock`, `/release`, `/release_all` and inline
  button callbacks can now be restricted to authorized sender IDs via `telegram_allowed_chat_ids` in
  `config.json`. Default is empty list (allow all) for backward compatibility.
- **Uvicorn CWD-independent startup** (`main.py`): Changed module import from `src.middleware.fritz_webhook:app`
  to `middleware.fritz_webhook:app` with `--app-dir <src_dir>` flag so the daemon starts correctly regardless
  of the process working directory (e.g., systemd unit with a custom `WorkingDirectory`).

### 🟢 Minor Fixes & Configuration
- **Pi-hole API path is now configurable** (`ips.py`, `config.py`): Hardcoded `/api/v2/domains` replaced
  with `config.get("pihole_api_path", "/api/v2/domains")`. Set `pihole_api_path` in `config.json` to use
  Pi-hole v5 (`/api/dns/blacklist`) or a custom path.
- **`release_all_devices()` uses MAC as canonical key** (`ips.py`): Fixed edge case where two devices with
  identical hostnames would only generate one release call. Now uses MAC address as primary identifier,
  falling back to IP, then hostname.
- **`fastapi_port` and `telegram_allowed_chat_ids` added to `DEFAULT_CONFIG`** (`config.py`): Both keys
  were previously used in code without being documented in the defaults dict.
- **`router_isolated_devices` and `operator_released_devices` added to `_ips_state` defaults** (`state_guard.py`):
  Prevents `KeyError` if code accesses these keys on a fresh install before the first isolation event.
- **Honeypot IP sourced from `config["honeypot_ips"]`** (`scoring.py`, `pipeline.py`): Alert detail message
  previously hardcoded `192.168.1.200`. Now reads from `config.json["honeypot_ips"]` list, injected into
  the feature dict before scoring.
- **`_bot_updates_worker` responsive shutdown** (`alerts.py`): Replaced `time.sleep(5)` with
  `threading.Event.wait()`. Thread now stops within ≤1 second of `stop()` being called, instead of waiting
  up to 25 seconds for the Telegram long-poll to time out.
- **`get_ips_state()` TOCTOU warning added** (`state_guard.py`): Docstring now clearly warns that inner
  dicts are mutable references and directs callers to `update_ips_state_atomic()` for read-modify-write.

## [v4.0.7] - 2026-08-06

### 🔒 Security & Local Loopback IPC Trust
- **Local Loopback IPC Authentication**: Updated `verify_token` in `src/middleware/fritz_webhook.py` to automatically trust loopback requests (`127.0.0.1`, `::1`, `localhost`). This allows local CLI utilities (like `release_device.py`) to execute live daemon memory releases seamlessly without needing `API_SECRET_TOKEN` exported in the user's interactive shell profile.

## [v4.0.6] - 2026-08-06

### 🐛 Bug Fixes & Diagnostics
- **Enhanced CLI IPC Fallback Telemetry**: Updated `src/release_device.py` to output explicit exception details (`ConnectionRefusedError`, HTTP status codes) when live daemon IPC is offline or unconfigured, making CLI diagnostics transparent.

## [v4.0.5] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Unauthenticated Local IPC Support**: Updated `verify_token` in `src/middleware/fritz_webhook.py` to allow local IPC release calls (`POST /api/ipc/release`) when `fritz_api_token` is unconfigured (`""`) without throwing HTTP 500 configuration errors.

## [v4.0.4] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Telegram Alert Plain Text Fallback**: Added automatic plain text fallback in `AlertManager._dispatch_worker()` if Telegram rejects formatted alert messages with HTTP 400 (`can't parse entities`).
- **Telegram Inline Button Read Timeout Fix**: Increased local IPC timeout in `_handle_telegram_callback()` from `3.0s` to `10.0s` to prevent `HTTPConnectionPool Read timed out` exceptions when operators tap Telegram inline action buttons.

## [v4.0.3] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Fixed `NameError: name 'alert_threshold' is not defined`**: Defined `alert_threshold` float evaluation in `IPSMitigator.mitigate()` in `src/mitigation/ips.py` from `config.json` before checking Pi-hole domain block threshold conditions.

## [v4.0.2] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Fixed `NameError: name 'pihole_enabled' is not defined`**: Defined `pihole_enabled` boolean evaluation in `IPSMitigator.mitigate()` in `src/mitigation/ips.py` before checking Pi-hole domain block threshold conditions.
- **Regression Test Alignment**: Updated `test_09` in `src/test/test_ids_regression.py` to match the 5.5 risk score threshold for baseline poisoning freeze.

## [v4.0.1] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Graceful `tldextract` Fallback**: Updated `etld1()` in `src/utils.py` with try/except fallback logic so system execution operates smoothly without throwing `ModuleNotFoundError` if `tldextract` is missing from system Python.
- **Immediate Pi-hole DNS Sinkholing**: Ensured Pi-hole domain sinkholing executes 100% immediately upon threat detection; interactive Telegram approval (`interactive_blocking_enabled`) applies strictly to Layer-2/3 Hardware Isolation (Fritz!Box WAN drop and Scapy ARP/NDP tarpit).
- **Explicit HITL Startup Log Banner**: Added startup log banner in `IPSMitigator` notifying operators of active HITL vs Auto-block configuration on boot.
- **Repository Privacy & Clean Git Tracking**: Added root `.gitignore` excluding runtime logs, state snapshots, and compiled bytecode.

## [v4.0.0] - 2026-08-06

### 🚀 Major Features & Architectural Redesign

#### 1. Interactive Telegram Human-in-the-Loop (HITL) Mode
- **Configurable HITL**: Added `interactive_blocking_enabled: true/false` option in `config.py`.
- **Immediate DNS Sinkholing**: Pi-hole domain blocking remains 100% immediate and autonomous upon threat detection.
- **Interactive Hardware Isolation**: When `interactive_blocking_enabled: true` is set, Layer-2/3 Hardware Isolation (Fritz!Box WAN Drop and Scapy Layer-2 ARP/NDP Tarpit) is queued for Telegram operator approval.
- **Inline Action Buttons**: Telegram alerts feature live inline keyboard buttons:
  - `[ 🔒 Approve Hardware Isolation ]`
  - `[ 🔓 Release Device ]`
  - `[ 🛡️ Immunize FP Domain ]`
- **Telegram Bot Command Listener**: Asynchronous background worker (`_bot_updates_worker`) handles `/unblock <target>`, `/release <target>`, `/release_all`, and `/status` commands directly via Telegram chat.

#### 2. Process IPC & State Synchronization Architecture
- **FastAPI Local IPC Server**: Added local IPC endpoint `POST /api/ipc/release` on port 8010.
- **Split-Brain Prevention**: Updated CLI tool `release_device.py` to communicate directly with the running `soc.service` process memory over local IPC, preventing stale memory overwrites.
- **Full Scope Unblocking**: `release_device()` releases Layer-2 ARP tarpits, Fritz!Box WAN drops, and associated Pi-hole blocked domains simultaneously.

#### 3. 1-Hour Operator Release Cooldown & Lateral Movement Override
- **1-Hour Release Cooldown**: Releasing a device registers a 3600-second cooldown period, preventing immediate re-blocking on decaying background metrics.
- **Hard Safety Override**: If internal subnet port scanning or lateral movement (`zeek_lateral_moves > 0`) is detected during cooldown, the cooldown is **instantly bypassed**, hardware containment is re-enforced, and a high-priority alert is logged.

#### 4. Multi-Threat 9-Feature Matrix Alignment & Model Validation
- **Unified 9-Feature Vector**: Expanded anomaly feature vectors across `DeviceMLEngine` and `GlobalMLEngine` to include `zeek_lateral_moves`, `zeek_s0_rej_count`, and `zeek_app_protocol_weight`.
- **Automated Retraining & Hot-Reload**: Created `src/scripts/train_fp_classifier.py` and weekly daemon `_weekly_retrain_loop()` in `fp_engine.py` to auto-retrain and hot-reload `models/fp_classifier.onnx` on the full 9-feature matrix.
- **Dynamic ONNX Input Shape Guard**: Updated `_stage2_lgbm()` in `fp_engine.py` to dynamically inspect ONNX input tensor signatures at runtime (`[None, 6]` vs `[None, 9]`).

#### 5. Real-Time Prometheus & Grafana Metrics Synchronization
- **Real-Time Garbage Collection**: Added `garbage_collect_ips_metrics()` to the pipeline execution loop in `pipeline.py` to synchronize active gauge labels with live state.
- **Clean Label Removal**: Updated `unblock_domain()`, `release_device()`, and `release_all_devices()` to call `.set(0.0)` and `.remove()` on Prometheus metrics (`ips_tarpit_active`, `ips_router_isolated_active`, `ips_active_blocks_gauge`).

#### 6. Core Stability & Code Quality Fixes
- **Non-Blocking IsolationForest Training**: Replaced synchronous `.fit()` in `ml_engine.py` with background daemon threads (`_fit_worker`) and atomic model swapping under `_fit_lock`.
- **Atomic State Guard**: Added `update_ips_state_atomic()` to eliminate TOCTOU disk state race conditions.
- **LRU Cache Concurrency**: Wrapped `_ip_cache` in `identity.py` with thread locks and converted to `OrderedDict` with LRU eviction.
- **Clean Shutdown Handling**: Added explicit file handle closure (`webhook_log_file.close()`) in `main.py` signal handler to eliminate exit `ResourceWarning`.
