# v13 Full Architecture Shift — Legacy-Reliance Audit & Complete Migration Plan

**Living document.** Companion to [`V13_ARCHITECTURE_DEPENDENCY_MAP.md`](V13_ARCHITECTURE_DEPENDENCY_MAP.md)
(what's built) and [`V13_REMAINING_WORK.md`](V13_REMAINING_WORK.md) (the original,
now-mostly-resolved scope-cut ledger). This file answers two questions the other two
don't: **(1) what in the live codebase today still runs on pre-v13 logic/state despite
the cutover, verified against real code on 2026-09-07**, and **(2) what a full shift —
accepting none of the original scope cuts — actually requires**, as a trackable
checklist. When an item here ships, move its outcome into the dependency map and check
it off here (don't delete the row — the "why it was cut" reasoning stays useful).

Companion artifact (kept in sync with this file's Part 3/4):
`https://claude.ai/code/artifact/4e055533-481d-461d-9e63-c47ef7dbdf90`

**Versioning boundary (set 2026-09-07)**: Workstreams P0/1/2 close out **v13** as a
milestone. Workstream 3 onward, plus the net-new items, are tracked as **Release
14** — a fresh version, not a renumbering of the same list.

**Standing design constraint, applies to every item below**: target hardware for
this codebase's eventual deployment is a **Raspberry Pi, 8GB RAM minimum**, not
`.94`'s current 12GB x86 box. Every implementation decision from here on is
evaluated against that, specifically: no unbounded in-memory growth, no unchecked
disk growth (a retention/rotation policy from day one, not bolted on after an
incident — see A14's 43,342-row duplication incident, the exact failure mode this
guards against), async/non-blocking I/O wherever the work is genuinely I/O-bound,
and low latency on the live 2s decision cycle as a first-class requirement.

---

## Part 1 — Audit: what still runs on pre-v13 logic (verified, not assumed)

Verified by direct grep/read against `src/` on 2026-09-07, cross-checked against two
independent Explore-agent passes. All line numbers current as of that date.

### 1.1 Fully v1, with no v13 counterpart at all
v13 was never scoped to replace these — they're listed here so "full architecture
shift" has an honest boundary, not because they're bugs:

- Actuation/mitigation — `src/mitigation/ips.py` (`IPSMitigator`: Pi-hole/router/tarpit actions)
- Alerting — `src/mitigation/alerts.py` (`AlertManager`/`AlertJSONWriter`), `alerts.json` is still the only real alert sink
- Threat intel & GeoIP — `src/intelligence/threat_intel.py`, `src/intelligence/geoip.py`
- ML anomaly engine — `src/intelligence/ml_engine.py` (`MLRegistry`)
- Incident tracking — `src/core/incident_tracker.py`
- The entire feature-extraction front end — `src/extractors/zeek_features.py`, `dns_features.py`, `fritzbox_capture.py`

### 1.2 Nominally "v13" but mostly riding on v1 underneath
- **Identity** — `LiveIdentityManager` (`src/v13/identity/live_manager.py`) subclasses
  `DeviceIdentityManager` and overrides only `resolve_device_id()` and
  `_merge_orphan_if_fragmented()`. Everything else — Fritz!Box enrichment,
  `device_type` inference, per-row orchestration — is unmodified v1.
- **Device state** — `src/core/state_guard.py`'s `StateManager`/`ids_state.json` is
  still the actual live source of truth for MAC↔IP bindings and `known_ips`. The
  graph's `devices`/`device_metadata` tables only *mirror* merges into it
  (A29) — they don't own identity independently.
- **CL-AFPE** — `AutonomousFPEngine` (`src/intelligence/fp_engine.py`) is what
  actually suppresses/actuates. v13's `ClAfpeEngine` computes a full real verdict
  every cycle but it's discarded (`core/pipeline.py:1833-1840`) — shadow only.

### 1.3 Vestigial — kept alive, doing nothing under the live default
- `core/decision_engine.py`'s Gap-1/2/3 shadow code (`shadow_changed`/
  `_log_shadow_divergence`, lines 484/500) only executes under `engine: v_current`
  — dead under the real default (`v13`).
- `scripts/shadow_watcher.py` — still scheduled every 5 minutes
  (`config.yaml:754-756`), watching a file (`shadow_decisions.jsonl`) that's stopped
  growing. Its own config comment admits this.
- `mitigation/scoring.py` — confirmed zero importers anywhere outside its own tests.

### 1.4 Two live discrepancies found by this audit (not documented anywhere before)

**A. RESOLVED 2026-09-07 — false alarm.** Verified directly via SSH to `.94`
(`/home/user/myscripts/home-ids/SOC/config.yaml`): all four v13 jobs
(`live_prune`, `live_retro_hunter`, `live_llm_review`, `live_decision_archive`) are
present and `enabled: true`, and `engine: v13` is set (line 863). **This NAS-hosted
repo checkout's own `config.yaml` is NOT authoritative for `.94`'s real config** —
whatever sync mechanism keeps `state/`'s data files current (Unison) apparently
doesn't extend to `config.yaml`. Lesson: always verify `.94`'s live config via SSH
directly, never trust this local copy.
→ tracked as item **P0-1** below, now closed.

**B. The weekly ML retrain writes to a directory the live model loader never reads.**
- `src/scripts/train_fp_classifier.py:990` writes retrained artifacts to
  `state_dir / "models"` → `state/models/fp_classifier.onnx` (confirmed on disk:
  19,538 bytes, Sep 5, with a `.last_retrain` timestamp of Aug 31 — the job is
  genuinely running).
- `src/intelligence/fp_engine.py:2532` and `:2671` load from
  `Path(self.config.get("model_path")).parent`, and `config.yaml`'s `model_path:
  models/ids_model.pkl` (`src/config.py:106`) resolves to the **top-level** project
  `models/` directory — confirmed still holding the stale Aug-25 placeholder
  (4,179 bytes).
- Net effect: **every weekly retrain since this split happened has been silently
  discarded** by live inference. This predates v13 entirely and isn't a scope cut —
  it's a real, currently-active bug, found only because this audit compared the two
  paths directly.
- **Confirmed live on `.94` itself on 2026-09-07** (not just this checkout):
  `state/models/fp_classifier.onnx` = 8148 bytes, today 10:57 (the real current
  retrain); `models/fp_classifier.onnx` = 4179 bytes, Aug 17 (the stale one
  `fp_engine.py` actually loads).
→ tracked as item **P0-2** below, in progress.

---

## Part 2 — `state/` folder: what stays flat, what has a graph analog, what's dead

| File / group | Status | Notes |
|---|---|---|
| `alerts.json`, `autonomous_muted.jsonl`, `confirmed_threat_counts.json`, `fp_sigma_shifts.json`, `local_confirmed_intel.json`, `training_row_exclusions.json`, `reactive_capture/`, `zeek_cursor_*.json`, `ti_cache/` | **Stays flat-file** | No graph equivalent, several by explicit v13 scope-cut (v13 declines to share `local_confirmed_intel.json`; `fp_sigma_shifts.json` never ported). |
| `fp_trust_cache.json` | **Parallel graph copy exists, not yet primary** | v13 already writes an equivalent `trusts` edge (`v13/cl_afpe/engine.py`). Migration only makes sense once CL-AFPE flips off shadow (Part 3, Workstream 3). |
| `device_fp_profiles.json` | **Partially portable, not started** | Only the "trust" concept was ported; per-device threshold-bumping data has no graph home yet — same Workstream 3 dependency. |
| `shadow_decisions.jsonl` | **Superseded, not migrated** | Spiritually replaced by v13's own `decisions` table already. Nothing to "migrate" — the write path and its watcher are just vestigial (Part 1.3). |
| `.unison.*.tmp`, `fritz_webhook.log`, `scheduler.log`, `*.bak*`, `backups/`, `job_health.json`, `ollama_run_stats.json`, `autotune_stats.json`, `feed_health.json` | **Pure infra, leave alone** | Log captures, manual snapshots, Prometheus-relay artifacts. |
| `metrics_dump.txt` | **Dead** | 0 bytes, zero references anywhere. Safe to delete. |
| `state/fastembed_cache/`, `state/models/*`, top-level `state/fp_classifier.onnx` | **Orphaned by the P0-2 bug** | Don't delete `state/models/` until P0-2 is fixed — it currently holds the *only* genuinely up-to-date model. |
| `state_scratch/` | **Dead** | Zero references anywhere in the repo. Safe to delete. |
| v13-only files (`v13_graph.db`, `v13_ingest_cursors/`, `v13_cl_afpe/`, `decision_archive/`, `cl_afpe_divergence_v13.jsonl`, etc.) | **Not present on this checkout** | Consistent with the P0-1 finding — confirm directly on `.94`. |

---

## Part 2a — Pending manual actions on `.94` (blocked by the auto-mode classifier)

Every SSH *write* attempt to `.94` in this session was blocked (2 for 2) — read-only
commands (grep/ls/systemctl status) go through fine, matching the documented
"sometimes blocked" pattern. Run these directly on `.94` (as `user`, in
`/home/user/myscripts/home-ids/SOC`) and confirm when done — none require a
`soc.service` restart to be safe to apply immediately, but the restart is needed
for `fp_engine.py` to actually pick up the corrected model file:

```bash
cd /home/user/myscripts/home-ids/SOC

# 1. Remove the now-dead shadow_watcher scheduler entry (matches the code cleanup
#    already committed — decision_engine.py no longer produces anything for it to watch)
cp config.yaml /tmp/config.yaml.pre-workstream1-cleanup-backup-$(date +%Y%m%d_%H%M%S)
python3 - <<'PYEOF'
path = 'config.yaml'
text = open(path, encoding='utf-8').read()
old_block = '''    # Shadow-mode divergence watcher (Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md) --
    # fires a Telegram alert the moment state/shadow_decisions.jsonl gets a new entry.
    # Temporary: remove this job once the evidence-taxonomy fix is either flipped live or
    # abandoned -- it has nothing to watch once shadow_decisions.jsonl stops being written.
    shadow_watcher:
      enabled: true
      cron: "*/5 * * * *"
'''
new_block = '''    # REMOVED (2026-09-07): shadow_watcher's own experiment was removed from
    # decision_engine.py the same day -- nothing left to watch.
'''
assert old_block in text, "block not found -- config.yaml may have drifted, check manually"
open(path, 'w', encoding='utf-8').write(text.replace(old_block, new_block, 1))
print("done")
PYEOF

# 2. Consolidate the model split (P0-2's fix makes top-level models/ permanent;
#    state/models/ currently holds the genuinely newer retrained file)
cp models/fp_classifier.onnx /tmp/fp_classifier.onnx.pre-p02-backup-$(date +%Y%m%d_%H%M%S)
cp state/models/fp_classifier.onnx models/fp_classifier.onnx
cp state/models/fp_calibration.json models/fp_calibration.json

# 3. Delete confirmed-dead files
rm -f state/metrics_dump.txt
rm -rf state_scratch/

# 4. Add Workstream 2's CL-AFPE flip-monitor config (both pieces, or the monitor has
#    nothing to schedule it and no key to ever flip)
python3 - <<'PYEOF'
path = 'config.yaml'
text = open(path, encoding='utf-8').read()

engine_anchor = "engine: v13\n"
cl_afpe_block = '''
# cl_afpe_engine -- see config.yaml.example's own comment for the full explanation.
# "v_current" (default) = real suppression stays AutonomousFPEngine's; v13's own
# ClAfpeEngine keeps running in shadow. Flipped to "v13" automatically by
# cl_afpe_flip_monitor.py once its own bar clears.
cl_afpe_engine: v_current
'''
assert engine_anchor in text, "engine: v13 line not found -- check manually"
if "cl_afpe_engine:" not in text:
    text = text.replace(engine_anchor, engine_anchor + cl_afpe_block, 1)

scheduler_anchor = '''    live_decision_archive:
      enabled: true
      cron: "0 4 1 * *"
      script: "../v13/ops/live_decision_archive.py"
'''
cl_afpe_job_block = '''
    cl_afpe_flip_monitor:
      enabled: true
      cron: "*/15 * * * *"
      script: "../v13/ops/cl_afpe_flip_monitor.py"
'''
assert scheduler_anchor in text, "live_decision_archive scheduler block not found -- check manually"
if "cl_afpe_flip_monitor:" not in text:
    text = text.replace(scheduler_anchor, scheduler_anchor + cl_afpe_job_block, 1)

open(path, 'w', encoding='utf-8').write(text)
print("done")
PYEOF

# 5. Restart soc.service to activate the model fix + shadow-code removal + Workstream 2
#    wiring (explicit, human-triggered, per the standing rule -- not something to automate)
sudo systemctl restart soc.service
sudo systemctl status soc.service --no-pager
```

After restart, worth a spot-check: `journalctl -u soc.service -n 50 --no-pager` for a
clean startup with no new errors.

## Part 3 — Full shift plan: every scope cut, why it existed, what completing it requires

Format per item: **what**, **why it was cut** (the real original reason, not
"not done yet"), **what full completion requires**, checkbox.

### Workstream 0 — Fix confirmed bugs first (not scope cuts, block trustworthy signal for everything below)

- [x] **P0-1. Confirm v13 ops-job scheduling status directly on `.94`.** DONE
  2026-09-07 — false alarm, all four jobs already enabled + `engine: v13` set on
  the real box. See Part 1.4.A.
- [x] **P0-2. Fix the model-path mismatch** so the weekly retrain actually feeds live
  inference. DONE 2026-09-07: added `AutonomousFPEngine._model_dir()` as the single
  source of truth (both `_load_lgbm_model()`/`_load_calibration()`/the FastEmbed
  cache path AND the weekly retrain call site now call it — previously each side
  independently hardcoded its own default, which is exactly how they drifted).
  `train_and_export_onnx()` now takes an explicit `model_dir` param instead of
  hardcoding `state_dir/"models"`. 4 new tests
  (`tests/test_train_fp_classifier_model_path.py`) prove the reader/writer paths
  match by construction. **Still open**: `state/models/` vs top-level `models/`
  cleanup (folded-in W1-3) and a `.94` restart to activate live — deferred to land
  together, see below.

### Workstream 1 — Retire vestigial code (cleanup, not a cut) — DONE 2026-09-07

- [x] **W1-1.** Remove `mitigation/scoring.py`. Turned out already done in an
  earlier, pre-this-session commit (confirmed via `git log` — the file isn't in
  `HEAD`) — only a stale `__pycache__` bytecode file remained, cleaned up.
- [x] **W1-2.** Removed `core/decision_engine.py`'s entire Gap-1/2/3 shadow
  computation (the `shadow_attack`/`fresh_arp_spoof`/`fresh_geofence`/
  `fresh_confirmed_exploit`/`shadow_state`/`shadow_changed` block and its 4
  return-dict keys, plus the now-unused `_HARD_STOP_FRESHNESS_SECONDS` constant
  and `import time`), `pipeline.py`'s `_log_shadow_divergence()` method and its
  call site, and `scripts/shadow_watcher.py` entirely (removed from git, plus its
  `config.yaml`/`config.yaml.example` scheduler entries). 2 test files
  (`test_phase47_shadow_honeypot_safe_ips.py`, `test_phase54_g6_...py`) asserted
  directly on the removed shadow fields — rewritten to assert the equivalent LIVE
  `state`/`explanation` fields instead (the underlying behavior they guard was
  already flipped live at Phase 64; the shadow comparison itself is what became
  redundant). Verified: both rewritten files pass, `test_phase7_scheduling.py`
  unaffected (never asserted `shadow_watcher` must exist), and all 4 golden-case
  regression files (`test_phase38`/`34`/`42`/`54`) pass clean with zero behavior
  change on the live decision path (this was intentionally read-only cleanup of
  code that only ever ran under the already-inert `engine: v_current` path).
  **Still open**: mirror this same `config.yaml` edit onto `.94`'s real, live
  config — the automated SSH write was blocked by the auto-mode classifier (the
  documented "sometimes blocked" pattern); needs the user to run it directly
  (exact command below) or approve a retry.
- [ ] **W1-3.** `metrics_dump.txt` and `state_scratch/` deletion, and copying
  `.94`'s genuinely current `state/models/fp_classifier.onnx`/`fp_calibration.json`
  (Sep 7, real retrain) over the stale top-level `models/` copy (Aug 17) now that
  P0-2's code fix makes top-level `models/` the permanent target — all confirmed
  safe, all **blocked by the auto-mode classifier on every SSH write attempt to
  `.94`** (2 consecutive blocks, the same "sometimes blocked" pattern
  `feedback_pi_target_and_v13_execution` documents). Consolidated into one pending
  manual-action list for the user (see chat) rather than retried piecemeal.

### Workstream 2 — CL-AFPE: shadow → live (Phase 6f, the biggest remaining cut) — DONE 2026-09-07, awaiting the bar

**Why CL-AFPE stayed a cut this long**: per `V13_REMAINING_WORK.md` Group C, the
original reason was research effort — "per-device threshold bumping... depends on a
whole separate per-device-profile subsystem never researched for v13." That research
is now done (A21-A24: sigma-shift, thresholds, local-intel poisoning guard, and ML
Stage 2/3 all ported and tested) — the remaining gap was purely the live-flip
decision, gated the same way every prior mechanism in this project has been gated.

**Architectural decisions, asked and answered explicitly (2026-09-07)**: (1) flip
bar = volume floor + zero-false-negative veto, **no fixed time floor** (user's
choice, given this box's already-reduced risk tolerance); (2) flip granularity =
**whole engine at once**, matching the `engine: v13` pattern, not a per-mechanism
drip; (3) flip trigger = **fully automatic** once the bar clears, matching the A9
precedent, with a Telegram notification either way.

- [x] **W2-1.** Flip bar defined: **>= 50 real eligible comparisons** in
  `state/cl_afpe_divergence_v13.jsonl` (both sides must have produced a verdict to
  count) **AND zero false-negative-shaped divergences** (v13 says `FALSE_POSITIVE`
  — would silently suppress — on an alert where v-current's real verdict was NOT
  `FALSE_POSITIVE`, i.e. a human actually saw it). 50 is a first-pass judgment call
  (between the retired A10 mechanism's 15-20 for a pure scoring refinement, and Gap
  3 honeypot's 58 for a hard-stop — CL-AFPE controls real suppression, closer to
  the hard-stop end), not empirically tuned, same honesty framing this project's
  own `INDEPENDENCE_FAMILY_MAP` already uses for a similar number.
- [x] **W2-2.** Flip switch built: `src/v13/ops/live_engine.py`'s new
  `evaluate_cl_afpe_live()` (fail-safe adapter, same one-way-dependency/fallback
  shape A13's own `evaluate()` uses — never imports `intelligence.fp_engine`
  directly). `core/pipeline.py`'s `fp_verdict = ...` call site now branches on
  `config.get("cl_afpe_engine", "v_current")`; the shadow comparison
  (`evaluate_cl_afpe_shadow`) only runs on the `v_current` side now, since once
  flipped there's no more real v1 verdict to diff against (same reasoning that
  froze `decision_engine.py`'s own shadow experiment once the main engine
  flipped). New `src/v13/ops/cl_afpe_flip_monitor.py` (15-min scheduled job):
  checks the bar, runs `tests/test_v13_cl_afpe.py` +
  `tests/test_v13_live_cl_afpe_shadow.py` as a hard gate, flips
  `config.yaml`'s `cl_afpe_engine` via the same targeted-text-edit pattern (not a
  YAML round-trip) every prior flip in this project has used, notifies via
  Telegram either way, **never restarts `soc.service`**. New config key
  `cl_afpe_engine: v_current` + the scheduler entry added to
  `config.yaml.example`. Verified: 4 new checks in
  `tests/test_v13_live_cl_afpe_shadow.py` (Section D — return-shape parity with
  `AutonomousFPEngine.evaluate()`, fail-safe fallback with correct params,
  no-fallback re-raise), 33 checks in new
  `tests/test_v13_cl_afpe_flip_monitor.py` (classifier, targeted config edit,
  `check_bar()`'s 4 outcomes, full `run_once()` orchestration with
  Telegram/subprocess mocked including the notification spam-guard, and the same
  AST-level "only one subprocess call, never systemctl" proof the retired
  `gap_monitor.py` established). Full v13 suite + golden-case regression suite
  (`test_v13_cl_afpe`/`test_v13_live_engine`/`test_v13_integration` individually
  re-run) all pass clean.
- [ ] **W2-3.** Once flipped **and confirmed stable**, migrate
  `device_fp_profiles.json`/`fp_sigma_shifts.json`/`fp_trust_cache.json` to be
  genuinely retired (or kept only as an offline audit export) rather than
  dual-written. **Deliberately not done yet** — the flip hasn't actually happened
  (needs 50 real eligible comparisons to accumulate first), and touching v1's
  flat files before the flip is proven safe in production would remove the
  rollback's own data.

**Still open before this can do anything on `.94`**: needs `cl_afpe_engine:
v_current` + the `cl_afpe_flip_monitor` scheduler entry added to `.94`'s real
config.yaml (same SSH-write-blocked situation as Part 2a's other pending items —
folded into that same manual-action list) before the monitor is actually
scheduled and has a key to flip. Until that lands, this is deployed and tested
but inert on `.94` — matching the exact same "built but not yet wired to
production config" state A10's own shadow computation was in for a few hours
after A9, per the dependency map's own precedent for this situation.

### Workstream 3 — Identity/state fully on the graph

**Why this wasn't attempted**: A29 found `GraphStore.merge_device()` had zero
callers *at all* before that session — the fix scope was "wire the one merge-mirror
gap that broke," not "migrate identity off `StateManager` entirely." No prior session
ever scoped the larger migration.

- [ ] **W3-1.** Decide, explicitly with the user (real live-service risk, not a
  unilateral call): does `GraphStore` become the primary MAC/IP-history store with
  `StateManager` as an in-memory cache, or does `ids_state.json` stay authoritative
  permanently because of the 2s-cycle latency requirement? This is an architecture
  decision, not an implementation task — do this before W3-2.
- [ ] **W3-2.** If migrating: make ordinary (non-trust-anchor) device MAC↔IP binding
  route through the graph as the source of truth, with `StateManager` becoming the
  fast-path cache it's synced from — not the other way around as today.

### Workstream 4 — LLM-review completeness (remaining Group D items)

- [ ] **W4-1. Cross-device campaign correlation (`_is_campaign_corroborated`
  equivalent).** Why cut: explicitly deferred pending Phase 6/1a's cross-device work
  landing first (Group D3). That work (A19, `CoordinatedTargetingHypothesis`) is now
  live — this is unblocked, not permanently deferred. Requires: reuse
  `get_devices_targeting()`'s already-proven query pattern from the LLM-review
  script's own read side.
- [ ] **W4-2. GeoIP enrichment for v13's LLM-review report** (flagged as missing by
  the capability-ledger artifact; not yet independently verified against source —
  verify first, then port `ollama_soc.py`'s own `_geo_note()`-equivalent, which
  Phase 7 (A25) already factored out for retro-hunter's use).
- [ ] **W4-3. In-cycle LLM review** (net-new, not a cut — see Part 4).
- [ ] **W4-4. LLM-review local-triage default.** Why cut: `query_triage()`'s own
  accuracy is unvalidated (Group B2, still open) — wiring a `hardware_profile`
  default for a capability nothing calls yet would be speculative. **Sequence
  strictly after B2 is resolved**, not before.

### Workstream 5 — Retro-hunt completeness

- [ ] **W5-1. Per-device job-health breakdown** for `live_retro_hunter.py` (mirrors
  v1's `_count_findings_by_device()` — small, self-contained).
- [ ] **W5-2. The loop-closing `record_confirmed_threat()` + sigma `TUNE_UP` action**
  for a newly-implicated device. Why cut: A25 named this out of Phase 7's approved
  scope explicitly (cross-reference + notification only, not this additional
  mutation). Now unblocked since `ClAfpeEngine` exists — needs an instance threaded
  into `live_retro_hunter.py`.

### Workstream 6 — Suricata evidence pipeline (A6, the one genuinely large cut)

- [ ] **W6-1.** Design and build a v13-native Suricata evidence path. Why cut: not a
  tailable log stream in this deployment at all — Suricata only runs in short batch
  invocations against reactively-captured pcap bursts
  (`extractors/fritzbox_capture.py`'s `ReactiveCaptureDispatcher`); replicating this
  for v13 means replicating the entire burst-trigger/dispatch subsystem, not writing
  a tailer. Treat as its own separately-scoped initiative — don't fold into any
  other workstream above.

---

## Part 4 — Net-new capability: "Now possible, not yet built"

Pulled from the companion artifact's own "Potential" section — these aren't scope
cuts (nothing pre-v13 ever had them), they're direct consequences of the graph
existing that nobody has built yet.

- [ ] **N1. Ad-hoc historical threat-hunting surface.** "Show every device that ever
  touched X" / "trace the full evidence timeline behind decision Y" as a direct
  query. The data's already indexed and relational — this is a query-surface/small
  CLI-or-dashboard problem, not a storage problem.
- [ ] **N2. Peer-cohort behavioral baselining.** Ongoing "does this device deviate
  from similar devices" comparison, generalizing the cross-device query mechanism
  Workstream 4/`CoordinatedTargetingHypothesis` already proves out.
- [ ] **N3. Decision replay / regression testing harness.** Re-run any historical
  decision against a newer hypothesis-engine version before shipping a change live —
  every decision's exact supporting evidence is preserved via real `supports` edges,
  not reconstructed from a log. High-value: de-risks every future scoring change.
- [ ] **N4. Multi-signal campaign detection.** Widen `CoordinatedTargetingHypothesis`
  to correlate by shared JA3/JA4 fingerprint or DGA seed, not just shared
  destination — the query pattern already exists, this widens what it correlates on.
- [ ] **N5. In-cycle LLM review.** Dispatch a review the moment an alert fires
  instead of waiting for the 4-hourly batch. Client/validator already built and
  already used by the batch job (Phase 5/8) — only async-dispatch wiring is new, and
  it must never violate the standing "one in-flight Ollama request" rule.
- [ ] **N6. LLM-review local-triage default.** Same item as W4-4 — listed here too
  since it's also a "graph/hardware_profile makes it possible" item, gated on B2.

---

## Part 5 — Sequencing notes (a recommendation, not a decision already made)

1. **P0-1 and P0-2 first, unconditionally** — they affect whether anything else's
   signal (divergence logs, retrained models) can be trusted.
2. **Workstream 1 (cleanup) any time** — zero risk, no dependencies.
3. **Workstream 2 (CL-AFPE live flip)** is the highest-value remaining item and has
   no blocking dependency other than its own bar (W2-1) — but it's also the
   highest-stakes (it changes real suppression behavior), so it should get the same
   explain-then-confirm treatment as every other live-decision-path change this
   project has made.
4. **Workstream 3 (identity/state)** is an architecture decision before it's an
   implementation task — surface W3-1 to the user explicitly, don't default either
   way.
5. **Workstreams 4/5** are independent, low-risk, and can proceed in any order —
   W4-4/N6 is the one exception, gated on Group B2's own open validation question.
6. **Workstream 6 (Suricata)** and **N1-N4** are genuinely separate initiatives with
   no dependency on 1-5 — pick up whenever there's appetite for net-new capability
   rather than migration completeness.
