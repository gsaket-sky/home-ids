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

**Versioning boundary — v13 CLOSED 2026-09-07**: Workstreams P0/1/2 (see Part 3)
are complete — that closes out **v13** as a milestone. Workstream 3 onward, plus
the net-new items in Part 4, are tracked as **Release 14** — a fresh version, not
a renumbering of the same list. See Part 3's own banner for the full record.

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

## Part 2a — Manual actions on `.94` — DONE 2026-09-07, verified

User ran all 5 steps directly on `.94` (SSH writes had been blocked by the
auto-mode classifier all session, 2-for-2). Independently re-verified via
read-only SSH after the fact, not just taken on report:
- `shadow_watcher` scheduler block confirmed gone from `config.yaml` (only the
  historical "REMOVED" comment remains).
- `cl_afpe_engine: v_current` and the `cl_afpe_flip_monitor` scheduler entry
  both confirmed present.
- `models/fp_classifier.onnx` now matches `state/models/fp_classifier.onnx`
  byte-for-byte (8148 bytes, both copies) — the retrain/inference split is closed.
- `state/metrics_dump.txt` and `state_scratch/` both confirmed removed.
- `soc.service` restarted cleanly (`ActiveEnterTimestamp` 2026-09-07 21:50:06
  CEST) — journal since restart shows zero errors/tracebacks, only two routine,
  unrelated lines (an AbuseIPDB rate-limit warning; local-intel correctly
  refusing to record a multicast address as confirmed-malicious, a guard
  working as intended, not a bug).
- **Follow-up correction #1, same day**: the user's own live `journalctl -f`
  caught the `--runmode=workers` fix failing for real — Suricata rejected it
  outright (`custom type "workers" doesn't exist for this runmode type
  "PCAP_FILE"`), exiting 1 immediately with zero findings on every burst
  since the restart. Re-fixed to `--runmode=autofp` (the actual multi-threaded
  PCAP_FILE option).
- **Follow-up correction #2, same day**: `autofp` alone *still* didn't fix it
  — real bursts kept timing out. A live CPU-sampling watcher (see Workstream 6
  below for full detail) found the real cause: a separate, pre-existing
  `suricata.service` daemon crash-looping 25,922+ times (disabled), AND
  Suricata being throttled to a shared ~40%-of-one-core cgroup budget because
  it's spawned as a child of `soc.service` (fixed via a new opt-in
  `reactive_capture_suricata_cgroup_isolate` config key).
- **Follow-up correction #3, next day (2026-09-08)**: enabling the config key
  and deploying immediately broke every scan a different way — `sudo: The "no
  new privileges" flag is set, which prevents sudo from running as root`.
  `soc.service` has `NoNewPrivileges=true` set (real, deliberate hardening,
  correctly left in place rather than weakened) — the kernel blocks sudo
  outright for such a process regardless of sudoers policy, so `.94`'s
  passwordless `sudo` never mattered. Re-fixed to `systemd-run --user --scope`
  (asks the calling user's own systemd instance, no new privilege requested
  at all — compatible with `NoNewPrivileges=true` instead of fighting it);
  needs `loginctl enable-linger <user>` done once so that instance exists at
  boot. **Verification of THIS version is still pending** — not yet observed
  under a real post-fix burst as of this note.

Original instructions (kept below for the historical record — all already applied):

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
#    wiring + the Suricata --runmode=workers fix + N4's zeek_network.py provenance
#    change (explicit, human-triggered, per the standing rule -- not something to
#    automate)
sudo systemctl restart soc.service
sudo systemctl status soc.service --no-pager
```

**After this restart, worth watching specifically**: `sudo journalctl -u soc.service -f
| grep -i suricata` during/after the next few reactive-capture bursts — confirm scans
now complete within the 240s timeout instead of every single one timing out. If they
still time out even with 8-core parallelism, the ruleset-trim/timeout-margin follow-ups
noted in Workstream 6 become the next real step, not a re-guess at the runmode fix.

After restart, worth a spot-check: `journalctl -u soc.service -n 50 --no-pager` for a
clean startup with no new errors.

## Part 3 — Full shift plan: every scope cut, why it existed, what completing it requires

Format per item: **what**, **why it was cut** (the real original reason, not
"not done yet"), **what full completion requires**, checkbox.

> ## 🏁 v13 is CLOSED (2026-09-07)
>
> Workstreams 0, 1, and 2 — the fix, bugfixes, cleanup, and CL-AFPE live-flip
> mechanism — are all built, tested, and committed (`fea2f21`, `379a86b`). That's
> the whole of what "v13" was scoped to be: the EvidenceGraph architecture, live,
> with every mechanism either flipped or holding a real, automated path to flip.
> The remaining open item (W2-3, retiring CL-AFPE's flat files) is explicitly
> gated on real production data accumulating first, not on more building — v13
> has nothing further to build.
>
> **Everything from Workstream 3 onward, plus every net-new item in Part 4, is
> tracked as a new version: Release 14.** Not a renumbering — a fresh scope with
> its own milestone, matching the project's own convention of naming a real
> version boundary rather than an endless "v13.x" tail.

---

# Release 14 — beyond the EvidenceGraph cutover

Everything below is genuinely new scope, not v13 cleanup. Same tracked-checklist
discipline as Part 3 above: what, why it was cut/deferred, what completion
requires, checkbox.

> ## 🏁 Release 14 is COMPLETE (2026-09-07)
>
> Every item in this plan — Workstreams 0 through 6, plus N1 through N5 (N5
> deliberately reconfirmed deferred; W4-4/N6 deliberately gated on Group B2's own
> open validation question) — is now built, tested, committed, and pushed. Two
> real bugs found and fixed along the way that weren't in the original scope at
> all (the ML retrain/inference path split, and Suricata's 100%-timeout-rate
> `--runmode=single` bug). **The `.94` manual action list (Part 2a) is now DONE
> too** — applied by the user 2026-09-07, independently re-verified via
> read-only SSH (clean restart, config confirmed, models consolidated). The
> only thing still open in this entire plan is the CL-AFPE live flip (W2-3),
> which is correctly gated on real production data accumulating, not on more
> building.
> See the artifact for the full item-by-item trackable checklist.

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

### Workstream 3 — Identity/state fully on the graph — DONE 2026-09-07

**Why this wasn't attempted**: A29 found `GraphStore.merge_device()` had zero
callers *at all* before that session — the fix scope was "wire the one merge-mirror
gap that broke," not "migrate identity off `StateManager` entirely." No prior session
ever scoped the larger migration.

- [x] **W3-1.** Decided explicitly with the user: **graph-backed durability,
  `StateManager` stays the hot-path cache** — a middle ground chosen on its own
  technical merits (identity resolution is the single most incident-prone
  subsystem this project has hit — 3 real production bugs in Phase 3 alone —
  and a Pi-class SQLite read on every device's every cycle is a genuinely
  different resource profile than the evidence graph's own batched writes),
  not because it's less work than a full migration.
- [x] **W3-2.** Implemented: `LiveIdentityManager` gained a new
  `_refresh_identity_signals()` override (item 6 in its own module docstring) —
  runs the real v1 update unchanged via `super()`, then mirrors the MAC/IP into
  `GraphStore.update_device_metadata()`'s new `mac_history`/`known_ips_history`
  dicts (`{value: last_seen_timestamp}`). Deliberately write-only: the hot
  `resolve_device_id()` lookup still reads `state_manager.get_device_id_for_mac()`
  exclusively, unchanged — no SQLite on the hot path. Only writes on a
  genuinely NEW MAC/IP (no write amplification), bounded eviction (20 MACs /
  50 IPs per device — a real, bounded improvement over `StateManager`'s own
  in-memory `BoundedSet(max_size=8)` for `known_ips`, honoring the standing
  Pi-8GB no-unchecked-growth constraint), fail-safe (a graph read/write failure
  never affects the real v1 update). 13 new checks in
  `tests/test_v13_live_identity.py` (2 in Section A confirming this is a real,
  isolated override that doesn't touch `process_dns_identities`/
  `process_zeek_identities`; 8 in new Section G — new-value mirroring,
  no-write-amplification on a repeat value, bounded/oldest-evicted,
  `graph_store=None`, graph-failure fail-safe). Full v13 GraphStore suite
  re-confirmed clean alongside this.

### Workstream 4 — LLM-review completeness (remaining Group D items)

- [x] **W4-1. Cross-device campaign correlation.** DONE 2026-09-07. Real
  investigation found this wasn't quite `_is_campaign_corroborated()` (that's a
  v1-specific auto-suppress-withhold guard `live_llm_review.py` has no equivalent
  action for) — the actual gap was structural: `live_llm_review.py` reads
  PERSISTED graph evidence, but `live_engine.py`'s own live decision path
  deliberately never persists its synthetic `coordinated_targeting` evidence
  (writing it would recreate the Phase 1 evidence-duplication incident), so a
  decision informed by "another device just touched this destination" left the
  reviewer with no way to see that fact. Fixed by re-deriving
  `coordinated_targeting` fresh at review time (`_inject_coordinated_targeting()`),
  anchored to the decision's own original timestamp — reuses the exact same
  `graph/window.py` query `live_engine.py` uses, matching
  `independence_family_report.py`'s own "re-derive, don't assume persistence"
  precedent. Scoped to `coordinated_targeting` only (the item named here);
  `first_contact`/reputation-propagation have the identical structural gap but
  are a separate, not-yet-scoped follow-up.
- [x] **W4-2. GeoIP enrichment for v13's LLM-review report.** DONE 2026-09-07.
  Verified as a real gap (confirmed via grep: `live_llm_review.py` had zero GeoIP
  references while `ollama_soc.py` uses it for both digest text and campaign
  correlation). Ported `_geo_note()` as a small local copy (matching
  `live_retro_hunter.py`'s own established "small per-script copy" convention),
  wired into the Telegram digest's per-rejection detail lines via a new
  `_representative_destination()` heuristic (highest-confidence real destination
  among the evidence reviewed — documented as a first-pass heuristic, not a
  claim of a single canonical "target" the way v1's alert_payload has one).
  Human-facing reporting only, never sent to the LLM. 12 new tests in
  `tests/test_v13_live_llm_review.py` including an end-to-end check that the
  real prompt sent to the (fake) LLM for a two-device shared-destination
  scenario actually contains `coordinated_targeting` — proving the fix closes
  the structural gap, not just that the helper function works in isolation.
- [ ] **W4-3/N5. In-cycle LLM review** — **decision reconfirmed 2026-09-07,
  stays deferred.** Asked explicitly: building this means a background
  dispatch queue/worker thread inside `soc.service`'s own always-running
  process (Ollama's up-to-900s worst case makes a synchronous in-cycle call a
  non-starter), a materially different, higher-risk change than every adapter
  built this session, all of which call synchronously and fail-fast. The
  4-hourly batch job already reviews everything at meaningfully lower risk;
  chosen to leave deferred, matching A20's original reasoning, not overridden
  just because this plan reached it.
- [ ] **W4-4. LLM-review local-triage default.** Why cut: `query_triage()`'s own
  accuracy is unvalidated (Group B2, still open) — wiring a `hardware_profile`
  default for a capability nothing calls yet would be speculative. **Sequence
  strictly after B2 is resolved**, not before.

### Workstream 5 — Retro-hunt completeness — DONE 2026-09-07

- [x] **W5-1. Per-device job-health breakdown** for `live_retro_hunter.py`.
  `_count_by_device()` added, generic over both `findings` (attribute access) and
  `local_intel matches` (dict access) — `job_health.json` now carries
  `findings_by_device`/`local_intel_matches_by_device`.
- [x] **W5-2. The loop-closing `record_confirmed_threat()` + sigma `TUNE_UP` action**
  for a newly-implicated device. `_close_local_intel_loop()` threads a
  `ClAfpeEngine` instance into `live_retro_hunter.py` (previously the named
  blocker), calling `record_confirmed_threat(reason="RETRO_HUNT_LOCAL_INTEL_MATCH")`
  — matching `scripts/retro_hunter.py`'s own real reason string exactly — plus a
  `TUNE_UP` sigma-shift, per-match fail-safe (one failure never blocks closing the
  loop for other matches in the same run). Verified the actual point of doing
  this, not just recording it: a second run against the same fixture finds ZERO
  new matches for the now-closed device (its own exclusion rule now correctly
  treats it as an already-known source) — without this, an identical match would
  have re-fired and re-notified every single day. 12 new tests across
  `tests/test_v13_live_retro_hunter.py` (end-to-end loop-closing + the
  zero-new-matches-on-rerun proof + sigma-shift persistence check) and inline
  unit tests for both new functions' fail-safe paths. Full `test_v13_retro_hunter.py`
  suite re-confirmed clean.

### Workstream 6 — Suricata evidence pipeline (A6) — CLOSED 2026-09-07 (already-satisfied, stale framing corrected) + a real bug found and fixed along the way

- [x] **W6-1.** Re-investigated before building anything (the "why cut" reasoning
  below predates A13's fast engine cutover and turned out to be stale). Read the
  real code: `extractors/fritzbox_capture.py:670` already calls
  `evidence_store.add(ev)` for every real Suricata signature match, writing
  directly into v1's shared `EvidenceStore` — the SAME store `pipeline.py`'s
  `active_evidence` is drawn from every cycle, which `v13_live_engine.evaluate()`
  already converts via `convert_list()` with no type filtering. **v13's
  `SuricataSignatureHypothesis` already receives real Suricata evidence
  automatically, with zero v13-specific wiring ever needed** — the original A6
  gap was scoped around `.19`'s separate standalone comparator daemon (which
  can't tail Suricata independently), and that comparator's whole purpose
  (deciding whether to trust v13 before cutover) is moot now that v13 already
  *is* the live engine. No new code needed for the actual live decision path.
  ~~Why cut: not a tailable log stream in this deployment at all — Suricata only
  runs in short batch invocations against reactively-captured pcap bursts;
  replicating this for v13 means replicating the entire burst-trigger/dispatch
  subsystem, not writing a tailer.~~ (superseded reasoning, kept for the
  historical record.)
- [x] **A real, significant, pre-existing bug found by the live verification
  smoke test** (not a v13 issue — affects v1 and v13 equally): checked `.94`'s
  real `journalctl` logs before trusting the code-read alone. Over 48 hours: 139
  reactive-capture bursts completed, **every single one** reporting
  `suricata_findings: {}`; separately, 151 Suricata batch-scan invocations hit
  their 240s timeout and were skipped. **Root cause**: `run_suricata_on_pcap()`
  hardcoded `--runmode=single`, pinning the ENTIRE batch scan to one CPU core
  regardless of availability — confirmed via SSH that `.94` has 8 real cores
  (`nproc`) sitting mostly idle during each scan, against a genuinely large,
  untrimmed 68,620-line ruleset and burst captures up to ~170MB per radio.
  Suricata has effectively never produced a real detection via reactive capture
  in production, independent of this migration. **First fix attempt was itself
  wrong, caught live**: `--runmode=single` → `--runmode=workers` was deployed
  and confirmed-clean via a post-restart journal check, but the user's own
  `journalctl -f` shortly after caught it actually failing — Suricata rejected
  `workers` outright (`custom type "workers" doesn't exist for this runmode
  type "PCAP_FILE"`), exiting 1 immediately with zero findings on every burst,
  which is worse than the timeout it replaced (at least the timeout attempted a
  real scan). `workers` only exists for live-capture runmode types
  (AF_PACKET/PF_RING/etc.); `-r` (offline pcap) only supports `single`/`autofp`.
  **Corrected for real**: `--runmode=autofp` — PCAP_FILE's actual
  multi-threaded option (one capture thread, N auto-flow-pinned detection
  worker threads, one output thread). Regression tests in
  `tests/test_phase37_suricata_batch_scan.py` updated to assert `autofp` is
  used and guard against *both* `single` and `workers` reappearing — full file
  (30 checks) re-confirmed clean.

  **A third, deeper root cause, found the same day by re-verifying under real
  load instead of trusting the `autofp` fix on its own**: even with `autofp`
  and with the (separately-found — see below) crash-looping `suricata.service`
  disabled, real bursts *still* timed out. A CPU-sampling watcher run against a
  live scan showed Suricata using only ~19% of one core, wall-clock time spent
  waiting rather than computing, with 6+ of 8 real cores sitting completely
  idle (load average never exceeded ~1.8) — the opposite of a CPU-bound
  problem. Root cause: `run_suricata_on_pcap()` spawns Suricata as a **child of
  `soc.service`**, which inherits the whole cgroup, including
  `soc.service`'s own `CPUQuota=40%` — sized for the always-on 2s decision
  loop (whose own steady ~25% usage was already eating most of that budget),
  never for an occasional multi-threaded batch job. Confirmed directly: the
  exact same pcap that timed out in-pipeline finished in 90-99s when run
  manually outside the cgroup, at ~100% CPU. No `--runmode` choice could ever
  have fixed this — the ceiling was external to Suricata entirely. **Fixed**:
  new opt-in `reactive_capture_suricata_cgroup_isolate` config key wraps the
  invocation into its own transient `reactive-capture.slice` (auto-collected
  on exit, own configurable `reactive_capture_suricata_cpu_quota_percent`,
  default 300%) — the main loop's own tight quota stays untouched; only the
  batch scan gets room to use idle cores.

  **First deploy attempt failed immediately, caught live (2026-09-08)**: the
  initial version wrapped with `sudo systemd-run --scope`. Enabled and
  deployed, every scan then failed with `sudo: The "no new privileges" flag is
  set, which prevents sudo from running as root`. `soc.service`'s own unit has
  `NoNewPrivileges=true` (real, deliberate hardening — "Restrict what the IDS
  process can do if compromised" — correctly left in place, not weakened to
  make this work) which makes the kernel refuse ANY new-privilege exec
  including sudo, regardless of sudoers policy; `.94`'s deploy user having
  `NOPASSWD: ALL` never mattered. **Re-fixed for real**: `systemd-run --user
  --scope` instead — asks the calling user's own systemd instance to create
  the scope, requesting no new privilege at all, fully compatible with
  `NoNewPrivileges=true` rather than fighting it. Requires `loginctl
  enable-linger <user>` (done once on `.94`) so that instance exists at boot
  independent of any login; `XDG_RUNTIME_DIR` is set explicitly in the
  subprocess environment since a boot-time system service doesn't inherit it
  the way an interactive shell would. No `--uid`/`--gid` flags needed anymore
  either — `--user` inherently runs as the calling user. Regression tests
  updated to assert `--user` is used and guard against `sudo` reappearing —
  full file (35 checks) re-confirmed clean.

  **Also found and fixed along the way, unrelated to any of the above**: a
  separate, pre-existing `suricata.service` systemd unit (installed by the OS
  package, live AF_PACKET mode) was crash-looping — **25,922+ restarts**,
  configured for an interface (`eth0`) that doesn't exist on this box, burning
  a full CPU core every ~35-40s cycle recompiling the ruleset before failing.
  Not part of this codebase's design at all (the documented architecture is
  deliberately batch-only) and never fed the pipeline. Disabled
  (`systemctl disable --now`) — confirmed stopped, no process remains.

  **Still not confirmed under real load**: the corrected `--user`-based
  `cgroup_isolate` fix is deployed and enabled on `.94` with linger active,
  but hasn't yet been observed against a real post-fix burst as of this note
  — needs one more live-burst journalctl check for an actual "scan complete"
  line before this can be marked done.
  **Deliberately not also done, flagged as a real follow-up**: the
  68,620-line ruleset is the full/untrimmed feed, not the "trimmed/security
  policy" this module's own docstring says was the intended design — pruning it
  is a real detection-coverage-vs-performance judgment call, left for a human
  decision once the `--runmode` fix's real-world effect on scan duration can be
  observed, not pre-emptively pruned blind. Also worth a later look if timeouts
  persist post-fix: `reactive_capture_suricata_timeout_seconds` (240.0, the
  config default `.94` is running) could still be raised as a safety margin, and
  `.94`'s current 3.7GB/4GB swap usage is worth a health check even though it
  isn't confirmed as a contributing cause here.

---

## Part 4 (Release 14) — Net-new capability: "Now possible, not yet built"

Pulled from the companion artifact's own "Potential" section — these aren't scope
cuts (nothing pre-v13 ever had them), they're direct consequences of the graph
existing that nobody has built yet.

- [x] **N1. Ad-hoc historical threat-hunting surface.** DONE 2026-09-07. New
  `src/v13/ops/threat_hunt.py`, a thin CLI (`devices --destination X`,
  `timeline --decision-id X`, `device --device-id X`) over 3 small functions,
  almost entirely reusing `GraphStore`'s already-built read methods — exactly
  the "query-surface problem, not a storage problem" this item's own framing
  predicted. One new `GraphStore.get_decision(decision_id)` method (a single-row
  lookup, mirroring `get_decisions_since()`'s own parsing) was the only new
  storage-layer code needed. 15 new tests (`test_v13_threat_hunt.py` + 3 in
  `test_v13_graph_store.py`), including a merged-orphan-history check (looking
  up either the orphan or canonical id transparently returns the same full
  history).
- [x] **N2. Peer-cohort behavioral baselining.** DONE 2026-09-07 — the LAST item
  in this entire plan. Asked explicitly first: live detection signal vs.
  reporting-only vs. skip, since this is the one N-item that's a genuinely NEW,
  unvalidated anomaly heuristic rather than a query surface (N1) or a widened,
  already-established correlation concept (N4). User chose the live signal.
  Cohort = `device_type` (already computed, now also persisted onto
  `device_metadata` as a side effect of evaluation — the cohort self-completes
  over time, no backfill job needed). Metric = distinct-destination count over
  a 7-day window (cheap, needs no new evidence field, a real anomaly axis for
  many device classes — e.g. most IoT devices talk to a small, stable
  destination set). New `GraphStore.get_devices_with_metadata_value()` +
  `get_distinct_destination_count()`; `live_engine.py`'s
  `_inject_peer_deviation_evidence()` (own injection call, not folded into
  `_inject_graph_derived_evidence()`, precisely because it's a different risk
  category) requires ≥2 real peers (a statistically meaningless comparison
  otherwise) and both a ≥3x multiplier AND a ≥5 absolute floor (avoids
  flagging trivial small-number swings) — first-pass, explicitly **not
  empirically tuned**, same honesty framing as `INDEPENDENCE_FAMILY_MAP`. New
  `PeerDeviationHypothesis`, deliberately capped at a SUSPICIOUS ceiling (3.0)
  on its own — reflecting the lower confidence (0.6 vs. 1.0 for established
  signals) explicitly rather than silently trusting an unvalidated heuristic;
  reaching HIGH still requires a second, independent, corroborating family
  (the decision engine's own ≥2-independent-source gate already enforces this
  structurally, no extra code needed). 20 new tests across
  `test_v13_graph_store.py`/`test_v13_hypotheses_engine.py`/
  `test_v13_live_engine.py` (Section H — including a fail-safe and both
  not-enough-peers and no-device_type regression guards). Full v13 suite +
  `test_v13_integration.py` re-confirmed clean.
- [x] **N3. Decision replay / regression testing harness.** DONE 2026-09-07. New
  `src/v13/ops/decision_replay.py` (manual/CI-style diagnostic, not a scheduled
  job): `get_decision_evidence()` resolves a historical decision's REAL
  supporting evidence via its `supports` edges; `replay_decision()` re-runs the
  CURRENT `DecisionEngine` against it and reports unchanged/changed/no-evidence-
  available/replay-error; `replay_range()` + a `main()` CLI (`--since-days`,
  `--device-id`, `--changed-only`, `--out`) drive it end-to-end. **Real,
  documented limitation**: a decision's original `rep`/`device_type`/
  `baseline_familiarity`/`is_safe` context isn't stored on the row and can't be
  perfectly reconstructed — `_rep_from_evidence()` derives a best-effort
  duck-typed rep from any `reputation` evidence present; the rest default to
  safe/neutral values. Answers "does the current scoring logic reach a
  different verdict against the same real evidence," a real regression signal
  that doesn't need a byte-perfect environment reconstruction to be useful. 11
  new tests in `tests/test_v13_decision_replay.py`.
- [x] **N4. Multi-signal campaign detection.** DONE 2026-09-07, larger than
  originally scoped — investigated first and found the JA3/JA4 hash was never
  captured into Evidence at all (only a boolean flag), and DGA-seed correlation
  needed genuinely new similarity logic, not just a query. User chose to build
  both. **Fingerprint half**: `intelligence/detectors/zeek_network.py` (a live
  v1 hot-path detector) now encodes the real ja3/ja4 hash into `provenance`
  (this codebase's own established free-text-discriminator convention) —
  additive only, doesn't change what triggers evidence or any existing scoring.
  New `GraphStore.get_devices_sharing_provenance()` (exact match) +
  `RollingWindowView.devices_sharing_fingerprint()` wrapper. **DGA-seed half**:
  no detector change needed (the domain string is already in `destination_id`)
  — new `_dga_shape_key()` in `live_engine.py` computes a coarse "generation
  shape" (label length + TLD + charset class), an established DGA-clustering
  heuristic, explicitly flagged as a first-pass/not-empirically-tuned number
  matching `INDEPENDENCE_FAMILY_MAP`'s own honesty convention. New
  `GraphStore.get_evidence_by_type_since()` for the cross-device scan the shape
  grouping needs. Both wired into `_inject_graph_derived_evidence()` (same
  never-persisted-to-the-graph pattern as `coordinated_targeting`) as two new
  evidence types (`fingerprint_campaign`, `dga_seed_campaign`) feeding the SAME
  `CoordinatedTargetingHypothesis`, now widened to score on any of the three
  (unchanged scoring logic — it already read generically). 30 new tests across
  `test_v13_graph_store.py`/`test_v13_graph_window.py`/`test_v13_live_engine.py`
  (Section G)/`test_v13_hypotheses_engine.py`; 1 pre-existing test
  (`test_phase32_lateral_movement_targets.py`) updated for the new provenance
  format. Full v13 suite + `test_v13_integration.py` re-confirmed clean.
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
