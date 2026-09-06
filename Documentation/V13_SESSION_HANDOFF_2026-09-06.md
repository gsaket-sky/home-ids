# v13 Session Handoff — 2026-09-06

**Read this first if you're picking this effort back up after a gap.** It's a
point-in-time briefing, not a living document — for current status always
cross-check [`V13_ARCHITECTURE_DEPENDENCY_MAP.md`](V13_ARCHITECTURE_DEPENDENCY_MAP.md)
(what's built) and [`V13_REMAINING_WORK.md`](V13_REMAINING_WORK.md) (what's
open) directly, since they keep changing after this snapshot. The published
plan/status artifact is at
`https://claude.ai/code/artifact/10413936-63b9-4fd6-8793-f4dcfd24f13e`.

**Addendum (same day, after this doc's original snapshot)**: the divergence
comparator now runs automatically every 15 minutes via a plain crontab entry
on `.19` (`src/v13/ops/run_gap_check.py`) instead of needing a manual
invocation — see `V13_ARCHITECTURE_DEPENDENCY_MAP.md`'s own entry for full
detail, including a real cursor-persistence bug found and fixed along the
way. A dashboard is published separately at
`https://claude.ai/code/artifact/a3309d23-2333-41e4-aa17-8b4cb3b38f98`,
genuinely live-updating via the Artifact platform's `db` capability — BUT
that liveness is relayed by a `CronCreate` job in THIS session (id
`e388ea04`), which is session-only and **auto-expires 2026-09-13** (7 days
after creation) regardless of whether this session is still alive by then.
**If you're reading this after that date, the dashboard has silently
stopped updating** (it'll show its last-pushed data with a "stale"
indicator, not an error) — re-create the relay job if live updates still
matter, or just accept the page as a point-in-time snapshot. See
`V13_ARCHITECTURE_DEPENDENCY_MAP.md`'s entry for exactly how the relay works
and why `.19`'s cron can't push to the artifact directly.

**Addendum 2 (same day, 2026-09-06 ~12:50 CEST)**: A11 (a real evidence-coverage
gap — `sources.py` never called `ZeekNetworkDetector`/`DNSBehaviorDetector`,
both of which `.94`'s live pipeline calls every cycle) was found, fixed,
tested (8 new checks, 18/18 files green), and deployed to `.19`
(`v13-ingest.service` restarted). This resets the comparator's "clean data"
clock — divergences gathered before this fix are historical record, not
signal about independence-family grouping. The first automated dashboard-relay
tick after this fix ran clean (totals up, no new severity disagreement). A
concrete flip bar for A10 is now documented in
`V13_ARCHITECTURE_DEPENDENCY_MAP.md`'s "Automated per-mechanism flip bars"
section: **don't consider flipping A10 before 2026-09-13** (7-day time floor,
matching Gap 1/2's own precedent) **and** at least 15-20 real
divergence-eligible comparisons logged in
`state/v13_independence_divergences.jsonl` on `.94`, with a hard, unconditional
veto on any false-negative-shaped divergence found in that window regardless
of time/volume. As of this addendum: ~1.5h post-A11-fix-restart, 120 real
alerts processed, 0 divergences logged (file doesn't exist yet on `.94`) —
too small a sample to mean anything yet, check again in a few days rather
than treating this as "already clean."

---

## 1. What this is, in one paragraph

v13 is a ground-up rewrite of this repo's IDS decision pipeline around a
SQLite-backed EvidenceGraph, built to fix three things a third-party review
found structurally unfixable via incremental patches to the existing
(`v-current`) code: (#17) raw target-domain heuristics instead of mandatory
evidence attribution, (#7/Roadmap #8) genuine per-hypothesis evidence
independence instead of an ad-hoc per-detector grouping string, and
(Roadmap #4) a real graph-native store instead of several independently-TTL'd
flat JSON files. It also generalizes the codebase toward a reusable IDS
product. The plan was to build it fully in parallel (new files only, zero
existing code touched) on a second machine, prove it against real traffic,
then incrementally flip individual mechanisms live — this snapshot is deep
into that flip phase.

## 2. Where things stand RIGHT NOW

**v13 is not just built — it's running.** A live daemon on `.19` continuously
ingests real Zeek + Pi-hole traffic from `.94`, computes real evidence AND
real decisions, and a real comparator diffs those decisions against `.94`'s
actual alerts.json. And as of today, **the first real v13 mechanism
(hypothesis independence-family scoring) is running inside `.94`'s own live
`decision_engine.py`/`pipeline.py`** as a shadow computation — `soc.service`
was restarted and confirmed clean. Nothing about `.94`'s live behavior has
changed yet (the shadow computation only logs, never acts), but the
long-standing gap of "`.94`'s code doesn't know v13 exists at all" is closed
for one mechanism.

**The immediate next step is NOT more building — it's waiting and watching.**
Let real shadow-divergence data accumulate on `.94` (same evidentiary bar
every prior Gap in this project used: "N days, zero false negatives") before
deciding whether to flip that first mechanism live, and before documenting
per-mechanism bars for `gap_monitor.py` (which still doesn't exist — see §5).

## 3. Everything closed this session (2026-09-05 → 2026-09-06)

Each item below has full detail in `V13_ARCHITECTURE_DEPENDENCY_MAP.md` and
`V13_REMAINING_WORK.md` (search for the same A-number) — this is a condensed
index, not the full record.

| # | What | One-line result |
|---|---|---|
| Phases 1-6 | All 12 core v13 modules (evidence, graph store, identity, hypotheses, decision engine, CL-AFPE, LLM review, retro-hunter) | Built + unit tested earlier in this effort, ~247 checks, zero v-current code touched |
| A4 | Deploy automation | GitHub Deploy Keys (one per box, separate keypairs) + 15-min pull cron on `.94` and `.19`. `.19` auto-runs the full test suite and rolls back on failure; `.94` syncs code-only, validates syntax, never auto-restarts `soc.service` |
| A1 | `retro_hunter.py`'s threat-intel lookup | Real `ThreatIntel.lookup_domain()` wired in via a factory, not a test stub |
| A2 | `zeek_exfiltration`/`zeek_beaconing` had no destination | `sources.py` supplies `fallback_context` from `last_dest_ip`, the same value the detector already computed but never attached |
| A3 | v13 had no continuous process at all | `src/v13/ingest/daemon.py` + `v13-ingest.service` (systemd, `MemoryMax=2G`/`CPUQuota=100%`) — **running on `.19` right now** |
| A5 | No Pi-hole/DNS evidence | New `PiHoleLogSource` (a real dnsmasq-text-log parser — the FTL sqlite DB isn't mount-accessible) + `PiHoleFeatureStore` (reuses v-current's real `RollingWindow`/`FeatureExtractor.compute()` unchanged) |
| A7 | v13 only ever produced evidence, never a decision | `compute_decision()` wires v13's own `HypothesisEngine`/`DecisionEngine` against a fresh graph query; a dedup guard stops it from writing an identical row every 2s |
| A8 | No comparator existed | New 4th Samba share (`v13-alerts`, a narrow hardlink to just `alerts.json`, not all of `state/`) + `src/v13/compare/divergence_log.py`. **Verified live**: found 1,691 real divergences in one run (expected — v13's decision history is only hours old) |
| A9 | Auto-flip risk needed re-confirmation | Asked explicitly, given the architecture discovery in A10 below — **user chose "keep fully automatic."** Documented as a deliberate, informed decision, not a default |
| A10 | `.94`'s live code had zero v13 hooks at all | First mechanism (hypothesis independence-family scoring) wired into `decision_engine.py`/`pipeline.py` as a **purely additive** (0 lines removed) shadow computation. **Deployed and running on `.94` right now** |

**Infra also stood up this session**: a fourth Samba share (`v13-alerts`) on
`.94`; a `chmod o+x` traverse-only permission fix on `/home/<deploy-user>`
(needed because the new share's path went through the home directory, unlike
the other three); `soc.service` restarted twice this session (once
implicitly not needed, once explicitly for A10) with clean startups both
times.

**Test count**: 15+ dedicated v13 test files (`tests/test_v13_*.py`, run with
bare `python3`, no heavy deps needed) plus one new v-current test file
(`tests/test_phase68_v13_independence_shadow.py`, needs
`.venv/Scripts/python.exe` — v-current's real dependencies like `geoip2`
aren't in the bare `python3` environment). All green as of this snapshot.

## 4. Real findings that corrected assumptions (read before you build on old assumptions)

These aren't bugs — they're things this session discovered were different
from what the original plan assumed, each one changing subsequent design
decisions:

1. **v13 on `.19` runs as a fully independent process, not an in-process
   shadow hook.** The original plan's "Automated incremental flips" section
   assumed individual mechanisms would be wired into `.94`'s `pipeline.py`
   directly. What got built first was a separate daemon on `.19` with its
   own ingest pipeline — genuinely useful for generating comparison data,
   but it means **nothing on `.94` responds to a `v13_flags` config value
   until you explicitly wire each mechanism in**, which is exactly what A10
   started doing.
2. **Pi-hole's FTL sqlite DB is not shareable/reliable for this.** Not
   mount-accessible via Samba in this deployment, and SQLite's own docs say
   WAL mode (which that DB uses) is unreliable over network filesystems
   regardless. Fixed by parsing the plain-text `pihole.log` instead — a
   genuinely new parser, not a port of anything.
3. **Suricata is not a continuous log stream in this deployment at all.** It
   only runs in short batch invocations against reactively-captured pcap
   bursts. There is no persistent `eve.json` to tail, ever, in this
   architecture — replicating Suricata-sourced evidence for v13 would mean
   replicating the entire capture-trigger subsystem, a distinct, larger
   initiative (tracked as A6, not started).
4. **v13's daemon uses the raw device IP as `device_id`, never routing
   through `identity/resolver.py`'s stable-hash identity.** This is fine for
   now (both v-current's `device.ip` and v13's `device_id` are the same raw
   IP, so the comparator can correlate on it) but is a known, flagged
   limitation — not robust across a device's IP changing mid-comparison.
5. **`.94`'s RAM is 12GB, not the 16GB every prior reference (including
   `fp_engine.py`'s own docstring) claimed.** Verified directly via `free -h`.
6. **The Claude Code auto-mode permission classifier blocks SSH write
   actions to `.94`/`.19` unpredictably** — sometimes a command succeeds,
   sometimes an identical-shaped one is blocked, including `sudo systemctl
   restart soc.service` even after the user explicitly said "restart
   yourself" twice in a row. When blocked, the working pattern is: stop,
   hand the user the exact command, wait for them to confirm "done," then
   verify remotely (read-only checks like `systemctl status`/`journalctl`
   go through fine even when the write itself was blocked).

## 5. What's actually still open (see `V13_REMAINING_WORK.md` for full detail)

**The real next blocker**: `src/v13/ops/gap_monitor.py` doesn't exist yet.
Its prerequisites (A7 real decisions, A8 real comparator, A9 the automation
decision, A10 at least one mechanism actually wired into `.94`) are now all
in place — but it still needs:
- **Per-mechanism bars**: a concrete proposed bar for A10 is now documented
  (see Addendum 2 above and `V13_ARCHITECTURE_DEPENDENCY_MAP.md`) — 7-day
  time floor (not before 2026-09-13) + 15-20 real eligible comparisons +
  zero false-negative-shaped divergences. Not yet met; just documented.
- **UPDATE (Addendum 3, same day, ~15:31 CEST): `gap_monitor.py` now exists and is
  live on `.94`.** See `V13_ARCHITECTURE_DEPENDENCY_MAP.md`'s "A12" entry for full
  detail — the actual live/shadow switch (`pipeline.py`'s `_apply_v13_flip()`) and
  the automated monitor (`src/v13/ops/gap_monitor.py`) are both built, tested (44
  new checks across two files), deployed, and as of this addendum `.94`'s REAL
  `config.yaml` has the `v13_flags:` section and the `gap_monitor` scheduler entry
  (added with explicit confirmation, backed up first to
  `/tmp/config.yaml.pre-gap-monitor-backup` on `.94`). `scheduler.py` re-reads
  config.yaml fresh every 60s loop and runs as its own always-live process
  (confirmed via `ps aux`, PID separate from `soc.service`'s main process) — so
  `gap_monitor.py` starts firing on its `*/15 * * * *` schedule WITHOUT needing a
  `soc.service` restart. It will find `waiting_time_floor` every tick until
  2026-09-13 (harmless, no Telegram noise — see `run_once()`'s own routine-vs-
  noteworthy distinction). This item in §5 above is now DONE, not open.
- **The actual `v13_flags`-driven live/shadow config read** — A10 only wired
  the mechanism to shadow-compute and log; nothing reads a config flag to
  actually switch behavior yet.
- **More mechanisms wired the same way A10 did the first one** — decision
  engine's pluggable hard-stop registry was the other candidate the user was
  offered and didn't pick first; still a reasonable second mechanism.

**A6 (Suricata reactive-capture)**: a real, substantial, separately-scoped
initiative — not connected to the flip-monitor goal, lower priority.

**Everything in Groups B/C/D/E/F of `V13_REMAINING_WORK.md`**: genuinely can
wait — either the parallel run's own data is supposed to answer it (Group B:
which independence-family granularity is actually better, whether triage
specificity needs tuning, whether production's real Ollama model has the
placeholder-echo bug), or it's real future work with no current dependency
(CL-AFPE scope cuts, LLM-review scope cuts, retro-hunter's cross-device IOC
check, the `IDS_PRODUCT` GitHub repo milestone).

## 6. Standing rules that apply to ANY future work on this repo/project

These are established, not just this-session preferences — check the auto-
memory system too (`feedback_*`/`project_*` files), but the load-bearing
ones for v13 work specifically:

- **Never restart `.94`'s `soc.service` as part of an automated deploy** —
  always a separate, explicit human-triggered action. (`.19`'s
  `v13-ingest.service` is NOT production and can be restarted more freely
  when its own code changes — that distinction matters.)
- **Never send more than one in-flight request to `.94`'s own Ollama** (its
  `llama-server` runs with `-np 1`) — a real production-contention incident
  happened this way earlier in this effort.
- **Never run the full pre-existing 22-file v-current test suite without
  asking first** — v13's own ~15-file suite is fine to run freely, it's a
  separate, smaller, already-established convention.
- **Never use real hostnames/first names in anything committed to this
  repo** — it's public on GitHub. Use `.94`/`.19`/"the deploy user" style
  placeholders, matching what's already in every doc this session touched.
  Always `grep` a diff for the real username before staging.
- **Big infra changes on `.94`/`.19` (new Samba shares, new systemd units,
  service restarts) get explained-then-confirmed, not silently executed** —
  this session's whole A8/A9/A10 sequence followed that pattern throughout.

## 7. Quick orientation for a cold-start session

1. Read `V13_ARCHITECTURE_DEPENDENCY_MAP.md` and `V13_REMAINING_WORK.md` in
   full — they're kept current, this handoff doc isn't.
2. Check `git log --oneline -20` on `main` for what's landed since this
   snapshot (this doc was written at commit `474b4d2`).
3. SSH to `.19` (the deploy user `@192.168.77.19`) and check
   `sudo systemctl status v13-ingest.service` — confirm it's still running,
   check how much real divergence data has accumulated in
   `state/v13_divergence.jsonl` (from `.19`'s own comparator runs, if
   `gap_monitor.py` or a cron job has been calling `run_comparison()`
   periodically — as of this snapshot, nothing schedules that call yet, it
   was only ever run manually once).
4. SSH to `.94` and check `state/v13_independence_divergences.jsonl` — if it
   exists and has entries, that's the real shadow-divergence data A10's
   "when to pick this back up" condition is waiting on.
5. The published artifact (`https://claude.ai/code/artifact/10413936-63b9-4fd6-8793-f4dcfd24f13e`)
   has a visual module-by-module status board — useful for a quick refresher
   before diving into the two markdown ledgers.
