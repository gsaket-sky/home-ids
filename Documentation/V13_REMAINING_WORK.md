# v13 Remaining Work — Complete Ledger

Living document, companion to [`V13_ARCHITECTURE_DEPENDENCY_MAP.md`](V13_ARCHITECTURE_DEPENDENCY_MAP.md).
That file tracks what's *been built and tested*; this one tracks **everything still
open** — every deferral, scope cut, and unresolved question raised anywhere across
this effort — in one place, so nothing quietly falls through the cracks between
sessions. Same discipline as `HEE_ROADMAP.md` (v-current's own "considered and not
built" ledger): when an item here gets picked up, move it into the dependency map
with its outcome and delete it from here.

Each item states **why it's open** (the actual reason, not just "not done yet")
and **when it should be picked up** (a real trigger condition, not a vague
priority label) — the two things a "just a TODO list" would leave out and that
future confusion would come from omitting.

---

## Group A — Needed to make Phase 7 (deployment + parallel-run) actually work

These aren't optional polish — the parallel run can't produce meaningful
comparison data without them.

### A1. ~~`retro_hunter.py`'s threat-intel lookup is currently a test stub~~ — DONE (2026-09-06)
**Resolved**: added `real_threat_intel_lookup_factory(config, state_dir,
refresh=True)` to `src/v13/retro_hunter.py`. It constructs v-current's own
`intelligence.threat_intel.ThreatIntel` (feed-refresh logic reused as-is, not
reimplemented) and returns its `lookup_domain` bound method directly as the
injected `threat_intel_lookup` callable — confirmed `lookup_domain(domain:
str) -> Optional[dict]` already returns exactly the `{confidence, tags,
source}` shape `RetroHunter` expects, so this is a genuine pass-through, not an
adapter. 5 new mock-based tests added to `tests/test_v13_retro_hunter.py`
(construction args, `_refresh_all()` call behavior for both `refresh=True` and
`refresh=False`, and that the real bound method is returned unchanged) — full
file now 18/18. All 12 v13 test files (227+ unit checks + the 15-check
integration test) independently re-confirmed passing after this change.

### A2. ~~`zeek_exfiltration`/`zeek_beaconing` never carry a real destination~~ — DONE (2026-09-06)
**Resolved**: `src/v13/ingest/sources.py`'s `run_detection_cycle()` supplies
`fallback_context={"dest_ip": features["last_dest_ip"]}` — the SAME destination
`threat_signals.py`'s own detector code already computes internally (via
`ZeekFeatureExtractor._last_connection_meta`) but never attached to the
`Evidence` it creates. Guarded against `ZeekFeatureExtractor`'s own "no
connection seen yet" sentinel (`"unknown"`) so a device with no real connection
data correctly still gets `NO_DESTINATION`, not a fake destination. Verified
two ways: 26 unit checks in `tests/test_v13_ingest_sources.py`, and a live
sanity check feeding a real massive-outbound-burst pattern through the REAL
(imported, unmodified) `ZeekFeatureExtractor` + `ThreatSignalDetector` classes
— produced `zeek_exfiltration` evidence with `destination_id="8.8.4.4"`
instead of `NO_DESTINATION`, confirming this isn't just test-shaped.

### A3. ~~Resource isolation on `.19`~~ — DONE (2026-09-06)
**Resolved**: `src/v13/ingest/daemon.py` wraps `sources.py`'s tailer/detection
functions into a continuous poll loop (2s interval, matching v-current's own
`poll_interval` default), writing real v13 Evidence into a `GraphStore` at
`state/v13_graph.db`. `src/v13/ops/v13-ingest.service` installs it as a
systemd service on `.19` with `MemoryMax=2G`/`CPUQuota=100%` — sized as a
ceiling against runaway behavior (a log-parsing bug spinning in a tight loop),
not a tuned allocation, against `.19`'s confirmed 31GB/8-core spec and its
Docker Ollama's own idle footprint (~780MB combined at check time, 30GB+
free). **Verified live, not just "service is active"**: within ~90 seconds of
starting, the daemon had picked up a real `arp_sweep` evidence item (device
`.94` itself, ARP-scanning the LAN as part of its own normal Pi-hole/NAS
discovery — a benign, expected pattern) through the FULL real pipeline (Zeek
JSON log → `ZeekLogSource` tailer → real `ZeekFeatureExtractor.ingest()` →
real `ThreatSignalDetector.detect()` → `v13.evidence.ingest.convert_list()` →
`GraphStore.insert_evidence()`), confirmed by querying the live sqlite file
directly. Memory held steady at ~11MB (0.5% of the 2G ceiling), CPU
negligible. Per-log-type cursor files (`state/v13_ingest_cursors/`) persisted
correctly across poll cycles. Config loaded from a real, gitignored
`config_v13.yaml` on `.19` (`network.subnets: [192.168.77.0/24]` — never
committed, same split as `config.yaml`/`config.yaml.example`).

### A5. ~~`sources.py` doesn't produce any Pi-hole/DNS-behavior evidence yet~~ — DONE (2026-09-06)
**Resolved**: `src/v13/ingest/sources.py` gained `PiHoleLogSource` (a new
dnsmasq-format text-log parser, grammar confirmed via direct `grep` against
`.19`'s live `pihole.log`, not assumed — correlates a `query[TYPE] domain
from client_ip` line with its own subsequent `<verb> domain is <value>`
resolution line; a CNAME chain's intermediate hops, which never had their own
query line, correctly go uncorrelated and are silently skipped, not
misattributed) and `PiHoleFeatureStore` (a per-device wrapper reusing
`core/state.py`'s real `RollingWindow`/`BoundedSet` and
`extractors/dns_features.py`'s real `FeatureExtractor.compute()` UNCHANGED —
feature computation itself was never the problem, only the sqlite-DB
ingestion path was unavailable). `run_detection_cycle()` gained an optional
`dns_features` param, merged into the Zeek-derived features dict before
calling `detect()` — no key collisions between the two sources, confirmed by
direct comparison. `daemon.py` wires a `PiHoleLogSource` against `.19`'s
`/mnt/v13-pihole/pihole.log` alongside the existing Zeek sources, so a device
seen only via DNS traffic (no Zeek conn/arp event that cycle) is still
evaluated. **Verified two ways**: 12 new unit checks in
`tests/test_v13_ingest_sources.py` (line-grammar parsing, classification,
CNAME-chain correlation, cursor persistence/rotation) plus 3 new end-to-end
checks in `tests/test_v13_ingest_daemon.py` — a real, long, high-entropy DNS
label fed through the actual dnsmasq log-line format produced genuine
`dns_tunnel_v2` evidence via the full daemon, not just at the unit level.
**Known, documented limitation carried forward, not silently accepted**:
`top_domain` still isn't wired (stays `None`), so `detect()`'s
telemetry-domain dampening won't suppress DNS evidence for telemetry-heavy
devices the way v-current's live behavior does — the two domain-EXAMPLE
branches (which carry real attribution, matching #17's own point) are
unaffected since they already exclude telemetry domains at the source.
**Also flagged**: `dns_qtypes` is fed the real DNS query type (from
`pihole.log`'s own `query[TYPE]` line) rather than v-current's
`row.get("reply_type", 0)` (a Pi-hole FTL DB column unavailable from text
logs) — a deliberate divergence that arguably matches this field's own
documented intent ("Tracks DNS qtypes") better than v-current's own value
does, not a regression.

### A6. Suricata reactive-capture is NOT a tailable log stream — real scope cut, not built
**What**: found while building `src/v13/ingest/sources.py` (2026-09-06):
`.19`'s live `v13-suricata` share has an `eve.json` sitting at 0 bytes even
though the mount and Samba path both work correctly — because this
deployment's `intelligence/detectors/suricata_scan.py` runs Suricata in short
BATCH invocations against reactively-captured pcap bursts
(`extractors/fritzbox_capture.py`'s `ReactiveCaptureDispatcher`, triggered a
handful of times per hour), not continuously against live traffic. Each
invocation writes to a per-run scratch `eve.json` that doesn't persist — there
is no live, continuously-growing `eve.json` to tail at all in this
architecture, confirmed by direct inspection, not assumed from the plan's
original "Suricata eve.json" framing (which predates this finding).
**Why it's open**: replicating this for v13 means replicating the ENTIRE
reactive-capture trigger/dispatch subsystem (burst-triggering heuristics, pcap
capture, invoking both Zeek and Suricata against it) — a substantial, separate
subsystem, not a log tailer. Matches this project's own precedent for CL-AFPE
(Group C) and retro-hunter (Group E)'s local-intel dependency: an honest,
named scope cut, not a silent omission.
**When**: a distinct, later initiative if v13 needs Suricata-sourced evidence
at all — not connected to `sources.py`'s current Zeek-tailing scope. The
`SuricataSignatureHypothesis` (`hypotheses/engine.py`, already ported and
tested) simply receives no evidence from this path today; it isn't broken,
it's unfed.

### A7. ~~v13 never computed a DECISION, only evidence~~ — DONE (2026-09-06)
**Resolved**: found while starting to build the automated flip monitor
(`gap_monitor.py`) — its whole premise is evaluating DIVERGENCE between v13's
decisions and v-current's, but until now nothing on `.19` ever computed a v13
decision at all; `run_detection_cycle()` only ever produced and stored
evidence. `src/v13/ingest/sources.py` gained `compute_decision()`, wiring
v13's own already-built `HypothesisEngine`/`DecisionEngine` (Phase 3) against
a fresh `RollingWindowView` query of the device's accumulated graph evidence,
classifying a representative destination via v-current's real
`ReputationClassifier` (reused unchanged — real tiers 0-3 from static
known-domain/ASN lists, but never 4/5, since no live VirusTotal/AbuseIPDB/
ThreatIntel API scoring is wired on `.19`, a real bounded limitation, not fake
data). `GraphStore` gained `insert_decision()`, writing to schema.sql's
already-designed-but-previously-unused `decisions` table. Wired into
`daemon.py`'s `_run_cycle()` with a dedup guard (`only_persist_if_changed_from`)
so a device's unchanging verdict isn't re-persisted every 2-second poll
forever — only a genuine state transition writes a new row, matching this
codebase's own "don't re-alert on unchanged state" discipline. 24 new tests
(8 in `test_v13_graph_store.py`, 9 in `test_v13_ingest_sources.py` including a
spy-based check that the correct destination gets classified, 3 in
`test_v13_ingest_daemon.py` including the dedup behavior end-to-end). All 15+
v13 test files re-confirmed passing.

### A8. ~~`divergence_log.py` (the comparator) is not built~~ — DONE (2026-09-06)
**Resolved**: a fourth read-only Samba share (`v13-alerts`) was added on
`.94`, exposing a NARROW export directory (a hardlink to `state/alerts.json`
only, NOT the whole `state/` tree — which also holds trust caches and
reactive-capture data this comparator has no need for and shouldn't be
exposed to). Required one small permission fix found live: `/home/<deploy-
user>` itself was `750` (no traverse for other users) — the other three
shares' paths sit under world-traversable system directories
(`/opt/`, `/var/log/`) so this gap was never hit before; fixed with a
minimal `chmod o+x` (traverse-only, not list) on that one directory, not a
broader permission change. Mounted read-only on `.19` at `/mnt/v13-alerts`
via the same `fstab`/`x-systemd.automount` pattern as the other three shares.

`src/v13/compare/divergence_log.py` — built. `AlertsJsonlTailer` tails the
100MB+, continuously-growing `alerts.json` incrementally (same cursor
algorithm as `ZeekLogSource`/`PiHoleLogSource`, an independent third copy,
not shared code — a deliberate scope trim given this session's time
constraints). `compare_window()` correlates by device IP (v-current's real
`device.ip` field vs. v13's own `device_id`, which — a real, flagged
limitation — is the raw source IP in the current daemon wiring, not routed
through `identity/resolver.py`'s stable-hash device_id) within a
`TOLERANCE_SECONDS=300` window, classifying each pairing as `AGREE` (same
decision_path), `DIFFERENT_PATH` (both flagged, disagreed on what),
`VCURRENT_ONLY` (v-current alerted, v13 either called it benign nearby or
never evaluated it at all — the two are distinguished via
`v13_evaluated_but_benign`), or `V13_ONLY` (v13 flagged, no v-current alert
nearby). A v13 BENIGN decision with nothing to compare against correctly
produces NO divergence record at all — confirmed via direct test, not
assumed. Divergences append to a JSONL file, matching the plan's own stated
design (`state/v13_divergence.jsonl`).

**25 new tests** (`tests/test_v13_divergence_log.py`) cover the tailer's
cursor/rotation/partial-line behavior, field extraction from a real alert
record's confirmed shape, the full classification matrix including tolerance-
window edges (an alert just outside tolerance correctly produces TWO
independent unmatched records, one per side — not a bug, both signals
genuinely missed each other), and `run_comparison()`'s end-to-end wiring.
`GraphStore` gained `get_decisions_since()` (8 more tests in
`test_v13_graph_store.py`) as this module's read side into v13's own
decisions table.

### A9. ~~The automated flip monitor's PRODUCTION-EDITING step needs re-confirmation~~ — RE-CONFIRMED (2026-09-06)
**Resolved**: explicitly asked the user, given the architecture change this
session discovered (v13 runs as a fully independent process on `.19`, not an
in-process shadow hook inside `.94`'s `pipeline.py` as the plan originally
envisioned) — **the user re-confirmed "keep fully automatic"**: `gap_monitor.py`
still edits `.94`'s `config.yaml` and restarts `soc.service` on its own once a
mechanism clears its documented bar, notifying only after the fact, with no
per-flip human approval. This stands as a deliberate, informed decision made
WITH knowledge of the architecture change, not a holdover from before it was
discovered — recorded here so a future session doesn't need to re-litigate
it, and doesn't mistake it for an unexamined default either. The hard safety
vetoes from the original plan (regression suite must pass, zero
false-negative-shaped divergence, no auto-decision on a genuinely novel case)
remain non-negotiable regardless of this choice — they were never part of
what "fully automatic" was asking to relax.

### A10. ~~`.94`'s live `pipeline.py` had ZERO hooks for anything v13-related~~ — FIRST MECHANISM WIRED (2026-09-06)
**What was found**: even with A7 (real v13 decisions) and A8 (a real comparator)
both done, `gap_monitor.py`'s whole premise — flip a `v13_flags.<mechanism>`
config value and have `.94`'s live code behave differently — had nothing to
attach to. Confirmed via direct grep: `.94`'s real `pipeline.py`,
`decision_engine.py`, and `config.yaml.example` contained zero references to
`v13` or any `v13_flags` value. v13 on `.19` running as an independent
process (A2-A9) generates excellent COMPARISON data, but was never wired as
an in-process shadow-then-live branch inside `.94`'s own decision code the
way the original plan's "Automated incremental flips" section actually
described. Auto-editing `.94`'s config (A9) would have been a complete
no-op without this.
**Resolved (first mechanism only)**: user chose hypothesis independence-
family scoring (lowest-risk: a pure scoring refinement, doesn't touch
hard-stops or actuation) as the first real mechanism wired into `.94`'s live
`decision_engine.py`/`pipeline.py`, as a genuine, PURELY ADDITIVE shadow
computation — the live decision path is completely unchanged; new
`v13_state`/`v13_explanation`/`v13_decision_path`/`v13_independence_changed`
fields are computed alongside it and logged (only on divergence) to a new
`state/v13_independence_divergences.jsonl`, mirroring the existing Gap-1/2/3
shadow pattern already established in this exact file (separate log file so
it doesn't interleave with that unrelated experiment). `v13_flags`-based
live-flipping is NOT built yet — this step only gets the mechanism computing
and logging real shadow data, matching how every prior Gap in this project
started (shadow first, flip only after real accumulated evidence).
**Design decision, documented not improvised**: rather than re-deriving the
live tree's full elif priority order a second time (risking silent drift
from the real branch order, the exact failure mode the existing Gap-3 shadow
block's own comment warns against), the new shadow re-evaluation is keyed
off the ALREADY-COMPUTED `decision_path`/`explanation` (which already
correctly encode which branch fired, accounting for every higher-priority
hard-stop) — provably safe by construction, not by careful hand-matching.
**Verified**: a real, working divergence demonstrated on a realistic
scenario — two evidence items (`malicious_ja3` + `zeek_notice`) that
v-current's `ATTACK_EVIDENCE_FAMILIES` groups under one shared
`"zeek_network"` family (1 independent source, capped at SUSPICIOUS) but
v13's `INDEPENDENCE_FAMILY_MAP` correctly treats as 2 separate families
(clearing the `>=2` HIGH bar) — exactly the real-world shape issue #7 was
about. 20 new tests (`tests/test_phase68_v13_independence_shadow.py`) plus 4
existing, unrelated `.94` test files re-run for regression confidence
(`test_phase38_comprehensive_scenarios.py`'s own corroboration golden case,
`test_phase34_evidence_families_and_incidents.py`,
`test_phase54_g6_geofence_and_g7_hypothesis_naming.py`,
`test_phase42_tier5_verified_ioc_split.py`) — all pass, zero regressions.
**When to pick this back up**: after real shadow-divergence data has
accumulated on `.94` (same "N days, zero false negatives" evidentiary bar
this project has used for every prior flip), decide whether to flip this
mechanism live via an actual `v13_flags` config read — not built yet, and a
separate step from `gap_monitor.py`'s own automation, which still needs to
exist to make that flip itself automatic per A9.
**Deployment status (2026-09-06): LIVE on `.94`**. Code pushed, pulled, and
syntax-validated via the existing deploy pipeline (commit `84d82f3`), then
`soc.service` restarted by explicit user instruction (new PID confirmed,
clean startup journal — no errors traceable to this change; two unrelated,
pre-existing external-API rate-limit warnings from AbuseIPDB/VirusTotal are
routine and not caused by this work). The shadow computation now runs
unconditionally on every real decision cycle. `state/v13_independence_
divergences.jsonl` doesn't exist yet as of the restart — same lazy-create
behavior as the existing `shadow_decisions.jsonl` (only created on the FIRST
actual divergence, not proactively) — absence just means no divergence has
occurred in the first ~90s of runtime, not that anything is broken.

### A4. ~~No auto-deploy mechanism exists between the NAS repo and either box~~ — DONE (2026-09-05)
**Resolved**: the design evolved from "NAS → .94/.19" to "GitHub → .94/.19" once
this session found `.94`'s deployed directory was never a git repo at all (pure
`scp` historically) and this repo's only real remote is GitHub — a dedicated,
repo-scoped, read-only Deploy Key was set up per box (`.94`, `.19`), each with
its own separate keypair (a compromise of one can't affect the other). Both
boxes now `git fetch`/pull on a 15-minute cron. `.19` (nothing live to protect
yet) runs the full v13 test suite after every pull and auto-rolls-back on
failure. `.94` (production) syncs ONLY code directories (`src/`, `tests/`,
`Documentation/`, `zeek_scripts/`, `tools/`) — never `config.yaml`, `.env`,
`state/`, `models/`, or anything else runtime-specific — backs up first,
validates every `.py` file's syntax, rolls back on any failure, and
**deliberately never restarts `soc.service` automatically** (a live security
service restart is a materially different risk than a disk sync while the
process keeps running unaffected; that stays a separate, explicit human
action). Verified end-to-end: `soc.service` confirmed still active and
unaffected after the first real sync; the full v13 test suite passes in both
`.94`'s and `.19`'s own Python environments (3.12.3 on `.19`), not just
locally.

---

## Group B — Real correctness/design questions the parallel run itself should answer

Not blockers to *starting* Phase 7 — these are exactly what real divergence data
is supposed to resolve, and trying to guess the answer now would just be more
untested assumption-stacking.

### B1. `INDEPENDENCE_FAMILY_MAP` vs v-current's `EVIDENCE_FAMILIES` disagree
**What**: v13 splits JA3/JA4 + `zeek_notice` + exfiltration + beaconing into
three independence families; v-current groups them all into one (`zeek_network`).
Also, v13's `dns_behavior` bucket is coarser than v-current's own three-way DNS
split (`dns_behavior`/`dns_tunnel_v2`/`blindspot_audit`).
**Why it's open**: both are one-time judgment calls, neither empirically
validated at this granularity. Documented explicitly in
`src/v13/hypotheses/independence.py`'s own docstring, not silently picked.
**When**: Phase 7's divergence analysis should specifically flag any case where
this family-split disagreement is the ROOT CAUSE of a different verdict (not
just note "diverged") — that's the signal that would actually settle which
grouping predicts real outcomes better. No action needed before then.

### B2. Triage specificity is unsolved (recall is fine, filtering value is ~zero)
**What**: the local triage model flags nearly every routine case as needing
review too (0-1/5 in this session's spike) — safe, but provides no real
traffic-reduction benefit yet.
**Why it's open**: explicitly deferred by the user (2026-09-05) as an acceptable
interim state — "safe but not efficient" is still strictly better than no local
triage at all.
**When**: worth revisiting once there's a reason to care about local-Ollama call
volume specifically (e.g. once `.19`'s own Ollama, or a real Pi's, is under real
load) — prompt/calibration tuning against a broader set of real routine examples
(not just 5 constructed ones) is the natural next step, not attempted yet.

### B3. Production `llama3.1`'s placeholder-echo bug is still unconfirmed
**What**: whether v-current's actual production model has the same
`"benign|malicious"`-literal bug the small local models showed in Round 1 was
never confirmed — the test was aborted mid-run to protect production (see the
dependency map's incident note).
**Why it's open**: user's explicit decision (2026-09-05) — confirm safely later
rather than risk a repeat of the contention incident.
**When**: in a genuinely quiet window (no `ollama_soc.py` run active), one
request at a time, verifying server-side completion (not just client-side
"done") before sending the next. The proposed fix (real JSON-schema `format` in
`ollama_soc.py`'s `_query_ollama()`) is considered beneficial regardless of this
test's outcome, per the dependency map — applying it doesn't strictly need to
wait for this confirmation, but the user chose to sequence it that way.

---

## Group C — Deliberate CL-AFPE scope cuts (Phase 4)

All four exist in v-current's `fp_engine.py` and were explicitly NOT ported —
each is its own separate subsystem, not a small addition.

### C1. Per-device threshold bumping for `CONNECTION_ABUSE` corrections
**What**: v-current raises a specific device's own arp-sweep/long-conn/
rejected-connection thresholds when an operator corrects a `CONNECTION_ABUSE`
alert. v13's `mark_false_positive()` falls through to generic domain/IP
immunization instead for this signature family — a real, acknowledged behavior
gap, not equivalent.
**Why it's open**: depends on a whole separate per-device-profile subsystem
(`apply_device_fp_profile`, `get_device_*_threshold`) never researched for v13.
**When**: before CL-AFPE v13 can claim real parity with v-current for this
correction path — not needed for the parallel run's core hypothesis/decision
comparison, since this only affects the CORRECTION path, not the initial
detection/scoring logic being compared.

### C2. Local confirmed-intel poisoning protection
**What**: v-current's `local_intel.py` integration, plus the live-audit-derived
exclusions (safe_ips, cloud/CDN-owned IPs, known public DNS resolvers) that keep
a shared "confirmed malicious" store from getting poisoned by routine gateway/
multicast/CDN traffic.
**Why it's open**: its own store + protection-logic subsystem, not a small
addition; discovering v-current's own poisoning bugs (822 confirmations against
the IDS's own IP, etc.) took real live-audit work this codebase already did once
— re-deriving it for v13 needs the same care, not a quick port.
**When**: before `check_local_intel_history` (Group D below) can be un-deferred,
and before CL-AFPE v13 supports genuine cross-device IOC confirmation at all.

### C3. Sigma-shift EWMA widening
**What**: `_apply_sigma_shift()` widens a device's own EWMA anomaly-detection
threshold after a confirmed false positive, so the same benign pattern doesn't
keep re-triggering.
**Why it's open**: **unverified open question, not a confirmed gap** — this
session found `mitigation/scoring.py` (the original EWMA-based `RiskScorer`)
is dead code, unused by the live pipeline (`hypotheses/engine.py`'s own Phase 1
comment says so directly). Whether `threat_signals.py`'s actual live detectors
still consult sigma-shift for their own thresholds, or whether that mechanism
is now vestigial too, was **not verified this session** — `threat_signals.py`
itself was never read. Don't assume either answer.
**When**: read `threat_signals.py` directly before deciding whether this is a
real port target or dead weight not worth carrying into v13 at all.

### C4. ML model (LightGBM/FastEmbed) training/inference + training write-back
**What**: v-current's Stage 2/3 statistical classifier and its training-data
feedback loop (`autonomous_muted.jsonl` → `train_fp_classifier.py`).
**Why it's open**: a full separate ML pipeline; the parallel run's actual
purpose (comparing rule-based hypothesis/decision logic) doesn't need it to
produce useful comparison data.
**When**: a distinct, later initiative if a v13-native ML classifier is ever
wanted — not connected to closing out Phases 1-6's own scope.

---

## Group D — Deliberate LLM-review scope cuts (Phase 5)

### D1. Persistent caching (`_persistent_cache_key`/`ollama_analysis_cache.json`)
**Why it's open**: an efficiency/cost concern (avoid re-querying Ollama for
unchanged patterns), not a correctness concern.
**When**: before any real production-scale use — re-querying Ollama on every
single cycle for a repeating pattern would be wasteful and slow, especially
against `.19`'s own resource-capped local model. Not needed for small-scale
parallel-run testing.

### D2. Alert grouping/dedup logic
**Why it's open**: v-current groups near-duplicate alerts (e.g. persistence-
timer variants of the same finding) before ever calling the LLM, to avoid
redundant calls. v13 has no equivalent grouping step yet.
**When**: same trigger as D1 — matters once call volume matters, not before.

### D3. Campaign correlation (`_is_campaign_corroborated`)
**Why it's open**: distinguishes a genuine coordinated multi-device attack from
several devices independently tripping the same noisy signal against different,
individually-reputable destinations. Real logic, not yet ported.
**When**: needed for full LLM-review parity with v-current; not blocking a
single-device parallel-run comparison, which is the initial testing shape.

### D4. Telegram digest building
**Why it's open**: notification formatting/orchestration, deliberately left out
of the LLM-review module itself for testability (mirrors `ClAfpeEngine`'s own
"hand data back to the caller" shape).
**When**: needed once Phase 7's automated flip-monitor (`gap_monitor.py`) is
actually built — the plan already says it reuses this exact Telegram pattern,
so this and that should likely be built together, not this alone in isolation.

### D5. Per-run query-cap / rate-limiting logic
**Why it's open**: protects a shared Ollama instance from being overwhelmed by
too many alerts in one run — an operational safety valve, not core logic.
**When**: before real production-scale operation, and specifically important
for `.19`'s local Ollama given the resource constraints already documented in
Group A3 above — these two items should probably land together.

---

## Group E — Deliberate retro-hunter scope cut (Phase 6)

### E1. `check_local_intel_history()`'s cross-device IOC cross-reference
**What**: "device B also touched this IOC three days ago but wasn't over its
own detection threshold at the time" — catches a historical connection using
intel the network only learned from a DIFFERENT device's later confirmation.
**Why it's open**: depends entirely on C2 (local confirmed-intel store), which
doesn't exist in v13 yet.
**When**: strictly after C2 is built — no way to build this first.

---

## Group F — Infra/environment notes (not code, but real and easy to lose track of)

### F1. Zeek historical archives aren't reachable through the `.19` SMB mount
**What**: `/opt/zeek/logs/<date>/` archives use colon-containing rotated
filenames that SMB mangles into unreadable 8.3 short names — found and worked
around this session by mounting the live spool directly instead (which is what
actually matters for the live parallel run).
**Why it's open**: only matters for pre-live HISTORICAL Zeek replay, which
nothing currently needs (retro-hunter operates on graph-native evidence, not
raw historical Zeek logs).
**When**: only if a future need for historical Zeek replay actually arises — a
separate NFS export (no Windows-illegal-character restriction) would fix it
cleanly if that day comes. Not worth building speculatively.

### F2. `IDS_PRODUCT` GitHub repository
**What**: a new GitHub repo for the generalized product, seeded from v13 once
deployable, carrying over the existing Docker install tooling.
**Why it's open**: nothing exists to seed it with yet (v13 isn't deployed
anywhere real yet) — and publishing a new external repo needs your explicit
confirmation at the time regardless, per the plan's own stated boundary between
"fully automatic internal flips" and "an externally-visible new artifact."
**When**: once v13 reaches a genuinely deployable state — not before, and not
automatically even then.

---

## Priority summary (my read, not a decision already made)

**A4 is done** (2026-09-05) — v13 is now deployed and verified on both `.94`
(inert, alongside production, not restarted) and `.19` (its dedicated home),
with automated pull-and-verify on both going forward.

**A1 is also done** (2026-09-06) — `retro_hunter.py` now has a real
threat-intel lookup wired in via `real_threat_intel_lookup_factory()`.

**A2 is also done** (2026-09-06) — `src/v13/ingest/sources.py` built (Zeek
JSON-lines log tailing, ported cursor logic, `run_detection_cycle()`), closing
the `zeek_exfiltration`/`zeek_beaconing` destination gap using v-current's own
already-computed `last_dest_ip`. Verified with 26 unit checks plus a live
sanity check against the real, unmodified `ZeekFeatureExtractor`/
`ThreatSignalDetector` classes.

**Two new items found while building `sources.py`, both honest scope cuts, not
silent gaps**: A5 (no Pi-hole/DNS-behavior evidence yet — the FTL sqlite DB
isn't mount-accessible and wouldn't be reliable over SMB even if it were; needs
a new `pihole.log` text parser) and A6 (Suricata reactive-capture is
fundamentally not a tailable log stream in this deployment — replicating it
needs the whole burst-trigger subsystem, not a tailer).

**A3 is also done** (2026-09-06) — `src/v13/ingest/daemon.py` + the
`v13-ingest.service` systemd unit are live on `.19` right now, verified
producing real graph evidence from real production Zeek data, resource-capped
and stable.

**A5 is also done** (2026-09-06) — Pi-hole/DNS-behavior evidence
(`dns_dga_burst`, `dns_tunnel_v2`) is now genuinely produced by the live
daemon, verified end-to-end with a real DNS-tunneling-shaped query.

**A7 is also done** (2026-09-06) — v13 now computes real DECISIONS (not just
evidence) on `.19`, with a dedup guard so unchanging verdicts don't spam the
audit trail.

**A8 is also done** (2026-09-06) — the divergence comparator is built and
tested (25 checks), backed by a new, narrowly-scoped Samba share on `.94`.

**A9 is resolved** (2026-09-06) — the user explicitly re-confirmed "keep
fully automatic" for `gap_monitor.py`'s production-editing step, made with
full knowledge of the architecture change. No longer an open question.

**Comparator now runs on its own (2026-09-06)**: `src/v13/ops/run_gap_check.py`
+ a `*/15 * * * *` crontab entry on `.19` (matching `deploy_v13.sh`'s own
existing cron pattern — a plain crontab entry, not a new systemd service,
deliberately lightweight per the user's own ask) calls `run_comparison()`
automatically now, so divergence data accumulates without a manual run.
Found and fixed a real bug while building this: `AlertsJsonlTailer` only
saved its cursor lazily (inside `read_new_alerts()`, when there was
something to process) — a stateless caller that constructs a fresh tailer
every cron tick (unlike the long-lived ingest daemon, which reuses one
tailer object across every poll) could permanently miss content that
arrived between two "nothing new yet" ticks, since no baseline was ever
persisted. Fixed by saving the cursor immediately after establishing an
initial position. 9 new tests (`tests/test_v13_run_gap_check.py`); all 17
v13 test files re-confirmed passing. A live snapshot dashboard is published
at `https://claude.ai/code/artifact/a3309d23-2333-41e4-aa17-8b4cb3b38f98`
(refreshed manually on request, not auto-live).

**Next real blocker**: `src/v13/ops/gap_monitor.py` itself doesn't exist yet
— everything it needs (real decisions, a real comparator now running
automatically, an explicit answer on the automation question) is now in
place. It still needs per-mechanism BARS documented (this project's own
precedent: Gap 1/2's "N days shadow, zero divergences," Gap 3 honeypot's "58
confirmed divergences, zero false negatives") before it can evaluate
anything meaningfully — only 13 real (non-VCURRENT_ONLY) divergences have
accumulated as of this snapshot, not nearly enough volume yet to draw a
conclusion. A6 (Suricata reactive-capture) remains a larger,
separately-scoped initiative, unrelated to the flip-monitor goal.

**Everything else genuinely can wait** — either because it's what the parallel
run's own data is supposed to answer (Group B), or because it's real,
substantial, separately-scoped future work with no dependency on what's
happening right now (Groups C/D/E/F).
