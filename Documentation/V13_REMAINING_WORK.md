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

### A1. `retro_hunter.py`'s threat-intel lookup is currently a test stub
**What**: v13's `RetroHunter` takes `threat_intel_lookup` as an injected
dependency (by design, see `V13_ARCHITECTURE_DEPENDENCY_MAP.md`'s Phase 6
section) — but nothing has wired in a REAL lookup function yet (v-current's
`ThreatIntel.lookup_domain()`, URLHaus/FeodoTracker/ThreatFox/OTX).
**Why it's open**: the injection point was built deliberately so this could be
wired in later without a redesign — but "later" hasn't happened yet, so
`retro_hunter.py` currently can't produce a single real finding.
**When**: before Phase 7's parallel run is expected to produce useful
retro-hunt output — i.e., part of the initial wiring work, not after. Likely the
simplest real lookup is v-current's own `ThreatIntel` class, imported and called
directly (its own feed-refresh logic doesn't need re-implementing, just calling).

### A2. `zeek_exfiltration`/`zeek_beaconing` never carry a real destination
**What**: these two v-current detectors (`threat_signals.py:247-274`) never set
`.domain` on their `Evidence`. v13's ingest adapter (`evidence/ingest.py`) can
accept a `fallback_context` to work around this per-call, but nothing has
supplied it yet.
**Why it's open**: fixing it needs either (a) the live ingest layer
(`src/v13/ingest/sources.py`, not yet built) threading real connection-tuple
context through at the point evidence is created, or (b) fixing the two
detectors in v-current's own `threat_signals.py` (touches v-current, a separate
decision from anything in the v13 effort itself).
**When**: when `src/v13/ingest/sources.py` is built (part of Phase 7's wiring) —
that's the natural chokepoint to supply `fallback_context` for these two types
specifically. Until then, evidence from these two detectors will land in the
graph with `NO_DESTINATION`, which is a known, bounded degradation (affects only
these two evidence types' target-linkage quality), not a crash risk.

### A3. Resource isolation on `.19` doesn't exist yet
**What**: `.19` will run the full v13 parallel process AND its own dedicated
Ollama once Phase 7 starts — no CPU/memory ceilings exist between them yet.
**Why it's open**: there was no running v13 process to isolate until this
session's build finished — isolating a process that doesn't exist yet was
correctly deferred, not skipped.
**When**: at the same time v13's process is first started on `.19` (Phase 7's
own first step) — not after. A systemd resource slice or cgroup limit, sized
against `.19`'s real 31GB/8-core headroom (confirmed this session).

### A4. No auto-deploy mechanism exists between the NAS repo and either box
**What**: every file this session pushed to `.94` or `.19` went via a manual
`scp`, one file at a time. There's no mechanism for `.19` to receive the v13
codebase at all yet, let alone automatically on future changes.
**Why it's open**: this is Phase 7's own first deliverable per the plan
("Deployment automation") — it hasn't been started until now.
**When**: now — this is what "proceed to deploy" (this session) means concretely.
See the Deployment section of the plan/dependency map for the intended design
(NAS repo → `.94` auto-deploy mirroring the existing manual backup/`ast.parse`/
restart discipline; `.19` pulls the same repo, runs its own entry point).

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

**Actually blocking today's "proceed to deploy" work**: A1 (real threat-intel
lookup), A4 (the deploy mechanism itself). A2/A3 matter within Phase 7 but
slightly later in its own sequence (once ingest and the running process
respectively exist to attach them to).

**Everything else genuinely can wait** — either because it's what the parallel
run's own data is supposed to answer (Group B), or because it's real,
substantial, separately-scoped future work with no dependency on what's
happening right now (Groups C/D/E/F).
