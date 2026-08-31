# Reactive-Capture Load Analysis: Best-Case vs. Worst-Case Network Conditions

**Scope of this document**: the reactive-capture subsystem only — `ReactiveCaptureDispatcher`
and `capture_and_ingest()` in [`src/extractors/fritzbox_capture.py`](../src/extractors/fritzbox_capture.py),
the Suricata batch scan in [`src/intelligence/detectors/suricata_scan.py`](../src/intelligence/detectors/suricata_scan.py),
and the 7 trigger call sites in [`src/core/pipeline.py`](../src/core/pipeline.py) — and how that
subsystem behaves under two ends of the load spectrum. It is not a whole-codebase map.

**A note on accuracy** (matching `ENGINEERING_MANUAL.md`'s standard): every number below is
either read directly from the running config/source, or drawn from a real incident on this
deployment (2026-08-31, see §3). This is a living document — extend it if the dispatcher's
throttling logic changes.

**Trigger for this document**: `soc.service` was OOM-killed and auto-restarted on 2026-08-31
08:30:54 CEST after `soc.service`'s memory cgroup (`MemoryMax=1G`) filled during a period of
near-continuous reactive-capture activity. The immediate memory-doubling bug in pcap conversion
was already fixed (commit `8768f4a`, streaming `avm_pcap_to_standard()`). This document asks the
broader question: even with that fix, can the reactive-capture subsystem, as currently throttled,
survive a genuinely infected/actively-compromised network — not just one noisy false positive?

---

## 1. How the subsystem is throttled today

`ReactiveCaptureDispatcher` (`fritzbox_capture.py:648`) has exactly two protections:

1. **A sliding-window burst-COUNT budget** — `reactive_capture_max_bursts_per_hour` (live
   config: `6`). `_check_and_consume_budget()` (`fritzbox_capture.py:677`) resets the counter
   every 3600s and refuses a new dispatch once the count is hit.
2. **A single-burst-at-a-time lock** — `_burst_lock` (`fritzbox_capture.py:675`). A trigger that
   finds a burst already running is deferred (not queued) and its budget slot is refunded
   (`fritzbox_capture.py:726-729`), so trigger *diversity* never multiplies capture cost — one
   burst always covers whichever trigger(s) fired.

Both are sound, necessary protections. Neither bounds **how large** a burst is, **how much
subprocess memory** Zeek/Suricata use processing it, or **how little idle time** there is between
consecutive bursts when the budget is being saturated. That gap is this document's subject.

Live-config numbers used throughout (from `config.yaml` on the deployment host):

| Key | Value |
|---|---|
| `reactive_capture_max_bursts_per_hour` | 6 |
| `reactive_capture_burst_seconds` | 120.0 |
| `reactive_capture_radios` | `[ath0, ath1]` |
| `reactive_capture_snaplen` | 1600 bytes/packet |
| `reactive_capture_suricata_timeout_seconds` | 240.0 |
| `reactive_capture_delete_after_ingest` | true |
| `soc.service` `MemoryMax` | 1G |

---

## 2. Scenario A — Best case: a quiet, healthy network

**Description**: normal household traffic. Reactive-capture triggers fire rarely — an occasional
`arp_sweep` when a phone rejoins Wi-Fi, a `new_device` the first time something connects, maybe
one `dns_suspicion` blip that resolves itself. 0–2 bursts/hour is typical; long stretches with
zero bursts are normal.

**Trace through the numbers**:
- Burst size: 4–7MB per radio (observed baseline overnight before the incident, `journalctl`
  05:27–08:11 CEST) — snaplen-limited, 120s window, ordinary traffic mix.
- `avm_pcap_to_standard()` (now streaming, `fritzbox_capture.py:227`): peak memory ~O(one
  record), negligible.
- Zeek (`zeek -r`) and Suricata (`suricata -r ... --runmode=single`) each process a few MB and
  exit in seconds; well inside the 240s Suricata timeout.
- `_cleanup_burst_files()` deletes the raw/converted pcaps and Zeek scratch dir immediately after
  ingest (`reactive_capture_delete_after_ingest: true`), so disk never accumulates either.
- The unit-file's own comment (`/etc/systemd/system/soc.service`): *"MemoryMax=512M is
  generous — typical usage is 80-150MB."* Consistent with the freshly-restarted service's
  observed 80.2MB RSS.

**Verdict: handles this comfortably.** Enormous headroom between typical usage (~100MB) and the
1G ceiling. No code change needed for this scenario.

---

## 3. Scenario B — Worst case: an actively infected / multi-device-compromised network

**Description**: this is not hypothetical — it is what actually happened overnight on
2026-08-31, and it is the shape a real intrusion (or several compromised IoT devices doing
C2/beaconing/scanning/exfil simultaneously) would produce. Any combination of the pipeline's 7
independent trigger sources (`pipeline.py:526,559,604,621,997,1278,1875` — `spotcheck`,
`wired_probe`, `new_device`, `ambiguous_reidentify`, `arp_sweep`, `dns_suspicion`,
`high_severity`) can fire from different devices at once; they all share the one dispatcher.

**What actually happened, mechanically**:

1. One source (`dns_suspicion`, from a single device) fired **continuously from ~06:01 to
   08:30** — each burst re-dispatching within 1–2 seconds of the previous one completing
   (`fritzbox_capture.py:748`'s `[DEFERRED]`-free happy path: burst completes → next trigger
   already queued behind the lock → immediately acquires it → dispatches again). With
   `burst_seconds=120` plus Zeek/Suricata processing time, that's a burst roughly every
   10–15 minutes, sustained for **2.5+ hours with essentially zero idle recovery time** for the
   capture subsystem.
2. Burst size then spiked ~10x — 46–90MB per radio (vs. the 4–7MB baseline) at 08:13 and 08:24,
   consistent with a genuine traffic-volume event (real attacks routinely look like this: a scan,
   an exfil push, a burst of C2 traffic).
3. Suricata batch scans were **already timing out at 240s** on the *normal-sized* pcaps
   throughout the night (`WARNING home_ids.suricata_scan Suricata batch scan timed out after
   240s` — recurring every burst) — meaning the subsystem was already running at its processing
   ceiling before the size spike hit.
4. At 08:30:54, the memory cgroup hit exactly `1048576kB == MemoryMax`. The kernel OOM killer
   killed the main `python3` process **and** `Suricata-Main` **and** two other `python3`
   processes sharing the cgroup — i.e., the core detection/alerting pipeline died *alongside* the
   capture subsystem that caused the pressure, not independently of it.

**Concrete worst-case math** (budget-bound, ignoring Zeek/Suricata's own multiplier):

```
6 bursts/hour (budget ceiling) × 2 radios × up to ~90MB/radio (observed real spike)
  = up to ~1.08 GB of raw pcap captured in a single hour
  — before Zeek's parse-and-log memory or Suricata's flow-tracking/stream-reassembly
    memory (neither of which has any configured ceiling) is added on top.
```

The count-based budget (`max_bursts_per_hour`) bounds *how often* a burst can start; it does
**not** bound *how large* a burst is, so it does not bound aggregate bytes/CPU/memory per hour —
that scales with whatever the network is actually doing, unconstrained.

**Verdict: cannot fully handle sustained worst-case load, empirically confirmed** — this is the
literal incident that took `soc.service` down. The two existing protections (count budget,
single-flight lock) are necessary but not sufficient once (a) one source retriggers with no idle
gap for hours, and/or (b) burst sizes scale up with genuinely elevated traffic. Both conditions
are exactly what a real infection produces, not edge cases.

---

## 4. Root-cause gap analysis

| # | Gap | Where | Consequence under worst-case load |
|---|---|---|---|
| 1 | Budget is a burst **count**, not a **bytes/CPU** budget | `_check_and_consume_budget()`, `fritzbox_capture.py:677` | 6 legitimate max-size bursts/hour can still saturate memory; count alone can't prevent it |
| 2 | No per-`(device, trigger_reason)` diminishing-returns backoff | `try_dispatch()`, `fritzbox_capture.py:694` | A single repeatedly-firing source (false positive *or* a static/repetitive real infection) monopolizes the shared budget indefinitely — every other device's triggers get starved out too |
| 3 | No memory ceiling on the Zeek/Suricata **subprocesses** themselves | `reprocess_with_zeek()` `fritzbox_capture.py:277`, `run_suricata_on_pcap()` `suricata_scan.py:56` | `subprocess.run(...)` sets no `resource.setrlimit`/ulimit; a large or adversarially-crafted pcap can drive either subprocess's memory arbitrarily high, invisible to the dispatcher's own bookkeeping |
| 4 | Capture subsystem and the core detection/alerting loop **share one cgroup** (`soc.service`, `MemoryMax=1G`) | `/etc/systemd/system/soc.service` | When the bursty subsystem causes an OOM, the kernel kills whatever's in the same cgroup — which took out the core pipeline too, i.e. detection/alerting went down exactly when a real incident would need it most |
| 5 | Deferred (lock-contended) triggers aren't queued, only retried on the next pipeline cycle | `try_dispatch()`, `fritzbox_capture.py:718-730` | Not a memory driver by itself (cheap lock check), but produces the dozens-of-`[DEFERRED]`-lines/minute log pattern seen overnight — a symptom worth recognizing, not a separate root cause |

Already shipped, reduces but does not close the gap: streaming `avm_pcap_to_standard()`
(commit `8768f4a`) cut the *conversion-phase* peak from ~2x pcap size to ~O(one record). It does
nothing for gaps 1–4 above, since Zeek/Suricata's own memory use and the lack of any
bytes/backoff/isolation ceiling are untouched by it.

---

## 5. Recommended fix, prioritized

| Priority | Fix | Closes gap(s) | Effort | Notes |
|---|---|---|---|---|
| 1 | **Aggregate bytes-captured-per-hour budget**, alongside the existing count budget | 1 | Low — one counter + one config key in the same dispatcher | Directly caps worst-case memory regardless of how many devices are legitimately misbehaving at once |
| 2 | **Evidence-based per-`(device, trigger_reason)` backoff**: track consecutive "no new finding" bursts per source; extend that source's cooldown exponentially; reset instantly on any new finding | 2 | Medium — new small state dict in the dispatcher, keyed off what `capture_and_ingest()` already returns (`dns_evasion_findings`/`suricata_findings` counts) | Directly targets "fires every time" from one source without needing a human to hand-tune an exemption; a genuinely escalating attack (new findings each burst) keeps full cadence |
| 3 | **Subprocess memory ceiling** on the Zeek and Suricata `subprocess.run()` calls via `resource.setrlimit(RLIMIT_AS, ...)` in a `preexec_fn` (or `systemd-run --scope -p MemoryMax=...` wrapping) | 3 | Low-medium | Defense in depth: bounds the one thing that scales with pcap size that nothing else in this list bounds directly |
| 4 | **Split reactive-capture (and its Zeek/Suricata children) into its own systemd unit/cgroup**, separate from the core pipeline's `soc.service` | 4 | High — new unit file, IPC/handoff between units, deploy-topology change | Highest-impact fix for the worst-case *consequence*: a runaway capture subsystem gets killed and restarted in isolation instead of taking the detection/alerting loop down with it. This is the fix that would have kept the core pipeline alive through last night's incident even if nothing else changed. |

**Suggested rollout order**: #1 and #2 are both pure, low-risk code changes inside
`fritzbox_capture.py` that directly address the observed incident and can ship together. #3 is a
cheap, independent addition. #4 is the architecturally "correct" fix for blast-radius but is a
real infra change (new unit, systemd dependencies, redeploy) — worth doing, but as a deliberate
follow-up once #1/#2 are proven in production, not bundled into the same change.

**Status (2026-08-31)**:

- **Fix #1 — shipped.** `ReactiveCaptureDispatcher` now tracks aggregate bytes captured in the
  same rolling hourly window as the burst-count budget (`_bytes_captured`,
  `fritzbox_capture.py:670-684`), gated by a new `reactive_capture_max_bytes_per_hour` config key
  (default 500,000,000 — see `config.yaml`/`config.yaml.example`). A dispatch that would push the
  window over budget is deferred exactly like a count-exhaustion, logged/metriced distinctly
  (`outcome=deferred_bytes_budget` on `home_ids_reactive_capture_bursts_total`). Covered by 10 new
  checks in `tests/test_phase25_reactive_capture_triggers.py` (Sections A2/B3); full file (50+
  checks) passes clean.

- **Fix #2 — deliberately NOT implemented.** While wiring this up, two separate comments were
  found documenting an explicit prior operator decision this fix would reverse:
  `pipeline.py:1270-1274` ("a shared hourly budget (not per-source cooldowns) is what actually
  controls capture cost, not how eagerly any one source fires") and
  `config.yaml`/`config.yaml.example`'s per-trigger-enable-flags comment ("All default on, per
  explicit operator direction ('more trigger rather than conservative')"). Presented to the
  operator directly; the decision was to keep that design intact and rely on fix #1 (plus #3/#4
  below) instead of adding per-source cooldowns. Left un-implemented on purpose — do not
  re-propose without re-confirming this decision has changed.

- **Fix #3 — shipped, then found broken on the first real burst, corrected same-day.** Wired
  `utils.py`'s `memory_limited_preexec_fn()` (RLIMIT_AS via `preexec_fn`) into
  `reprocess_with_zeek()` and `run_suricata_on_pcap()`, deployed with both limits defaulted to
  512MB. The generic mechanism was live-verified working beforehand (a forced 200MB Python
  allocation under a 20MB limit failed correctly; the same allocation under 1GB succeeded) — but
  that test used a trivial single-threaded Python allocation, not the real target binaries. **The
  first real post-deploy burst (13:14:05 CEST) failed Zeek reprocessing on both radios**: `zeek -r
  exited -6 ... terminate called after throwing an instance of 'std::system_error' ... Resource
  temporarily unavailable`. Root cause: `RLIMIT_AS` bounds the process's total *reserved* virtual
  address space, not its actual resident memory use — Zeek (multi-threaded C++: thread stacks,
  shared-library mappings, internal arena reservations) reserves address space well beyond what it
  actually touches, so a limit that would comfortably cover real RSS usage can still abort the
  process outright. This is a known-bad fit for RLIMIT_AS against multi-threaded C/C++ binaries
  generally, not something specific to this deployment's Zeek build.

  **Impact window**: every burst between the 13:11:15 restart and the 13:15:36 config-hot-reload
  fix produced zero Zeek/DNS-evasion/Suricata findings (Zeek failed before Suricata got a turn) —
  non-fatal to `soc.service` itself (both call sites already treat a killed child as a logged,
  non-fatal "no findings" outcome, exactly as designed), but a real functional regression: reactive
  capture was silently producing nothing for ~4 minutes of live production traffic.

  **Correction, same session**: both `reactive_capture_zeek_memory_limit_mb` and
  `reactive_capture_suricata_memory_limit_mb` set to `0` (disabled) on the live `config.yaml`
  immediately upon discovery — `[LIVE]`, picked up via the existing config-hot-reload mechanism
  within ~1 minute, no restart needed. Verified via a burst dispatched entirely after the reload
  landed that Zeek reprocessing succeeds again with the limit disabled. The **shipped default was
  changed from 512 to 0** in both `config.yaml`/`config.yaml.example` and in
  `capture_and_ingest()`'s own fallback (`config.get("reactive_capture_..._memory_limit_mb", 0)`,
  `fritzbox_capture.py:555-556`) — so a config missing the key entirely also defaults safe, not to
  the confirmed-bad 512. The mechanism itself (`memory_limited_preexec_fn()`, the two call-site
  wirings, the config keys) is left in place, off by default, documented as "known-bad at 512MB,
  re-tune empirically or prefer §8's cgroup approach instead" rather than removed outright — the
  plumbing is correct, only the specific numeric default was wrong.

  **Lesson for fix #4**: this is direct, live evidence *for* preferring the cgroup-based approach
  (§8, Option B) over RLIMIT_AS for these two specific processes — a cgroup's `MemoryMax` bounds
  actual RSS+page-cache, not reserved address space, and would not have this false-trip mode
  against Zeek's normal startup footprint. Fix #4 remains unimplemented (permission model
  unverified from `soc.service`'s own runtime context, per §8 step 1) — this incident raises its
  priority relative to re-tuning RLIMIT_AS numbers by trial and error.

---

## 6. Open question for the operator

None of the above changes the geofencing-exemption work already shipped in the same commit
(`geofencing_exempt_ips`, `config.yaml:401`) — that addressed one specific low-value repeat
trigger (`185.209.85.151`/AS57578). Fix #2 above (evidence-based backoff) would have throttled
that same repeat trigger automatically, without needing an IP-specific exemption at all — the two
are complementary, not redundant: the exemption is for "I've vetted this specific destination and
it's not a threat," while the backoff is for "this source keeps re-triggering without telling us
anything new, regardless of what it turns out to be." (Fix #2 was ultimately not implemented —
see §5's status note — so this remains a real open gap: a repeat trigger's only mitigation today
is an individually-vetted `geofencing_exempt_ips` entry, or the aggregate-bytes budget in fix #1
kicking in as a side effect once enough bytes accumulate.)

---

## 7. Implementation plan — fix #3 (subprocess memory ceiling)

**Goal**: bound the memory `zeek -r` and `suricata -r` can use, independent of and in addition to
fix #1's bytes budget — defense in depth against the one thing that scales with capture size that
nothing else here bounds directly (a pathological pcap could in principle drive either tool's
internal memory use out of proportion to its file size — flow-table/stream-reassembly cost isn't
strictly linear in bytes).

**Mechanism**: Linux `RLIMIT_AS` (virtual address-space limit) applied to the child process via
`subprocess.run(..., preexec_fn=...)`, using Python's `resource` module. This is POSIX-only
(fine — the deployment target is Linux; the wrapper should no-op, not error, on any platform
where `resource.RLIMIT_AS` isn't available, so local dev on non-Linux keeps working unmodified).

**Steps**:

1. Add a small shared helper — likely in `fritzbox_capture.py` near the other subprocess-running
   code, or in `utils.py` if it's meant to be reused elsewhere:
   ```python
   def _memory_limited_preexec(limit_bytes: int):
       def _set_limit():
           import resource
           resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
       return _set_limit
   ```
   Guard the import/usage: if `resource` isn't importable (non-POSIX) or `limit_bytes <= 0`
   (feature disabled), skip `preexec_fn` entirely rather than passing a no-op — cleanest way to
   keep behavior identical to today when the feature is off.

2. Wire it into `reprocess_with_zeek()`'s `subprocess.run([...])` call
   (`fritzbox_capture.py:306-312`) via a new `reactive_capture_zeek_memory_limit_mb` config key.

3. Wire it into `run_suricata_on_pcap()`'s `subprocess.run([...])` call
   (`suricata_scan.py:76-78`) via a new `reactive_capture_suricata_memory_limit_mb` config key.

4. **Failure-path check (important, not just wiring)**: confirm both call sites already treat a
   killed/failed child as non-fatal — they do. `reprocess_with_zeek()` raises
   `FritzboxCaptureError` on non-zero exit, which `capture_and_ingest()`'s per-radio try/except
   already catches and logs as `errors.append(...)`/`reactive_capture_errors_total` (non-fatal to
   the rest of the burst). `run_suricata_on_pcap()` already treats non-zero exit as "no findings,"
   logged. An `RLIMIT_AS` kill manifests as a non-zero/signal exit, which both paths already
   handle — no new exception-handling code needed, only verify with a real forced-limit test
   (below) that this holds in practice, not just in theory.

5. **Sizing the defaults**: since `_burst_lock` guarantees only one burst runs at a time, and
   within a burst Zeek and Suricata run sequentially per radio (never concurrently with each
   other), the two limits are never both "in use" simultaneously — size each with the OTHER not
   running. Suggest starting both around 400-512MB (headroom above the largest real captures seen
   in the incident, well under `soc.service`'s 1G ceiling when added to the ~100-150MB baseline
   the rest of the process uses) and tuning down after watching real `reactive_capture_errors_total{stage="zeek_reprocess"|"suricata_scan"}` behavior in production.

6. **Test coverage**: add to `tests/test_phase23_fritzbox_capture.py` (which already covers
   `reprocess_with_zeek()`) or a new small section — the real assertion worth writing is "a
   process launched with a very small RLIMIT_AS actually gets killed/fails," which can be proven
   without a real Zeek/Suricata binary by pointing the wrapper at a trivial Python subprocess that
   deliberately allocates past the limit (`python3 -c "bytearray(50_000_000)"` under a 10MB
   limit) and asserting a non-zero/signal exit — proves the mechanism itself works, independent of
   Zeek/Suricata's own behavior.

**Effort**: low-medium. Two call sites, one shared helper, two config keys, no architecture
change. **Risk**: low — the failure paths it exercises already exist and are already exercised by
today's timeout-based failures.

---

## 8. Implementation plan — fix #4 (isolate the capture subsystem from the core pipeline)

**Goal**: make it impossible for a runaway reactive-capture burst (or its Zeek/Suricata children)
to OOM-kill the core detection/alerting loop — the thing that most needs to stay up during a real
incident. Two architecturally different ways to get there; recommend Option B.

### Option A — Separate systemd service, IPC back to the main pipeline

Move `capture_and_ingest()`'s whole pipeline (auth, capture, AVM conversion, Zeek, Suricata,
dns-evasion audit) into its own process (`soc-reactive-capture.service`), with its own
`MemoryMax` in its own cgroup.

**Why this is the harder path**: `capture_and_ingest()` currently calls `zeek_fx.ingest()`
directly against the SAME live `ZeekFeatureExtractor` instance the main pipeline reads every
cycle — this in-process sharing is explicitly the point (`fritzbox_capture.py`'s module
docstring: *"so on the very next pipeline cycle, whichever devices had traffic during the burst
window have real zeek_lateral_moves/zeek_ja3_malicious/... features, exactly as if a wired Zeek
tap had seen them the whole time"*). A separate process can't share that Python object directly —
it would need:
- A local IPC channel (Unix domain socket, or a small append-only file the main process tails)
  carrying either raw parsed Zeek-log events or the already-built `dns_evasion_findings`/
  `suricata_findings` evidence.
- A reader loop added to `pipeline.py`'s main cycle to drain and `ingest()` that channel.
- Handling for the reactive-capture process being down/crashed/restarting without stalling or
  crashing the main pipeline.
- Re-threading `state_manager`/`evidence_store` access, which today are also passed in-process
  (`run_dns_evasion_audit()` calls `state_manager.lock_device()` directly) — these would need
  their own IPC path or the audit logic would need to move to the main-process side entirely,
  with the separate service responsible only for capture+conversion+Zeek+Suricata, handing back
  raw events for the main process to run `run_dns_evasion_audit()`/`suricata_alerts_to_evidence()`
  itself.

This is a genuine redesign of a working, live-verified data path, not a small patch. Real risk of
introducing a NEW class of bug (message loss, ordering, stale-reader) to fix a resource-isolation
problem that doesn't require touching that data path at all — see Option B.

### Option B (recommended) — Keep the pipeline in-process; isolate only the Zeek/Suricata child processes into their own transient cgroup scope

Leave `capture_and_ingest()` exactly where it is (still in-process with `soc.service`, still
calling `zeek_fx.ingest()` directly — zero change to the data path that already works). Change
only *how* the two actual heavy subprocesses are launched: instead of a plain
`subprocess.run([zeek_bin, ...])` / `subprocess.run([suricata_bin, ...])`, wrap the command with
`systemd-run --scope -p MemoryMax=<limit> --collect -- <original command>` (or
`systemd-run --user --scope ...` depending on how `soc.service` is set up to run). Each invocation
gets its own transient cgroup with its own memory ceiling; if it blows past that ceiling, only
that transient scope is OOM-killed — `soc.service`'s own cgroup and the Python process inside it
are untouched, because they were never part of that scope.

**Why this is the smaller, lower-risk path to the same practical outcome**:
- No IPC, no message format, no reader loop, no re-architecture of a working data path.
- The change is localized to the two `subprocess.run([...])` call sites
  (`fritzbox_capture.py:306-312`, `suricata_scan.py:76-78`) — wrap the command list, same
  `capture_output`/`timeout`/`check` semantics as today.
- Largely overlaps with fix #3 in the specific failure mode it prevents (an oversized
  Zeek/Suricata memory footprint) but is a stronger guarantee: fix #3's `RLIMIT_AS` still charges
  the child's memory against `soc.service`'s own cgroup up until the limit trips; a `systemd-run
  --scope` child's memory is charged against its OWN cgroup from byte one, never touching
  `soc.service`'s ceiling at all. Fix #3 is worth having regardless (belt-and-suspenders, and
  useful even where `systemd-run` isn't available/permitted), but #4-Option-B is the one that
  actually satisfies this document's stated goal ("core pipeline never goes down because of the
  capture subsystem").

**Steps**:

1. Confirm the `soc` service account (or whichever user `soc.service` runs as) has permission to
   create transient scopes via `systemd-run` — typically needs either running as a user with a
   logind session/lingering enabled (`loginctl enable-linger`) for `--user` scopes, or appropriate
   polkit/D-Bus permissions for system-level transient units.

   **Checked directly on the deployment host (2026-08-31)**: `soc.service` runs as an unprivileged
   service account (uid 1000, not root; confirmed via
   `ps -o user= -p $(systemctl show -p MainPID --value soc.service)`).
   - `systemd-run --scope --collect -p MemoryMax=50M -- true` (system-level transient unit) —
     **fails**: `Access denied as the requested operation requires interactive authentication.`
     Expected; a system service has no interactive polkit prompt to satisfy this at runtime, so
     the system-level scope path is a dead end as-is (would need a polkit rule pre-authorizing
     this specific action for that account, unverified whether that's acceptable on this host).
   - `systemd-run --user --scope --collect -p MemoryMax=50M -- true` — **succeeds** (real
     transient scope created, exit 0) when run interactively over an SSH session as that account.
     However: `loginctl show-user <user> -p Linger` returns `Linger=no`, meaning there is no
     guarantee that account's systemd `--user` instance (and its `XDG_RUNTIME_DIR`/D-Bus session)
     is even running when `soc.service` itself starts — e.g. after a cold boot with no interactive
     login, `soc.service` starting at boot via its `enabled` preset would very plausibly hit the
     same failure a fresh non-interactive context would, not the success seen in this interactive
     test. **This is not yet proven to work from soc.service's own actual runtime context** — the
     interactive success above is encouraging but not sufficient evidence.
   - **Before implementing Option B for real**: either (a) `loginctl enable-linger <user>` and
     re-verify `systemd-run --user --scope` succeeds from a call made by `soc.service` itself
     (not an interactive shell) after a full reboot, or (b) get a polkit rule in place for the
     system-level path and re-test that instead. Do not assume either works from inside
     `soc.service` until re-verified in that exact context — if neither is viable,
     `subprocess.run` should fall back to the unwrapped command (log a warning once, not
     per-burst) rather than failing bursts outright.
2. Add a small helper that builds the wrapped command list, e.g.:
   ```python
   def _isolated_cmd(cmd: List[str], memory_limit_mb: int, unit_name: str) -> List[str]:
       if memory_limit_mb <= 0:
           return cmd
       return ["systemd-run", "--scope", "--collect", "--unit", unit_name,
               "-p", f"MemoryMax={memory_limit_mb}M", "--"] + cmd
   ```
   applied at the same two call sites as fix #3, gated by the SAME config keys (reuse
   `reactive_capture_zeek_memory_limit_mb`/`reactive_capture_suricata_memory_limit_mb` — one pair
   of knobs, two enforcement mechanisms, not four separate keys).
3. `--collect` ensures the transient unit is cleaned up automatically after exit (no leftover
   `.scope` units accumulating over time — verify this in a soak test, not just a one-off check).
4. Test on the deployment host directly (this genuinely needs the real host, not a mock — the point is proving
   the OS-level isolation, which nothing in this repo's test harness can simulate): launch a
   forced-oversized allocation under `systemd-run --scope -p MemoryMax=10M -- python3 -c
   "bytearray(50_000_000)"` and confirm (a) the scope is killed, not `soc.service`, and (b)
   `systemctl status soc.service` shows no memory/restart impact from the killed scope.
5. Roll out with a generous limit first (matching fix #3's suggested 400-512MB), watch
   `reactive_capture_errors_total` and journal for unexpected scope kills under real traffic
   before tightening.

**Effort**: medium (real host verification required, new subprocess-wrapping helper, soak test)
but meaningfully less than Option A. **Risk**: low-medium — worst case if `systemd-run` isn't
permitted or misbehaves is a fallback to today's unwrapped `subprocess.run` behavior (step 1's
fallback), not a new failure mode.

**Recommendation**: ship fix #3 first (cheap, no infra dependency, works everywhere). Evaluate
Option B only after confirming step 1's permission model on the deployment host — if it's a clean fit, it is the
correct long-term answer to this document's actual thesis (the core pipeline must never share a
failure domain with the bursty capture subsystem). Do not pursue Option A unless Option B turns
out to be infeasible on this host.
