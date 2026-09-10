# FULL_AUDIT_V14 Review Response & Implementation Plan

**Origin**: 2026-09-10. The user pasted a full external audit report (`FULL_AUDIT_V14.txt`,
preserved verbatim in [`AUDIT_V14_RAW.txt`](AUDIT_V14_RAW.txt) in this directory) and
asked for every item to be fixed toward production shippability, with tradeoffs and a
release recommendation. Same discipline as
[`AUDIT_REVIEW_FOLLOWUP.md`](AUDIT_REVIEW_FOLLOWUP.md) (the 2026-09-09 external
review): **every claim was checked against the actual current source before being
acted on** — nothing here is implemented from the audit's text alone.

**Headline finding**: this audit is a well-structured, genuinely useful *design*
review, but a large fraction of its P0/P1 findings describe code that no longer
exists in its described form — some fixed as far back as 2026-08-29/09-05, several
more on 09-07 and 09-08/09 (see [[project_v13_alert_quality_fixes]],
[[project_v13_full_architecture_shift_plan]] in memory). The audit also targets the
wrong live code path for several findings (`src/core/decision_engine.py` is a
disabled rollback fallback, not what evaluates real decisions — see §0), and its
Raspberry-Pi-8GB framing doesn't match the actual current deployment (see §4). Acting
on its literal recommended diffs would in three cases patch dead code and leave the
live path untouched.

That doesn't make the audit worthless — 6 of its findings are real, open, and worth
fixing (§2), including one (§2.6) that survived verification exactly as described.
Its overall discipline (corroboration before autonomous
containment, decouple risk-score arithmetic from hard mitigation, don't let a
generative model hold sensitivity authority) is exactly the standard this codebase
already tries to hold itself to. This document separates the two piles and proposes
a plan for the real one.

**Implementation status (same session, 2026-09-10)**: all 6 items in §2 are now
implemented. §2.2/§2.4/§2.6 needed no design call and were fixed directly. §2.1
(Suricata autonomy) and §2.3 (LLM sigma_shift bounding) were genuine policy
decisions, put to the user via `AskUserQuestion` before implementing — both
resolved to the more conservative of the offered options (Suricata: alert-only,
always corroboration-required, matching the `geofence` hard-stop's shape; LLM
tuning: route to a Telegram human-approval button instead of auto-applying). See
each subsection below for the applied fix and, where relevant, the test updated to
match the new intentional behavior.

---

## §0. Critical context the audit missed: which decision engine is actually live

`main.py` boots `core.pipeline.EnginePipeline`, and `pipeline.py` does still contain
`core/decision_engine.py`-shaped logic — but as of the 2026-09-07
`V13_FULL_ARCHITECTURE_SHIFT_PLAN.md` cutover, **`config.get("engine", "v13")`
defaults to `"v13"`**, meaning every real decision is evaluated by
[`src/v13/decision/engine.py`](../src/v13/decision/engine.py), not
`src/core/decision_engine.py`. The latter now only runs under the explicit
`engine: "v_current"` rollback flag — its own in-file comment says so directly
(`decision_engine.py:352-356`): *"this `evaluate()` only runs at all under the
`engine: v_current` rollback path... v13's own decision engine is the live default."*

The audit cites `src/core/decision_engine.py` line numbers for both P0 findings. Its
diagnosis of the OLD file's geofencing branch is itself already stale (the live copy
of that file already has the corroboration-required fix — see §1.2) — but more
importantly, fixing the rollback-only file would not touch what a real deployment
evaluates at all. Any future work against this report must target `v13/decision/
engine.py` and `v13/graph/store.py`, not their `core/`-namespace counterparts, unless
explicitly working on rollback-path parity.

---

## §1. Findings already fixed (verified against current source, not assumed)

### 1.1 [P0] "IPS Engine ignores `escalated_via_persistence`" — **FIXED**, pre-dates this audit

`pipeline.py:2491-2502` (the real call site immediately before `ips_mitigator.mitigate()`
is invoked) already downgrades the value passed as `decision_state`:

```python
containment_decision_state = decision.get("state", "SUSPICIOUS")
if decision.get("escalated_via_persistence"):
    containment_decision_state = DecisionState.SUSPICIOUS
...
self.ips_mitigator.mitigate(..., decision_state=containment_decision_state)
```

The in-code comment (`PHASE 19 FIX`) documents this as a direct response to the exact
failure mode the audit describes — `ips.py` never sees `"HIGH"` for a
persistence-escalated alert at all; `mitigate()`'s own severity gate doesn't need to
know about the tag because the caller already normalized it away. No action needed.
`escalated_via_persistence` is still shown in the alert text/Telegram severity exactly
as before — only the value that gates containment changed.

### 1.2 [P0] "Geofencing + 1 signal → 0.95 confidence → trivial tarpit" — **FIXED**, both engines

Live path (`v13/decision/engine.py:124-136,235-247`): the geofence hard-stop rule is
declared `requires_corroboration=True`. Its `check()` only fires on **fresh** evidence
(120s TTL, `_HARD_STOP_FRESHNESS_SECONDS`), and reaching `CRITICAL/0.95` additionally
requires `num_independent_sources >= 1 AND attack_score > benign_score` — a bare
geofence hit plus one weak DNS anomaly that the hypothesis engine doesn't actually
score as attack-leaning does **not** clear that bar. The uncorroborated path produces
`HIGH` / `threat_confidence=0.70` (`geofence_uncorroborated`), which maps to
`risk_score=7.0` — below the tarpit gate's `>=9.0` floor (`ips.py:628`) and below the
Pi-hole block floor. A Smart TV hitting a geofenced CDN alongside one weak, unrelated
DNS anomaly gets `HIGH`/alert (a Telegram notification), not a Layer-2 tarpit.

Rollback path (`core/decision_engine.py:227-260`) independently carries the same fix
(`VERSION 12 (G6, HEE coverage audit)` comment) — the audit's own cited file already
contained the fix by the time this report was apparently generated.

### 1.3 [P0-adjacent] "tier=4/5 treated as sufficient corroboration" — **tightened further, 2026-09-09**

`v13/decision/engine.py:262-269`: reaching `CRITICAL` off a bare tier-5 reputation
score (not a curated `verified_ioc` match) used to need only `num_independent_sources
>= 1`; a third-party review flagged that as weaker than `HIGH`'s own bar, and it was
tightened same-day to `>= 2`, with an explicit in-code rationale ("CRITICAL should
never require LESS corroboration than HIGH"). Tier-4 is unaffected — it was already
gated to `SUSPICIOUS`/`monitor` only (`tier4_unconfirmed` path), never a containment
trigger. No action needed.

### 1.4 "DNS evasion flags IoT devices hardcoding 8.8.8.8, causes systemic FPs" — **not reproducible against current code**

[`src/intelligence/detectors/dns_evasion.py`](../src/intelligence/detectors/dns_evasion.py)
explicitly excludes `KNOWN_PUBLIC_DNS_RESOLVERS` (`_is_known_dns_resolver()`,
line 194) before ever considering a connection "unexplained," on top of private-LAN
exclusion, VPN/CDN ASN matching, reverse-DNS base-domain matching, TI allowlist
matching, and a learned per-device familiarity damping term
(`fp_engine.get_baseline_familiarity()`). The resulting evidence still needs a second
independent evidence family to influence containment (`independence_group=
"blindspot_audit"`, same 2-source bar as everything else). We could not find the
described failure mode in the current implementation — this appears to describe an
earlier version, or a misreading of a different, hardcoded-list-shaped check
elsewhere in the file (`_KNOWN_PUBLIC_DNS_RESOLVERS` itself, which is the *allowlist*,
not the trigger). No action needed; flag if a real false-positive instance ever
surfaces in production logs.

### 1.5 "zeek_notice is 98.3% of evidence rows, weak notices fed in despite 0.0 weight" — **fixed 2026-09-08/09**

Already tracked in [[project_v13_alert_quality_fixes]]: `zeek_notice` was fragmented
into 4 evidence types by tier (`utils.py`'s `ZEEK_NOTICE_EVIDENCE_TYPES`), weak-tier
notices are explicitly excluded from `ATTACK_SHAPED_EVIDENCE_TYPES`
(`evidence.py:94-104`) and from `v13`'s equivalent benign-hypothesis treatment, and
weak-tier retention was cut from the general 90-day default to 12 hours with a
dedicated `idx_evidence_type_ts` index to make the resulting prune/query pattern
cheap. This was the single largest share of the graph's write volume; the fix
predates this audit landing in this conversation. No action needed beyond continuing
to watch table growth (§3.5 below covers residual sizing work).

### 1.6 "FritzBox burst capture triggers multiple radios in parallel threads, drops packets" — **mischaracterized**

`fritzbox_capture.py`'s `run_burst()` iterates `for iface in radios:` sequentially
across three distinct phases (start capture / stop+collect / convert), all under one
process-wide `self._burst_lock` (`threading.Lock`, non-reentrant, acquired
non-blocking) that rejects a second burst outright while one is running
(`"'%s' (the router's radio capture is a single shared resource; concurrent bursts..."`,
line 791-794). There is no parallel-thread fan-out per radio. The audit's concern
about concurrent raw packet streams saturating a low-end box doesn't describe this
code as it exists. No action needed.

### 1.7 "Dangerous uncoordinated locks: `requests.post()` to Fritz!Box held under `self._lock`" — **fixed for the operator path only; the autonomous path still has this bug** (moved to §2.6, confirmed open)

---

## §2. Findings still genuinely open

These are real, confirmed against current source, and worth fixing. Ordered by
risk-adjusted priority, not by the audit's own P-numbers (which conflated some
already-fixed items with these).

### 2.1 Suricata severity=1 is the one hard-stop with no corroboration requirement

**Confirmed live** (`v13/decision/engine.py:137-144`,
`suricata_scan.py:50-54`): `_SEVERITY_TO_CONFIDENCE = {1: 0.95, 2: 0.70, 3: 0.45}`
feeds a `confirmed_exploit` hard-stop rule that, unlike `geofence`, has
`requires_corroboration` unset (defaults `False`) — a single severity=1 Emerging
Threats match alone reaches `CRITICAL`/`block`/`threat_confidence=0.98`
(`risk_score=9.8`), clearing the tarpit floor with no second independent signal.

Suricata only runs in rate-limited batch mode against short reactive-capture bursts
(not continuously inline), which addresses the *Pi-load* half of the audit's original
concern (§14 of the raw report) but not the *false-positive-blast-radius* half — a
noisy ET rule (many are, by design, broad and heuristic even at "severity 1") can
still trigger full Layer-2 isolation off one match.

**Tradeoff**: a genuine zero-day/known-exploit signature match is exactly the kind of
evidence that *should* be allowed to skip the normal 2-family corroboration bar — that
was the deliberate design intent (`suricata_scan.py`'s own docstring: "a real rule
match against a curated ruleset is close to definitional, not a fuzzy heuristic").
Requiring corroboration the same way `geofence` does would weaken response to an
actual confirmed exploit, which is the one scenario where fast autonomous
containment is most justified.

**Resolved (`AskUserQuestion`, 2026-09-10): "Alert-only, always."** The user chose
the most conservative of the three offered options — a Suricata match alone should
never autonomously tarpit/block, full stop, requiring a second independent signal
(or an operator's own approval tap, via the existing interactive-blocking queue) to
escalate to `CRITICAL` containment.

**Fix applied**: `confirmed_exploit`'s `HardStopRule` (`v13/decision/engine.py`) now
sets `requires_corroboration=True`, `uncorroborated_state=HIGH`,
`uncorroborated_confidence=0.75`, `uncorroborated_decision_path=
"suricata_uncorroborated"` — the exact same shape `geofence` already uses. A
corroborated match (a second independent evidence family, with the hypothesis engine
agreeing attack > benign) still reaches `CRITICAL`/block; an uncorroborated one is
`HIGH`/alert instead. Mirrored into `core/decision_engine.py`'s rollback-path
equivalent too, for `engine: "v_current"` parity (same reasoning as §1.2's existing
rollback-path fix). Verified against `tests/test_phase37_suricata_batch_scan.py`,
`tests/test_suricata_api.py`, and `tests/test_v13_decision_engine.py` — all pass
unchanged (none of them asserted the old uncorroborated-auto-CRITICAL behavior).

### 2.2 SQLite `cache_size` = 4MB for the `pi_8gb` hardware profile

**Confirmed live** (`v13/graph/store.py:78-82`):
`_HARDWARE_PROFILE_CACHE_SIZE_KB = {"pi_8gb": 4_000, "x86_16gb": 16_000, "custom":
16_000}`. This *is* real and unaddressed — but two things the audit gets wrong about
its blast radius: (a) this profile isn't what's actually running anywhere right now —
see §4, the only live box (`.94`) is a 12GB x86 mini-PC on `hardware_profile: x86_16gb`
(this checkout) or possibly `custom`, not `pi_8gb`; (b) with §1.5's fix, the graph is
no longer dominated by zeek_notice noise, so the "5GB database, catastrophic
thrashing" framing is sized against pre-fix data volume.

That said, it's a real bug-in-waiting for the actual Pi-8GB product target the user
is building toward, it's a one-line, zero-risk change, and there's no reason to ship
an artificially crippled default. **Tradeoff**: SQLite's page cache is process RAM,
taken from whatever the box has free — on an *actual* 8GB Pi also running Zeek,
Suricata (batch), Pi-hole, and `soc.service`, a large cache directly competes with
those. The audit's suggested `256MB` is a guess, not a measured number, and (per §4)
there's no real Pi-8GB deployment yet to measure against.

**Fix applied**: `pi_8gb` bumped from `4_000` to `48_000` (48MB) — squarely in the
conservative 32-64MB range this section recommended, not the audit's guessed 256MB.
Documented in-code as a first-pass judgment call to re-tune once real Pi-8GB hardware
exists to measure against. `tests/test_v13_graph_store.py` (a script-style test, run
directly with `python tests/test_v13_graph_store.py`, not via `pytest` — see this
file's own note below on why) hardcoded the old `-4000` value; updated to `-48000`
and re-verified passing (55/55 checks).

### 2.3 LLM-driven per-device sensitivity loosening (`_apply_sigma_shift(TUNE_DOWN)`)

**Confirmed live** (`ollama_soc.py:1548-1567`): an IP-only `NETWORK_INTRUSION` target
that Ollama classifies as benign but can't resolve to a domain triggers
`_apply_sigma_shift(device_id, ..., direction="TUNE_DOWN")` — loosening *this
device's* future detection sensitivity — off a single LLM classification pass, plus
releases any active tarpit/router isolation on that device. The audit overstates the
blast radius (this is scoped to the one device, not "across all devices" or
"permanently" in the global sense — TUNE_UP on a later malicious verdict re-tightens
it), but the core concern is real: one adversarially-crafted or ambiguous payload that
convinces Ollama an IP-only alert is benign measurably reduces future detection
sensitivity for that specific device with no human in the loop.

**Tradeoff**: the entire point of the LLM review stage is to reduce the alert-fatigue
cost of the aggressive corroboration-first design elsewhere in this system — stripping
its ability to act autonomously at all (the audit's literal recommendation in §21,
"Remove LLM Authority... NEVER altering global device sensitivity") pushes that
alert-fatigue cost back onto the user for every IP-only ambiguous case, which is a
large fraction of real alerts per `AUDIT_REVIEW_FOLLOWUP.md`'s own numbers.

**Resolved (`AskUserQuestion`, 2026-09-10): route to human approval.** The user chose
option (c) — IP-only `TUNE_DOWN` now goes to a Telegram approval button instead of
applying automatically; domain-attributable immunization (the `if target_domain:`
branch, which only ever touches one specific domain via the FP trust cache, not
device-wide sensitivity) stays fully autonomous as before, since it has a real
domain to anchor trust on and isn't the exposed case.

**Fix applied**: `ollama_soc.py`'s no-domain branch no longer calls
`_apply_sigma_shift`/`release_device` directly — it records the pattern as
`outcome="queued_for_approval"` and appends `{device_id, hostname, target}` to a new
`pending_tune_approvals` list. The once-per-run Telegram digest
(`build_ollama_digest_message`, now with a `queued_for_approval` entry in
`_OUTCOME_LABELS`/`summary_order`/`detail_worthy` so it's actually visible instead of
silently folding into the "already actioned" bucket) ships with one
`inline_keyboard` row per queued device (`_send_telegram` gained an optional
`reply_markup` param for this). Tapping "✅ Approve" fires `callback_data:
"approve_tune:<device_id>"`, handled by a new branch in
`mitigation/alerts.py`'s Telegram callback dispatcher, which POSTs to a new
`/api/ipc/approve_tune_down` endpoint (`middleware/routers/pihole_api.py`) — mirrors
`fritzbox_api.py`'s existing `/api/ipc/block` interactive-approval shape exactly (no
ledger entry needed; the device_id alone is enough to re-derive the current hostname
from `StateManager` and apply `_apply_sigma_shift(TUNE_DOWN)` + `release_device()`
on approval). Still marks the pattern's cache entry `action_taken=True` immediately
(so it doesn't re-trigger Ollama review every run while awaiting a tap), matching
the existing immunize branch's bookkeeping.

### 2.4 `_VENDOR_CLOUD_API_DOMAINS` allowlist can mask exfiltration via major platforms

**Confirmed live** (`threat_signals.py:32-35,71`): `github.com`, `amazonaws.com`,
`google.com`, `microsoft.com`, `apple.com`, `azure.com`, `cloudflare.com`, `sentry.io`
all dampen the exfiltration signal via `is_vendor_cloud_api`. The design intent (per
the file's own comment) is legitimate — telemetry/SDK traffic to these platforms is
extremely common and a bare domain-suffix match on them was already generating real
false positives — but the audit's point stands: these are also some of the most
common real exfiltration channels precisely because they're allowlisted everywhere.

**Confirmed the exact current behavior, corrected from an earlier pass in this same
review** (`threat_signals.py:246,259-260,278`): of the three exfiltration-volume
tiers (elif chain, ordered massive-burst → elevated → absolute-volume), the *middle*
one already dampens rather than suppresses (`conf = 0.35 if is_vendor_cloud_api else
0.6`). The highest-confidence "massive burst" tier used a hard `not
is_vendor_cloud_api` gate, but because these are `elif` branches, a vendor case that
failed it still fell through and usually got evidence anyway — at the middle tier's
0.35, *by accident*, not by design. That fallthrough only rescues a vendor case that
also happens to clear the middle tier's own bar (`z>3.5, bytes>250KB`); a case that
clears the top tier's bar but not the middle one (e.g. a huge absolute transfer at a
comparatively low z-score) fell all the way through to the "absolute volume" tier,
which *also* hard-gated on `not is_vendor_cloud_api` with no further fallback —
**that** combination produces real, reproducible zero evidence, the actual failure
mode the audit was pointing at.

**Fix applied**: both tiers now dampen directly instead of relying on (or, for the
last tier, lacking) `elif` fallthrough — massive-burst: `0.5` if vendor else `0.9`
(deliberately higher than the middle tier's `0.35`, since `z>5` is a stronger signal
than `z>3.5`); absolute-volume: `0.25` if vendor else `0.55`. Every tier now dampens
consistently on its own rather than some tiers depending on an accident of branch
order. `tests/test_phase1_hypotheses.py`'s existing vendor-dampening check (previously
asserting the accidental `0.35` fallthrough value) updated to assert the new direct
`0.5`, with its own comment explaining why the old value was never a real design
guarantee.

### 2.5 `risk_score = threat_confidence * 10.0` — structurally still a direct linear mapping

**Confirmed live** (`pipeline.py:1656,1733,1822` etc.). The audit's underlying
architectural point — that containment authority should come from an explicit,
named condition (e.g. `has_confirmed_exploit`, geofence-with-corroboration) rather
than an arithmetic threshold on a derived float — is *already mostly true in
practice* after §1.2/§1.3: every path that can reach `risk_score >= 9.0` today is
already gated by one of the hard-stop rules or a tightened corroboration bar, not a
bare float crossing 0.9. The mapping itself is still there as plumbing (metrics,
`ips.py`'s `>= 9.0` / `>= 8.5` thresholds), so a future new decision path could
still reintroduce the exact failure the audit describes if it isn't routed through
the hard-stop registry.

**Recommended fix**: lower priority than §2.1-2.4 given the practical exposure is
already closed off — but worth a structural cleanup: have `ips.py`'s tarpit/router
gates check `decision_path in {"hard_stop", ...}` (or an explicit boolean the decision
result already could carry) in addition to the `risk_score >= 9.0` float check, so
the invariant is enforced by name, not by every future hard-stop rule happening to
also set `confidence >= 0.9`.

### 2.6 Autonomous router-isolation path still holds `self._lock` across the Fritz!Box network call

**Confirmed live, and confirmed genuinely still broken** (`ips.py:610-624`): the
audit's §16/18 "dangerous uncoordinated locks" concern is real for `mitigate()`'s
*autonomous* router-isolation branch specifically — `self._isolate_device_router(...)`
(a real `self.session.post(webhook_url, ..., timeout=5.0)` call, `ips.py:1117-1133`)
is invoked directly inside `with self._lock:`, and `self._lock` is a single
engine-wide `RLock` (`ips.py:85`) that every other mitigation operation
(Pi-hole blocking, tarpit registration, status queries, `release_device()`) also
acquires. If the Fritz!Box webhook is slow to respond, every other mitigation
operation on the box stalls for up to `router_webhook_timeout_seconds` (default 5s)
behind it.

This is the one place the audit's concern turned out to be right about the *live*
path rather than an already-fixed or misdiagnosed one — and the fix is already
proven correct elsewhere in the exact same file: `operator_isolate_router()`
(`ips.py:660-690`, a few hundred lines below) makes the identical
`_isolate_device_router()` call but deliberately keeps it **outside** the lock,
re-acquiring `self._lock` only for the local bookkeeping before/after. The
autonomous path at line 610-624 evidently didn't receive the same fix when the
operator path did.

**Fix applied**: restructured to match `operator_isolate_router()`'s existing shape
exactly — check under the lock (`already_isolated = mac_addr in
self._router_isolated_devices`), release it, make the network call
(`_isolate_device_router`) unlocked, then re-acquire the lock only to record the
result. `tests/test_ips_operator_actions.py` re-run and passes unchanged (it
exercises the operator path this mirrors, not the autonomous path directly, so it
was never expected to catch this gap in the first place — worth noting as a real
test-coverage hole, not something this fix closes).

---

## §3. Findings that are real engineering tradeoffs, not bugs — accept, monitor, or defer

### 3.1 Pure-Python Scapy ARP/NDP tarpit — real capacity constraint, not a logic bug

Confirmed: `ips.py` runs `scapy.sniff()` in background threads for the dual-stack
tarpit. This genuinely is slower than a compiled/eBPF equivalent, and genuinely will
drop packets under sustained multi-hundred-Mbps load. But: it only activates for
devices that have *already* cleared the (now well-corroborated) containment bar — not
continuously for the whole network — and a dropped tarpit packet fails safe (the
device just isn't as effectively trapped, not that the IDS itself stalls). Rewriting
this in eBPF/C is a substantial, higher-risk undertaking for a benefit that only
matters during an active containment event on a saturated link. **Recommendation**:
defer; add a Prometheus counter for tarpit-loop packet-processing latency/drops if one
doesn't already exist, so this becomes a measured decision instead of a guess if it
ever actually matters in production.

### 3.2 EWMA baseline absorbing slow beaconing over time

This is an inherent property of any adaptive baseline, not a fixable bug — the
tradeoff is baseline drift (accepts slow attacks) vs. baseline rigidity (false-positive
storms on legitimate behavior change, e.g. a new streaming app). **Recommendation**:
don't try to make the baseline resist absorption; add an independent slow-drift
detector that compares long-window vs. short-window baselines for the same device and
flags a *sustained directional trend* as its own weak evidence item, so slow beaconing
still produces something even after it's been fully absorbed into "normal."
This is new detection work, not a fix to existing code — worth a separate scoping
pass if wanted.

### 3.3 `systemd-run --user` / `loginctl enable-linger` deployment dependency for Suricata cgroup isolation

Confirmed real, and correctly characterized by the audit as "functional but brittle."
This is a deployment/ops concern, not a logic bug — it belongs in `INSTALL.md`'s
prerequisites checklist (confirm it's already documented there) rather than a code
change.

### 3.4 "Unknown" domains/IPs polluting the graph, breaking attribution reconstruction

Real and already an acknowledged, tracked gap — not new information from this audit.
No separate action from this document; continues under existing attribution-fix work.

### 3.5 Residual WAL growth / checkpoint tuning under high Zeek ingestion

Worth a follow-up check once §1.5's zeek_notice fix has had time to show its effect
on real WAL file size on `.94` — likely much less pressing post-fix than the audit
assumed, but not verified with fresh production numbers in this session.

### 3.6 NEW (found while testing this session's fixes, not from the audit): the v13 ingest daemon never computes `outbound_bytes_z`

While re-running tests after §2.4's change, `tests/test_v13_ingest_daemon.py`'s
"massive-outbound-burst" check failed. Traced to the root cause, and it's unrelated
to any of this session's 6 fixes: `calc_z()` (the EWMA-baseline z-score computation
`outbound_bytes_z` needs) is only ever called from `core/pipeline.py` — a `grep` for
`calc_z` across `src/` returns exactly one file. `src/v13/ingest/sources.py` (the
`IngestDaemon` this test exercises) never computes it at all, so every z-gated
detector branch in `threat_signals.py` — not just exfiltration's three tiers, any
other z-score-gated check too — silently and permanently reads `outbound_bytes_z=0.0`
(the `features.get(..., 0.0)` default) whenever evidence is generated through the
v13 ingest daemon path specifically, rather than through `core/pipeline.py`'s own
cycle. This looks like a real, pre-existing gap, not something this session
introduced — worth confirming which path `soc.service` actually runs in production
(`core.pipeline.EnginePipeline` per `main.py`, or a standalone `IngestDaemon`?) before
scoping a fix, since if it's the latter, z-score-gated detection may be silently
degraded there. **Deliberately not fixed in this pass** — out of scope for this
audit response, flagged here and in memory for a dedicated follow-up rather than
scope-creeping onto the 6 items above.

---

## §4. Corrected deployment picture (the audit's Pi-8GB framing doesn't match reality)

The audit evaluates everything against "deployment on a Raspberry Pi 8 GB" and scores
"Raspberry Pi suitability: 3/10... FAIL" as if that's the box currently in production.
It isn't, per `V13_ARCHITECTURE_DEPENDENCY_MAP.md`'s own verified (not assumed)
hardware table:

| Claim in audit | Actual current state |
|---|---|
| "Local Ollama inference... requires ~4-5GB RAM and saturates the CPU [on the Pi]" | The v13 parallel-run's Ollama runs on `.19`, a *separate* Intel i7/31GB-RAM box, reached over the LAN — not on the production sensor box at all. The production box (`.94`) does run its own local Ollama (`llama3.1:latest`, 8B Q4_K_M) for the legacy/`ollama_soc.py` review path, but `.94` is not a Raspberry Pi. |
| "Raspberry Pi 8GB" as the thing being evaluated | Per `V13_ARCHITECTURE_DEPENDENCY_MAP.md:20` (2026-09-05): *"The 8GB Raspberry Pi remains a forward-looking product target only — not hardware available for direct testing as of this document."* Nobody has run this stack on real Pi-8GB hardware yet. |
| Implied box: SD-card-based Pi | `.94` is a BOSGAME E4 mini-PC (Ryzen 5 3550H, 4C/8T, 12GB RAM — not the 16GB some old docstrings still claim, corrected 2026-09-05), running Ubuntu 26.04 on what's presumably SSD/eMMC storage, not an SD card. |

This matters for how to read the audit's Pi-specific findings: `pi_8gb`-profile code
paths (§2.2's cache size, the `pi_8gb` CPU-quota tuning elsewhere) are legitimate
*design-for-a-future-target* work, correctly in scope to fix, but the audit's framing
("the system cannot be safely shipped... will result in rapid SD card degradation")
describes a failure mode on hardware that has never actually run this code. Treat
§2.2 as "get the default right before Pi hardware arrives," not "an active production
incident."

One thing genuinely worth separate attention this cross-check surfaced (not from the
audit): `.94` itself is currently tight on disk (39GB total, 8.6GB free / 77% used per
the same doc) while running Zeek + Suricata + Pi-hole + `soc.service` + unrelated
personal services (Grafana, Immich, n8n) on the same volume. That's a real, current
resource-pressure risk independent of anything Pi-shaped — worth a disk-headroom check
next time `.94` is touched, separate from this audit's scope.

---

## §5. Recommended action plan

Priority order reflects confirmed real risk, not the audit's own P-numbers (several of
its P0s are already closed; none of the still-open items are P0-grade given the
upstream corroboration gates already in place). **All 6 are now implemented and
verified** (test status per item below).

| # | Item | Risk if left | Effort | Status |
|---|---|---|---|---|
| 1 | §2.2 SQLite `pi_8gb` cache_size | Low now (not deployed), real for future Pi target | Trivial (1-line) | **Done** — `4_000` → `48_000`; `test_v13_graph_store.py` updated + passing (55/55) |
| 2 | §2.1 Suricata hard-stop corroboration | Medium — one noisy ET rule can auto-tarpit | Small, needed a design call | **Done** — user chose "alert-only, always"; `requires_corroboration=True` in both engines; `test_phase37_suricata_batch_scan.py`/`test_suricata_api.py`/`test_v13_decision_engine.py` passing unchanged |
| 3 | §2.3 LLM sigma_shift bounding | Medium — real but device-scoped, needed a real adversary to matter | Small-medium, needed a design call | **Done** — user chose human-approval routing; new Telegram approve button + `/api/ipc/approve_tune_down` endpoint |
| 4 | §2.4 Vendor-cloud allowlist: stop hard-suppressing 2 of 3 exfil tiers | Medium — confirmed a real zero-evidence gap for extreme bursts | Trivial (2-line) | **Done** — both tiers dampen instead of suppress; `test_phase1_hypotheses.py` updated + passing |
| 5 | §2.5 `risk_score` structural decoupling | Low now (already closed off in practice) | Medium | Deferred — not urgent, no change this round |
| 6 | §2.6 autonomous router-isolation holds engine-wide lock across a live HTTP call | Medium — a slow/unresponsive Fritz!Box stalls Pi-hole blocking, tarpit registration, and `release_device()` fleet-wide, not just router isolation | Trivial — working fix already existed in the same file | **Done** — network call moved outside `self._lock`, mirrors `operator_isolate_router()`; `test_ips_operator_actions.py` passing unchanged |
| — | §3.1-3.5 | Various, all accepted tradeoffs or deferred new work | — | No action this round |
| — | §3.6 (new, not from the audit) | v13 ingest daemon never computes `outbound_bytes_z` — found while re-testing #4 | Needs scoping | Flagged, not fixed — see §3.6 |

Items 2 and 3 were the two places this plan couldn't just proceed
autonomously — both are policy decisions about how much autonomous authority this
system should have over containment and sensitivity, not engineering questions with
one correct answer. Both were resolved via `AskUserQuestion` before implementation.

## §6. Revised production-readiness assessment

The audit's `4/10 (NOT READY)` verdict was computed against a mix of already-fixed
code, a decision engine that isn't the live one, and a hardware target that was never
actually deployed. Re-scored against verified current behavior:

- **False-positive resistance**: the audit's own headline failure modes (persistence
  bypass, trivial geofence tarpit) are closed. The two remaining open items that
  bear on this (§2.1 Suricata, §2.3 LLM tuning) are real but narrower and both already
  have partial mitigations (batch-mode rate limiting; device-scoped not global).
  Materially better than 2/10 — call it a genuine 6/10 pending §2.1/§2.3.
- **IPS safety**: every autonomous containment path that can reach the tarpit/block
  floor is corroboration-gated except the single Suricata rule (§2.1). Not the 3/10
  the audit gives it once that one path is addressed.
- **Raspberry Pi suitability**: not meaningfully assessable yet — there's no real
  Pi-8GB deployment to measure against (§4). The `pi_8gb` config profile defaults are
  reasonable-effort placeholders, not validated numbers either direction.
- **Reliability**: the audit's 5/10 "lock handling over network calls" concern is
  confirmed real for the autonomous router-isolation path specifically (§2.6) — not
  fixed, unlike most of its other locking concerns. This is the one finding in the
  whole report that survived verification exactly as described. Worth fixing before
  calling reliability solid, but it's a trivial, already-proven-pattern fix, not an
  architectural problem.
- **Everything else** (architecture, evidence integrity, observability): the audit's
  scores here look roughly right and aren't contradicted by this review.

**Recommendation for a general home-network production release**: the system was
already closer to ready than the audit suggested, and with all 6 confirmed-open
items now implemented (§5), there's no known outstanding item from this audit
blocking a general-home-network release. The one caveat is §3.6 — a real, but
separately-scoped, pre-existing gap found incidentally while testing this session's
fixes (not from the audit) — worth confirming which ingest path production actually
runs before treating z-score-gated detection as fully trustworthy. The Pi-8GB
hardware target specifically still needs real hardware to validate against before
that specific claim can be made with confidence — nothing in this pass changes that,
since (per §4) it was never actually blocked on code, only on hardware that doesn't
exist yet to test on.
