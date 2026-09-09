# External Architecture Review Follow-Up — Roadmap

**Origin**: 2026-09-09. The user shared a ChatGPT-authored critique of 2 real alerts
(a `COORDINATED_TARGETING` alert attributed to `224.0.0.22` showing 1 evidence family,
and a `PEER_COHORT_DEVIATION` alert showing 0 families alongside an 85% attack
confidence) plus a 27-point review of the whole hypothesis/decision architecture
("Threat Combinatorics"). A live 24h data pull against `.94`'s real `state/alerts.json`
confirmed the core complaint was genuine production behavior (34 of 121 real alerts
showed the same "HIGH with 0 evidence families" shape) — not a misreading, but also not
a scoring bug: a display/persistence bug, fixed same-day (`f027a6f`/`cd3d747`/`7d70e10`,
see [`THREAT_CATEGORY_REFERENCE.md`](THREAT_CATEGORY_REFERENCE.md) §5/§8 for the full
incident writeup and [[project_v13_alert_quality_fixes]] in memory).

This document tracks everything from that review that is **not** a same-session code
fix — either because it's genuinely large architectural work, or because closer
examination found it needs a decision or more data before it can be implemented safely.
Same discipline as `V13_REMAINING_WORK.md`: each item states *why* it's open and *when*
it should be picked up, not just "not done yet." When an item here gets resolved, move
its outcome into `THREAT_CATEGORY_REFERENCE.md` and delete it from here.

---

## Fixed this same session (for cross-reference — not open items)

Beyond the `hee_evidence_families`/destination-attribution fix above, this follow-up
pass also shipped, tested, and deployed:

1. **Geofencing excluded from independent-source counting** (`v13/hypotheses/independence.py`
   — `"policy"` added to `NON_ATTACK_FAMILIES`). A destination-policy fact could
   previously supply the *second* independent source for an unrelated, weaker attack
   hypothesis (the exact same cheapness argument already applied to
   `peer_cohort_deviation`/`ml_anomaly`, just not extended to geofencing until this
   review named it). The geofence hard-stop's own corroboration check is unaffected —
   verified against both its existing test scenarios, plus a new regression test.
2. **Exfiltration's absolute-volume branch now requires minimal baseline elevation**
   (`intelligence/detectors/threat_signals.py`) — it used to fire on raw `outbound_bytes
   > 50MB` with zero reference to the device's own baseline, unlike the two branches
   above it (which both gate on a real z-score). Added `outbound_z > 0` as a cheap
   floor. Deliberately conservative — see its own item below for why a stricter bar
   wasn't chosen.
3. **Multicast/local destinations excluded from reputation-target selection**
   (`core/pipeline.py`, new `_dest_ip_is_real_host` guard) — closes audit Invariant 8.
   No live incident confirmed this ever actually fired (a real TI/VT/AbuseIPDB feed
   essentially never has data for a non-routable multicast address), but nothing
   previously prevented it structurally.
4. **C2 beaconing's 3 sub-signals are no longer treated as equally strong**
   (`intelligence/detectors/threat_signals.py` + `v13/hypotheses/engine.py`'s
   `BeaconingHypothesis`) — only `persistent_single_target` (genuine interval
   regularity: `tdr>0.75` across `>=15` observations) can reach HIGH/CRITICAL now;
   `low_and_slow`/`uniform_jitter` (thinner signals, no regularity requirement) are
   capped at the base floor, same treatment `DNS_ATTRIBUTION_GAP` already gets.

---

## Re-examined and found more nuanced than first scoped — NOT changed, needs a decision

### A. Invariant 3, literal form ("if evidence.destination_id != decision.destination_id: reject()")

**What's actually implemented**: `decision["winning_evidence"]`/`evidence_families` now
expose the REAL evidence that satisfied the winning hypothesis, and every display site
(`network_context.destination_ip`, `hee_evidence_families`, the Telegram WHY block) reads
from that instead of independently re-deriving an answer. This closes every concrete
incident actually found.

**Why the audit's literal ask isn't implemented as stated**: a decision routinely rests
on evidence from *multiple* families that legitimately concern *different* destinations
(e.g. a `dns_behavior` finding on domain X plus a `cross_device_correlation` finding on
IP Y, both real, both independently corroborating the SAME device-level verdict). There
is no single well-defined `decision.destination_id` to compare against — inventing one
and rejecting on mismatch would break legitimate multi-destination corroboration, not
just catch bugs. The audit's practical concern (a persisted/displayed destination that
doesn't match ANY real evidence) is what got fixed; a literal reject-on-any-mismatch
gate is not the right shape for it.

**Trigger to revisit**: if a future incident shows a decision's displayed evidence
still doesn't trace back to *any* of its own real corroborating evidence (as opposed to
tracing back to a different-but-real family), that's a genuinely new gap worth its own
investigation — re-open then, don't build speculative protection now.

### B. Invariant 4 / `first_contact` in `RELEVANT_EVIDENCE_TYPES`

**Found on closer reading**: `DNSTunnelingV2Hypothesis`, `ExfiltrationHypothesis`, and
`BeaconingHypothesis` all still declare `first_contact` in their `RELEVANT_EVIDENCE_TYPES`
even though its `strong_score` contribution was already removed (third-party review,
`9e150ba`). This looked like a leftover worth cleaning up for Invariant 4's sake — but
`ExfiltrationHypothesis`'s own comment says otherwise: *"first_contact stays in
RELEVANT_EVIDENCE_TYPES (still valid context ai_soc.py/reporting can read), it just no
longer moves the score"* — a **deliberate** choice by whoever wrote that fix, not an
oversight.

**The real, narrow risk this creates**: `Hypothesis._effective_rep_tier()` (this
session's own generalized reputation-attribution fix) collects `my_destinations` from
every evidence item whose type is in `RELEVANT_EVIDENCE_TYPES` — including
`first_contact`. If a `first_contact` item happens to carry a DIFFERENT destination than
the hypothesis's own real evidence (e.g. `dns_tunnel_v2`), and a `rep_vector` happens to
describe THAT `first_contact` destination specifically, `_effective_rep_tier()` would
treat the rep_vector as "about my destination" and apply its tier — potentially the
exact "unrelated destination wrongly influences this verdict" bug this whole session
has been closing, just introduced fresh by interaction with a different fix.

**Why not fixed now**: two competing legitimate designs (keep for visibility vs. remove
for tighter scoping) with a real but narrow, not-yet-observed-live tradeoff. Two
reasonable paths: (a) leave as-is, accept the narrow risk (a `first_contact` item's
destination differing from the hypothesis's own primary evidence AND a rep_vector
specifically describing that novel destination is a fairly specific coincidence), or
(b) make `_effective_rep_tier()` itself smarter — collect `my_destinations` only from
evidence types that are ALSO read inside `evaluate()`'s scoring logic, not merely
declared for visibility (would need a second, narrower set per hypothesis, or a
convention like `SCORING_EVIDENCE_TYPES` vs `RELEVANT_EVIDENCE_TYPES`).

**Trigger to revisit**: if a live alert ever shows `_effective_rep_tier()` applying a
tier from a `first_contact`-only destination mismatch, that's the confirmation needed
to pick option (b) with confidence instead of guessing now.

---

## Deferred — large architectural items

Each states the real reason it's open and a concrete trigger for picking it up — not a
priority label.

### C. DNS tunneling required-evidence redesign (audit §4/§5)

**Current state**: `DNSTunnelingHypothesis`/`DNSTunnelingV2Hypothesis` require their
core evidence type (`dns_rate`+`dns_entropy`, or `dns_tunnel_v2`) but escalate on
`2+ distinct provenance subtags` OR a real reputation signal — not the audit's fuller
model (repetition + encoding + cadence as jointly REQUIRED, known-vendor-telemetry as an
explicit contradictor).

**Why open**: this is a genuine hypothesis redesign, not a threshold tweak — it changes
what evidence is even REQUIRED to reach SUSPICIOUS at all, which risks both new false
negatives (a real tunnel that doesn't hit all the new required signals) and requires
re-validating against every existing DNS-tunneling test scenario and any live incident
history for this category.

**Proposed approach**: define the required-core/supporting/contradicting split
explicitly (mirroring this document's §F "evidence classes" below), starting from
`Documentation/ALERT_CATEGORIZATION_CATALOG.md`'s real production volume data for this
category to see what the CURRENT false-positive/negative shape actually looks like
before redesigning blind.

**Trigger**: a dedicated session with time to (1) pull real DNS-tunneling alert history,
(2) design the new required-evidence model against it, (3) shadow-test before flipping
live — same discipline v13's own CL-AFPE rollout used.

### D. DGA lexical/NXDOMAIN detector capability (audit §6)

**Current state**: `DGAHypothesis` requires `dns_dga_burst` (the detector's own
DGA-shape scoring) plus `dns_rate>100` as a secondary signal.

**Why open**: NOT a scoring-logic gap — a genuinely NEW detector capability. The audit
wants lexical randomness, related-domain clustering, NXDOMAIN/low-survival-rate
tracking, and generation-pattern repetition as evidence. None of these exist in any
current sensor (`dns_extractor`/`zeek_fx`) — this requires new feature extraction
(NXDOMAIN response tracking isn't currently captured at all) before any hypothesis
logic could even read it.

**Trigger**: when there's appetite for a new DNS-behavior detector capability
specifically (distinct from a hypothesis-logic change) — check what Pi-hole/Zeek/DNS
extractor data is actually available for NXDOMAIN rates first, since that may not be
cheap to add depending on the current DNS-capture pipeline.

### E. CONNECTION_ABUSE / PORT_SCAN / INTERNAL_RECONNAISSANCE hypothesis split (audit §11)

**Current state**: `ConnectionAbuseHypothesis` already dynamically NAMES itself
`INTERNAL_RECONNAISSANCE`/`PORT_SCAN`/`CONNECTION_ABUSE` based on which single evidence
category fired, but all three share one `evaluate()`/one scoring ladder.

**Why open**: audit wants genuinely separate `Hypothesis` subclasses (their own
required/strong/contradicting logic, own escalation thresholds) rather than one class
with dynamic naming. This is a real design decision (are `zeek_conn_abuse`/
`zeek_long_conn`/`arp_sweep` actually different enough to warrant fully separate
tuning?), not obviously correct either way without live false-positive/negative data
per sub-category.

**Trigger**: if `ALERT_CATEGORIZATION_CATALOG.md`'s volume data (or a future live audit)
shows one of the three sub-shapes has a meaningfully different false-positive rate than
the others under the SAME shared thresholds — that's the concrete evidence needed to
justify the split.

### F. Evidence classes A–D formalization (audit §20)

**What already exists, informally**: `NON_ATTACK_FAMILIES`, the hard-stop registry, and
the corroboration-cheapening fixes already encode something like this taxonomy, just not
as an explicit, named structure. Formalized here as documentation (no code change),
mapping the audit's proposed classes onto this codebase's actual families:

| Audit's class | This codebase's equivalent | Families |
|---|---|---|
| A — Direct malicious evidence (can support CRITICAL alone) | Hard-stop registry (`DEFAULT_HARD_STOP_REGISTRY`) | `honeypot_access` (direct_observation), fresh `arp_spoofing`, fresh high-confidence `suricata_signature_match`, tier-5 `verified_ioc` |
| B — Strong behavioral evidence (can support HIGH, usually needs corroboration) | Attack hypotheses' own required evidence | `dns_tunnel_v2`, `zeek_exfiltration`, `zeek_beaconing` (now: `persistent_single_target` tag only — see item 4 above), `zeek_lateral_scan`, `malicious_ja3`/`malicious_ja4`, `dns_dga_burst` |
| C — Suspicious/anomalous (SUSPICIOUS/ANOMALOUS only, needs a 2nd family for HIGH) | Regular attack-family evidence at base-floor score | `dns_rate`/`dns_entropy`/`dns_unique_ratio` alone, `zeek_conn_abuse`/`zeek_long_conn`/`arp_sweep`, `zeek_beaconing` (weaker tags), `geofencing_violation` |
| D — Context (modifies interpretation, never independently creates a threat) | `NON_ATTACK_FAMILIES` | `local_device_discovery`, `first_contact`, `peer_deviation`, `ml_anomaly`, `geofencing_violation` (as of this session — see item 1 above) |

Note `geofencing_violation` appears in both C and D — it's real evidence a hypothesis
can score on IF one existed that read it directly (none currently does; it's
hard-stop-only), and is now correctly excluded from corroboration counting (class D
behavior) after this session's fix.

**Trigger for further work**: this table is now the reference — update it in place
whenever a family's classification changes, rather than treating this as a one-time
exercise.

### G. Home Network Protocol Context Layer (audit §21)

**Current state**: functionally covered by several SEPARATE mechanisms rather than one
unified layer: `is_local_or_multicast_destination()` (utils.py) handles
multicast/link-local/loopback/broadcast; `is_cloud_cdn_provider_org()` handles CDN/cloud
ASN trust; `ReputationClassifier`'s tiers 0-2 handle local/trusted/known-infrastructure
classification; `_is_shared_infrastructure()` (graph/store.py) handles
structurally-shared household destinations.

**Why open**: this is a consolidation/architecture-clarity project, not a functional
gap — every category the audit lists (`LOCAL`/`LOOPBACK`/`LINK_LOCAL`/`MULTICAST`/
`BROADCAST`/`DNS_INFRASTRUCTURE`/`CDN`/`CLOUD`/`VENDOR_INFRASTRUCTURE`/`AD_TRACKER`/
`INTERNET`/`UNKNOWN`) already maps onto SOME existing check. Unifying them into one
explicit `classify_destination()` function would improve readability and make future
gaps easier to spot, but isn't fixing a live bug by itself.

**Trigger**: the next time a NEW destination-classification concern comes up (this
session found 3: multicast+reputation, geofencing corroboration, exfiltration
vendor-cloud exemption) — that's 3 different call sites already; a 4th is the signal
it's worth consolidating rather than adding a 4th scattered check.

### H. Signature severity/category taxonomy (audit §13)

**Current state**: Suricata's own numeric severity (1/2/3) maps to confidence
(0.95/0.70/0.45); only severity-1 (`>=0.9`) hard-stops. The rule `category` field
(e.g. "trojan-activity" vs "generic-protocol-command-decode") is captured in evidence
provenance but never used to gate anything.

**Why open, and why NOT implemented speculatively**: checked `.94`'s entire alert
history (`state/alerts.json`, back to 2026-08-17) for real `suricata_matches` —
**zero recorded category data exists in this deployment's history.** Building a
category-based taxonomy now would be pure guesswork with nothing to validate it
against, and Suricata/ET rule categories are a large, externally-maintained taxonomy
this repo has no documented mapping for.

**Trigger**: once Suricata actually fires in production with real category data to
look at — pull a live sample (`suricata_matches` field on real alerts) FIRST, THEN
design the tiering against real categories seen, not a guessed list.

### I. Remove numeric score as the primary decision mechanism (audit §25)

**What the audit proposes**: replace "each hypothesis computes a score, decision engine
thresholds it" with a fully rule-constrained model — evidence supports/contradicts a
hypothesis, evidence quality and independent-family count directly gate the decision
state, with numeric scores (if kept at all) used only for ranking, never as the
mechanism that crosses a threshold into HIGH/CRITICAL.

**Why open**: this is the single largest change in the entire review — it touches
every one of the 11 attack hypotheses' `evaluate()` methods, the decision engine's
entire branching structure, and would invalidate large parts of the existing test
suite's own assumptions (many tests assert specific score values like `3.0`/`4.0`, not
just final states). Not something to attempt inside a single session without dedicated
design time.

**Real counter-consideration worth weighing before committing to this**: the CURRENT
score-based model, combined with this session's fixes (weak-family exclusion via
`NON_ATTACK_FAMILIES`, `num_independent_sources>=2` gating HIGH, the invariant-battery
test suite asserting this directly), already achieves MOST of the practical safety the
audit's rule-constrained model would provide — a hypothesis's raw score is already
structurally prevented from single-handedly reaching HIGH without genuine family
diversity. The audit's proposal is more about **debuggability/legibility** ("score=3.7
therefore HIGH" vs. an explicit reasoning chain) than closing a live gap that isn't
otherwise closed. Worth confirming that framing before a full rewrite, not just
implementing on the audit's say-so.

**Trigger**: a dedicated multi-session design effort, with the current score-based
engine kept running in parallel (shadow mode, same pattern as v13's own rollout against
v-current) for comparison before ever flipping live — this is exactly the kind of change
[[feedback_verify_dont_assume]] and [[feedback_pi_target_and_v13_execution]]'s
autonomous-execution rules require stopping for a real architectural decision on, not
something to build speculatively.

---

## Explicitly excluded from this pass — awaiting the user's own decision

### #10 — CRITICAL without deterministic proof (`tier5_corroborated` path)

Hard-stops (`honeypot`/`arp_spoof`/high-confidence `suricata_signature_match`) are
already fully deterministic. `tier5_corroborated` (external reputation tier 5 +
`independent_sources>=2`) can ALSO reach CRITICAL/auto-block — and that path is
probabilistic (a TI/VT/AbuseIPDB score + corroboration), not deterministic proof, which
is exactly what the audit's Invariant 2 says should never be allowed to auto-block.

This is a real, live tradeoff, not a bug: tightening it to require literal deterministic
proof for EVERY CRITICAL verdict would mean giving up autonomous blocking for
reputation-confirmed threats that never happen to also trip a hard-stop rule — a real
loss of coverage, not a free safety improvement. **Deliberately not changed without the
user's explicit call** — see the conversation this document originated from for the
full framing, and ask before touching `decision/engine.py`'s `tier5_corroborated` branch
for this reason specifically.
