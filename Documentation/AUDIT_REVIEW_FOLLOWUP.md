# External Architecture Review Follow-Up — Roadmap

**Origin**: 2026-09-09. The user shared a ChatGPT-authored critique of 2 real alerts
(a `COORDINATED_TARGETING` alert attributed to `224.0.0.22` showing 1 evidence family,
and a `PEER_COHORT_DEVIATION` alert showing 0 families alongside an 85% attack
confidence) plus a 27-point review of the whole hypothesis/decision architecture
("Threat Combinatorics"). A live 24h data pull against `.94`'s real `state/alerts.json`
confirmed the core complaint was genuine production behavior (34 of 121 real alerts
showed the same "HIGH with 0 evidence families" shape) — not a misreading, but also not
a scoring bug: a display/persistence bug, fixed same-day (`f027a6f`/`cd3d747`/`7d70e10`,
see [`Documentation/ARGUS_ARCHITECTURE.md`](ARGUS_ARCHITECTURE.md#8-threat-categorization--decision-logic)
for the full incident writeup and [[project_v13_alert_quality_fixes]] in memory).

This document tracks everything from that review that is **not** a same-session code
fix — either because it's genuinely large architectural work, or because closer
examination found it needs a decision or more data before it can be implemented safely.
Same discipline as the now-retired remaining-work ledger (its durable rationale items
now live in `Documentation/ARGUS_DECISIONS.md`): each item states *why* it's open and *when*
it should be picked up, not just "not done yet." When an item here gets resolved, move
its outcome into [`Documentation/ARGUS_ARCHITECTURE.md`](ARGUS_ARCHITECTURE.md#8-threat-categorization--decision-logic)
and delete it from here.

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
5. **WHY-block was reading a short-TTL evidence snapshot** (`v13/decision/engine.py`'s
   new `attack_evidence` field, `core/pipeline.py`) — the persisted alert JSON was
   already correct, but the ACTUAL Telegram text still showed 0-1 families because
   `pipeline.py`'s WHY-block looped over its own ~600s-TTL local evidence snapshot
   while the decision itself draws on Argus's 24h graph-window query. Found and fixed
   from 2 real Telegram alerts the user pasted mid-conversation, live-verified against
   the user's own next real alert (not just a data pull).
6. **Reputation evidence/tier ignored known-trusted infrastructure**
   (`core/pipeline.py`, new `reputation_target`-scoped ASN lookup) — the general
   "reputation" evidence (read by every hypothesis) was created purely on "was any
   TI/VT/AbuseIPDB score nonzero," never checking whether the destination is
   known-trusted infra the way `COORDINATED_TARGETING`'s own evidence-creation site
   already does (`a214a2f`). Separately, `rep_classifier.classify()`'s own tier-2
   trusted-infra check existed but asked about `dest_ip`'s ownership instead of
   `reputation_target`'s (can legitimately differ). **Retroactive cleanup**: the code
   fix alone doesn't touch evidence already sitting in the graph (86400s TTL) — a live
   audit of `.94`'s graph db found 70 of 112 distinct "reputation"-evidence
   destinations (62.5%) were known-trusted cloud/CDN infra, some with 100+ stale rows
   each (Amazon `34.200.1.24`: 222 rows, Google `34.54.88.138`: 128) — confirming this
   had been generating false positives at scale for days. User-approved, precisely
   scoped DELETE (`evidence_type="reputation"` only, only those 70 destinations)
   removed 1,466 stale rows; 1,925 legitimate (non-infra) rows left untouched.
7. **Reputation trust-gate missed Telegram's own separate trust list**
   (`intelligence/reputation/classifier.py`, new `is_known_safe_asn_owner()`) — item 6's
   `core/pipeline.py` gate called the shared `utils.is_cloud_cdn_provider_org()` directly,
   but `ReputationClassifier.classify()` internally combines that with its own narrower
   `_SAFE_ASN_OWNER_KEYWORDS` list (just `"telegram"`) — the two checks had silently
   drifted apart. Found live: the user pasted a real alert citing Telegram's own IP
   (`149.154.167.41`) as "poor reputation" even after item 6 was deployed. Fixed by
   extracting one shared method both call sites use, so they can't diverge again.
8. **`winning_evidence` was structurally empty for every `PEER_COHORT_DEVIATION` win**
   (`v13/decision/engine.py`) — it was built from `attack_evidence`, which excludes
   `NON_ATTACK_FAMILIES` (including `peer_cohort_deviation` itself), so the "Talked to N
   distinct destinations vs. peer average" Telegram line had never fired since it was
   written. Fixed by scoping `winning_evidence` from the raw `ev_store` instead —
   verified safe for every other consumer (`COORDINATED_TARGETING`/`DATA_EXFILTRATION`/
   `C2_BEACONING`'s relevant types are all real attack families, unaffected).
9. **`get_distinct_destination_count()` measured detector noise, not real traffic**
   (`v13/graph/store.py`, `v13/ops/live_engine.py`, `core/pipeline.py`) — the metric
   `PeerDeviationHypothesis` compares against a device's peer-cohort average queried
   `SELECT DISTINCT destination_id FROM evidence`, but the `evidence` table only ever
   gets a row when some OTHER detector already flagged something notable — not a record
   of real traffic. This created a self-reinforcing false-positive loop: more noise from
   unrelated detectors → more evidence rows → inflated distinct-destination count →
   additional `PEER_COHORT_DEVIATION` alerts. Confirmed live: a real "laptop cohort
   average of 0.3" and "phone cohort average of 2.2" over 7 days, both absurd for real
   devices, and `PEER_COHORT_DEVIATION` had become ~85% of alert volume. Fixed with a new
   `device_destinations` table (device_id, destination_id, first_seen, last_seen — one
   UPSERTed row per pair, 30-day retention) populated directly from `pipeline.py`'s
   already-computed per-cycle `dest_ips` (no new Zeek query), and repointed
   `get_distinct_destination_count()` at it. User explicitly chose this over disabling or
   just raising thresholds ("Leave it as-is, just fix it properly now"). Needs one full
   peer-comparison cycle of real traffic to accumulate before `PEER_COHORT_DEVIATION`
   alerts show corrected numbers — re-verify against the next real alert.
10. **`soc.service` OOM-crash root-caused and fixed** — user asked "is ollama job
    working," which led to finding `soc.service` had been repeatedly OOM-killed all
    day (confirmed via `journalctl`/`job_health.json`: `ollama_soc`/`live_llm_review`
    both missing several scheduled runs). Two compounding causes, both fixed:
    (a) `fp_engine.py`'s `_load_embed_model()` built its `fastembed.TextEmbedding`
    with no thread limit, defaulting to an 8-wide (nproc) onnxruntime intra-op pool
    for a one-time 53-string embed — `_load_lgbm_model()`, a few hundred lines away,
    already pinned its own onnxruntime session to 1 thread for the same reason; the
    embed loader never got the same treatment. Fixed with `threads=1`, confirmed live
    (8 `fp_embed_loader` OS threads → 1). (b) `middleware/routers/pihole_api.py`'s IPC
    handlers (`_ipc_immunize_logic`/`_ipc_revoke_logic`, the Telegram "Mark False
    Positive"/"revoke" buttons) constructed a brand-new `AutonomousFPEngine()` — 3
    daemon threads + 2 loaded ML models, never torn down — on every request. Replaced
    with a lazy, thread-safe, process-wide singleton; verified under 10 concurrent
    callers (exactly 1 construction). `soc.service`'s `MemoryMax` raised 1G → 2G, both
    as a live runtime override and persisted into the unit file (`INSTALL.md`
    updated to match).
11. **The real OOM root cause: a scheduling collision, not just memory** — even after
    the 2G bump, `soc.service` OOM'd again (peaked at the full 2G plus 2.4G swap).
    `ollama_soc` (cron `30 */4 * * *`, routine ~90-100min runtime) and `live_llm_review`
    (cron `45 */4 * * *`, only 15 minutes later) almost always overlap, since a 15-minute
    offset can't absorb a 90+ minute job — confirmed both of that day's OOM events
    (16:48, 20:48) landed exactly in that overlap window. Fixed by moving
    `live_llm_review` to a full 2-hour offset (`30 2,6,10,14,18,22 * * *`) — checked
    every other scheduled job first, none of them collide with `ollama_soc`'s slots.
    Config-only change on `.94`'s live `config.yaml` (not tracked in git — see
    [[project_v13_full_architecture_shift_plan]] for why that file isn't authoritative
    from this checkout).
12. **Multicast/broadcast addresses could become `reputation_target` via `top_domain`**
    — found while investigating a real `PEER_COHORT_DEVIATION` alert whose "Reputation"
    evidence pointed at `239.255.255.250` (SSDP multicast). Confirmed against `.94`'s
    graph: 782 "reputation" evidence rows for that one address, actively still being
    created (most recent row: seconds before the fix). Root cause: `state.rolling.
    domains`'s keys aren't always real DNS names — a raw destination IP lands there as
    a fallback "domain" when there's no PTR/DNS name, and a chatty multicast address can
    easily be the most frequent such key. `_select_target_domain()` (all 3 priority
    tiers) and pipeline.py's own separate `_rolling_domain_keys` snapshot had no
    multicast/broadcast filtering at all, unlike `dest_ip` elsewhere in the same
    function (`_dest_ip_is_real_host`). Fixed by applying the same
    `is_local_or_multicast_destination()` guard at both source points; verified against
    the real `EnginePipeline._select_target_domain()` method directly.
13. **VeriSign's gTLD-server infrastructure not recognized as trusted** — found while
    auditing the graph for the multicast fix above: 12 (of the 13 total) VeriSign
    gTLD-server anycast IPs (`a.gtld-servers.net` through `m.gtld-servers.net`, the
    `.com`/`.net` TLD root delegation infrastructure) had accumulated ~800 "reputation"
    evidence rows, actively still growing. Confirmed via `.94`'s own GeoIP DB:
    `autonomous_system_organization='VeriSign Global Registry Services'`. Added
    `"verisign"` to `ReputationClassifier._SAFE_ASN_OWNER_KEYWORDS` (the same
    dedicated-infrastructure list Telegram's own IPs already use — deliberately NOT
    `is_cloud_cdn_provider_org()`'s multi-tenant list, since nobody rents compute on a
    gTLD-server IP the way they can on AWS/Azure).
14. **Retroactive graph cleanup for items 12/13 + the earlier-missed Telegram gap** —
    same precedent as item 6's cleanup: the code fixes alone don't touch evidence
    already sitting in the graph (86400s/24h TTL). Enumerated exact scope before
    touching anything: 1,875 "reputation" evidence rows across 17 destinations
    (`239.255.255.250` multicast: 788; `224.0.0.252` multicast: 4; the 13 VeriSign
    gTLD-server IPs: 972 combined; `149.154.167.41`/`149.154.166.110` Telegram: 41
    combined) — all confirmed still actively accumulating right up to the deploy.
    User-approved, precisely scoped `DELETE ... WHERE evidence_type='reputation' AND
    destination_id IN (...)` removed exactly 1,875 rows (verified via `changes()`);
    184 legitimate reputation rows for other destinations left untouched.

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
`Documentation/ARGUS_ARCHITECTURE.md`§8's real production volume data for this
category to see what the CURRENT false-positive/negative shape actually looks like
before redesigning blind.

**Trigger**: a dedicated session with time to (1) pull real DNS-tunneling alert history,
(2) design the new required-evidence model against it, (3) shadow-test before flipping
live — same discipline Argus's own CL-AFPE rollout used.

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

**Trigger**: if `Documentation/ARGUS_ARCHITECTURE.md`§8's volume data (or a future live audit)
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

**Update (2026-09-09, live audit)**: `zeek_notice` (the `B`/`C` row above lists it
under `malicious_ja3`/`malicious_ja4` company implicitly via `network_behavior`, but
it was never actually differentiated from them) turned out to be a single evidence
type silently spanning ALL FOUR classes depending on which real `Notice::Type`/weird
fired — every one of them collapsed into one identical shape (`confidence=0.75`
flat, one family) with the real type surviving only as inert text in `provenance`.
Fixed: `utils.py`'s `classify_zeek_notice()` now grades the actual observed
type into weak/medium/strong/highly_deterministic (grounded in .94's own real
notice.log/weird.log distribution — see its own docstring), `zeek_network.py` sets
confidence per-tier instead of the old flat value, and `v13/hypotheses/engine.py`'s
`NetworkIntrusionHypothesis`/`DeviceProfileBenignHypothesis` read the tier (a
provenance subtag, `detector:zeek:notice:{tier}:{note_type}`) instead of treating any
`zeek_notice`'s mere presence as equally notable. Concretely: weak-tier notices (TCP-
capture/framing artifacts — confirmed the single most common one,
`weird:data_before_established`, alone fired 68,575 times on .94's real network) now
contribute nothing to either hypothesis; only medium-or-above notices can activate/
corroborate `NetworkIntrusionHypothesis` or block `DeviceProfileBenignHypothesis`'s
benign verdict. `zeek_notice` itself stays classified as class B/C on this table
(it's evidence a hypothesis CAN score on, at varying strength) — this update is about
making that strength real instead of assumed.

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

### I2. Extend known-trusted-infra exemption to behavioral evidence types (found live, 2026-09-09)

**Current state**: the "reputation" evidence-creation gap (item 6 above, "Fixed this
same session") is closed — known-trusted cloud/CDN infra (Google/Microsoft/Amazon/
Cloudflare/Akamai/Netflix/Alibaba/Hetzner, `is_cloud_cdn_provider_org()`) can no longer
produce false "poor reputation" evidence. But the SAME live alert that surfaced that
bug also showed `zeek_conn_abuse` ("many rejected connections") firing against Google
(`142.251.141.33`) and `dns_evasion_anomaly` ("no matching DNS lookup history") firing
against an unrecognized German ISP (`62.245.139.33`) in the SAME cycle — neither of
those evidence types has ANY trusted-infra exemption at all.

**Why NOT extended the same day**: this is NOT the same risk shape as the reputation
case. Reputation evidence is a cheap, external, often-noisy TI/VT/AbuseIPDB score —
exempting known-trusted ASN owners from it is low-risk (the same score for the SAME
IP wouldn't mean much even if genuine, since shared cloud IPs commonly accumulate
noise from OTHER tenants). `zeek_conn_abuse`/`dns_evasion_anomaly` are about THIS
DEVICE'S OWN observed behavior — a stronger, more direct signal. This codebase's own
`_CLOUD_CDN_ORG_KEYWORDS` docstring (`utils.py`) already warns against a blanket
"trust this cloud provider" list specifically because it "would create a real blind
spot for C2 hosted on the same infrastructure" — malware is commonly hosted on major
cloud providers precisely to blend into traffic exactly like this. A device
genuinely compromised and beaconing to a C2 server hosted on AWS/GCP/Azure would
produce EXACTLY these two evidence shapes, and a blanket exemption would blind the
engine to it.

**Proposed approach, NOT a quick copy-paste of the reputation fix**: if picked up,
needs its own design pass distinguishing "this destination is trusted" from "this
device's OWN behavior toward it is anomalous regardless of the destination's
identity" — e.g. `zeek_conn_abuse`'s existing `own_dns_failing` dampener (this device's
own blocked/nxdomain ratio) is the right SHAPE of signal (behavioral context about
THIS device, not identity-based trust about the destination), not a `is_cloud_cdn_
provider_org()` exemption. Possibly: dampen confidence rather than suppress outright,
or require a SECOND corroborating signal before a known-cloud-IP-targeted
`zeek_conn_abuse`/`dns_evasion_anomaly` item counts toward `independent_sources`
(mirroring how `peer_cohort_deviation`/`ml_anomaly`/`policy` are already excluded from
counting, this session's own earlier fixes) rather than not creating the evidence at
all.

**Trigger**: a dedicated look at real production volume for `zeek_conn_abuse`/
`dns_evasion_anomaly` against known-cloud destinations specifically (mirroring how
item 6's reputation cleanup started with a live graph-db audit, not a guess) — check
whether this is ALSO a large-scale pattern before designing the fix, since the
reputation case turned out to be 62.5% of all reputation evidence and the fix's shape
depended on knowing that scale.

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
engine kept running in parallel (shadow mode, same pattern as Argus's own rollout against
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
