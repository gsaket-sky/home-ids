# Threat Category Reference — every verdict this engine can produce, and every
# combination that produces it

Companion to [`ALERT_CATEGORIZATION_CATALOG.md`](ALERT_CATEGORIZATION_CATALOG.md) (which
tracks real production *volume* per category, last audited 2026-08-27 against
`core/decision_engine.py`) and [`DECISION_LOGIC_DEPENDENCY_MAP.md`](DECISION_LOGIC_DEPENDENCY_MAP.md)
(which tracks function-level call chains). This document answers a different question:
**for a given threat category, exactly which evidence, in exactly which combination, produces
it** — read straight from the live source, not inferred from alert samples.

**Live engine confirmed 2026-09-08** (`.94`, direct SSH check, not assumed): `config.yaml` has
`engine: v13` and `cl_afpe_engine: v13`. This document describes **v13's** engine
(`src/v13/hypotheses/engine.py` + `src/v13/decision/engine.py` for Layer 1,
`src/v13/cl_afpe/engine.py` for Layer 2) — a faithful, line-for-line port of
`core/decision_engine.py`/`intelligence/fp_engine.py` (v-current) with the specific
differences called out inline below. `ALERT_CATEGORIZATION_CATALOG.md`'s Layer 1 table
describes v-current's code; treat this document as authoritative for what actually decides a
verdict on `.94` right now.

**How to keep this current**: update this file in the same change that touches
`v13/hypotheses/engine.py`, `v13/decision/engine.py`, `v13/hypotheses/independence.py`,
`v13/cl_afpe/engine.py`, or `pipeline.py`'s destination-attribution switch (§8) — same discipline
as the two companion docs above.

---

## 1. The three decision layers, in order

Every alert passes through all three; each can only ever narrow or override what the previous
layer said, never see less information than it had.

| Layer | Module (live) | Question it answers | Can it escalate? | Can it suppress? |
|---|---|---|---|---|
| 1 — HEE (Hypothesis Evidence Engine) | `v13/hypotheses/engine.py` + `v13/decision/engine.py` | "What does the evidence, taken together, say happened?" → BENIGN / ANOMALOUS / SUSPICIOUS / HIGH / CRITICAL | N/A (this IS the initial verdict) | No — it can only choose not to escalate |
| 2 — CL-AFPE (autonomous false-positive engine) | `v13/cl_afpe/engine.py` | "Have we already learned this specific target is safe, or does a model say this looks like noise?" | Yes — a **hard-stop trigger firing on a trust-cached target** overrides a cached "safe" verdict back to CONFIRMED_THREAT | Yes — `FALSE_POSITIVE` verdict sets `suppress=True`, which silences Telegram/containment but never un-writes the Layer‑1 verdict from `alerts.json` |
| 3 — LLM batch review | `scripts/ollama_soc.py` (v-current, live, 4-hourly) — `v13/ops/live_llm_review.py` runs in parallel as a **shadow comparator only**, not yet decision-making | "Does an LLM, shown only the evidence (never the verdict), independently agree?" | Yes — `malicious` + valid → `record_confirmed_threat()` + sigma tune-up | Yes — `benign` + `suppress` + valid + not-already-actioned → autonomous `mark_false_positive()` |

Layer 1's verdict is what gets written to `alerts.json` and what Layers 2/3 evaluate against —
it is never silently replaced, only annotated with `fp_verdict`/a later LLM-review record.

---

## 2. Layer 1 — every attack hypothesis, exact trigger, exact score ladder

Each hypothesis's `evaluate()` returns **0.0** (required evidence absent — hypothesis doesn't
apply) or a score on a fixed ladder: **2.0** (bar just cleared) → **3.0** (a "strong" signal
present) → **4.0** (strong signal + a second confirming condition). The **decision engine**
(§3) then compares the single highest-scoring attack hypothesis against the highest-scoring
benign hypothesis and the independence-family count to pick a final state.

`rep_vector.tier ∈ {1,2}` (trusted/known-safe destination) sets `contradicting_score += 1.0` for
a hypothesis, blocking every score bump gated on "contradicting == 0"; a `tier` in the
hypothesis's own escalation range (varies per hypothesis — see each entry below) does the
opposite. This is the single most important cross-cutting rule in the whole engine — **but as of
`428d35a` (2026-09-09) it is no longer the SAME `rep_vector` blindly reused for every hypothesis**.

⚠️ **`rep_vector.tier` alone is never what a hypothesis actually reads.** `pipeline.py` computes
ONE `ReputationVector` per device per cycle, for whichever destination earned the highest
TI/VT/AbuseIPDB risk score THAT cycle (`reputation_target`) — structurally unrelated to any given
hypothesis's own evidence destination. Every attack hypothesis below routes its tier check through
`Hypothesis._effective_rep_tier(ev_store, rep_vector)` (base class,
`v13/hypotheses/engine.py`) instead of reading `rep_vector.tier` directly: it compares
`rep_vector.domain` against the REAL `destination_id`(s) of that hypothesis's own
`RELEVANT_EVIDENCE_TYPES` evidence, and returns tier **3** (neutral/"unclassified" — never
suppresses, only escalates hypotheses whose own ladder already treats bare-unclassified as
escalation-eligible) whenever both sides carry a real destination and they provably differ. When
either side lacks destination info (e.g. `PEER_COHORT_DEVIATION`'s own evidence, which is
device-level by design), the ambiguous case is left alone — `rep_vector.tier` applies unchanged,
same "never touch the ambiguous case" discipline as §4's domain-linkage reputation-stripping
filter. This generalizes `a214a2f` (which only fixed `COORDINATED_TARGETING` specifically, via
its own local ASN-owner lookup at evidence-creation time — still true, unchanged, and still the
right approach for a hypothesis whose evidence isn't a *pipeline.py* Evidence item at all).

**Update, same day**: `ADVERTISING_BURST`/`DEVICE_PROFILE_TELEMETRY` (the 2 BENIGN hypotheses whose
verdict is *gated* on `rep_vector.tier`, not just adjusted by it) were reconsidered and also wired
through `_effective_rep_tier()` — declared `RELEVANT_EVIDENCE_TYPES = {"dns_rate"}`. This is a
NO-OP in production today (`dns_rate`, `detectors/dns_behavior.py`, never sets `.domain` — a
device-wide rate aggregate, no destination to compare against, same shape as `DNS_TUNNELING`), but
closes a LATENT risk worse than the attack-hypothesis case: an unrelated cycle's `rep_vector`
wrongly APPROVING real attack traffic as benign needs less corroboration to go wrong than wrongly
suppressing an attack hypothesis does (a single required gate, not a corroboration count) — and
`dns_rate`'s destination gap could close the same way `zeek_exfiltration`/`zeek_beaconing`'s
identical gap already did (§8). `LOCAL_DEVICE_DISCOVERY` is the one hypothesis (benign or attack)
with genuinely zero `rep_vector` usage at all — nothing to wire.

### DNS_TUNNELING
- **Requires**: `dns_rate > 100` **AND** `dns_entropy > 4.0` (both, not either)
- **3.0** if `dns_unique_ratio > 0.8` also present, tier not (1,2)
- **4.0** if the above **and** `rep_vector.tier == 4` exactly (tightened from `∈ {3,4}` by the
  2026-09-09 third-party review — tier 3 means "unclassified, no external signal at all," not
  weak evidence of anything; being unclassified no longer helps this hypothesis reach its own
  ceiling. Doc corrected 2026-09-09, code was already live)
- Evidence family: `dns_behavior` only — this hypothesis can never combine with itself for a
  2nd independent source; needs a genuinely different family (e.g. `reputation`) to reach HIGH.
- Its own evidence (`dns_rate`/`dns_entropy`/`dns_unique_ratio`) never carries a destination — see
  §8, `DNS_TUNNELING` row.

### NETWORK_INTRUSION / LATERAL_MOVEMENT (same class, dynamic name)
- **Requires ANY of**: `zeek_lateral_scan>0`, `malicious_ja3`/`malicious_ja4` present,
  `arp_spoof_pending` (a single/uncorroborated MAC flip), or a bare `zeek_notice`
- Name becomes **LATERAL_MOVEMENT** if `zeek_lateral_scan` fired, else **NETWORK_INTRUSION**
- **3.0** if 2+ of {lateral_scan, malicious_tls, mac_flip} present, OR (a notice + 1 of those)
- **4.0** if `zeek_lateral_scan` fired at all (contradicting==0) — lateral scan alone is treated
  as strong enough to hit the ceiling regardless of corroboration
- **Broadest `required_satisfied` bar in the whole engine** — a bare `zeek_notice` (Zeek's own
  generic policy-notice channel, includes things like `SSL::Invalid_Server_Cert` on a
  self-signed local device) is enough on its own to clear 2.0. This is why it shows up as the
  evidence behind so many otherwise-thin verdicts (see §5's live incident).

### DGA_BOTNET_C2
- **Requires**: `dns_dga_burst` present
- **3.0** if best DGA-evidence weight ≥ 0.6, tier not (1,2)
- **4.0** if weight ≥ 0.85 **and** `dns_rate > 100` also present **and** tier ∈ {3,4,5}

### DATA_EXFILTRATION
- **Requires**: `zeek_exfiltration` present
- **3.0** if weight ≥ 0.6, OR if `zeek_beaconing`/`reputation`/`first_contact` also present
  (Phase 1a bugfix — these used to be computed but never actually consulted)
- **4.0** if weight ≥ 0.85

### C2_BEACONING
- **Requires**: `zeek_beaconing` present
- **3.0** if `zeek_exfiltration`/`reputation`/`malicious_ja3`/`malicious_ja4`/`first_contact`
  also present
- **4.0** if the above **and** weight ≥ 0.85

### DNS_COVERT_TUNNELING
- **Requires**: `dns_tunnel_v2` present
- **3.0** if 2+ distinct provenance subtags present (different detection signals agreeing),
  OR `first_contact` also present
- **4.0** if the above **and** weight ≥ 0.85 **and** tier ∈ {3,4}

### COORDINATED_TARGETING
- **Requires ANY of**: `coordinated_targeting` (2+ devices → same destination),
  `fingerprint_campaign` (2+ devices → same JA3/JA4 hash), `dga_seed_campaign`
  (2+ devices → same computed DGA generation shape) — all three synthesized fresh
  **every cycle** by `v13/ops/live_engine.py`, never persisted to the graph (derived context,
  not a sensor observation)
- **3.0** if weight ≥ 0.6, tier not (1,2)
- **4.0** if weight ≥ 0.85 **and** 3+ total devices sharing the signal
- ⚠️ **Two live bugfixes, 2026-09-08** (both in `GraphStore.get_devices_targeting()`, the query
  `coordinated_targeting`'s evidence is built from): (1) a multicast/broadcast/link-local
  destination (mDNS `224.0.0.251`/`ff02::fb`, SSDP `239.255.255.250`, ICMPv6 ND/MLD) never
  counts — every device sends to these as ordinary LAN presence, so "2+ devices touched it" was
  always true and meant nothing; (2) a **private** destination touched by ≥40% of the known
  device fleet (min fleet size 5) also never counts — confirmed live: a household's own second
  Fire TV, touched by 7/7 known devices, was scoring as "coordinated targeting" and got
  auto-blocked repeatedly. See `git log` on `src/v13/graph/store.py` (commits `1ff6c97`,
  `2367f77`) for the full incident. **A minority of the fleet (< 40%, or any absolute count in
  a small ≤4-device network) sharing an unusual destination still counts as real signal** — the
  fix is a floor on "structurally common," not a ceiling on cross-device correlation itself.

### CONNECTION_ABUSE / PORT_SCAN / INTERNAL_RECONNAISSANCE (same class, dynamic name)
- **Requires ANY of**: `zeek_conn_abuse` (external-facing scan shape), `zeek_long_conn`
  (abnormally long-lived connection), `arp_sweep` (local ARP sweep)
- Name: **INTERNAL_RECONNAISSANCE** if only `arp_sweep`, **PORT_SCAN** if only
  `zeek_conn_abuse`, **CONNECTION_ABUSE** if only `zeek_long_conn` or 2+ categories present
- **3.0** if weight ≥ 0.6, tier not (1,2)
- **4.0** if 2+ of the three categories present at once (tier not (1,2))

### DNS_POLICY_BYPASS / DNS_EVASION / DNS_ATTRIBUTION_GAP (same class, dynamic name)
- **Requires**: `dns_evasion_anomaly` present
- Name picked from the evidence's own provenance subtag: `policy_bypass` →
  **DNS_POLICY_BYPASS** (device queried a resolver other than the network's configured one —
  actively evading DNS-based blocking), `no_dns_history` → **DNS_EVASION** (connection with no
  preceding DNS lookup at all — the classic DoH/hardcoded-IP evasion shape), anything else →
  **DNS_ATTRIBUTION_GAP** (a partial/ambiguous gap — by far the largest single category in
  production, see `ALERT_CATEGORIZATION_CATALOG.md`)
- **3.0** if weight ≥ 0.6, tier not (1,2)
- **4.0** if any OTHER evidence type also present alongside it (tier not (1,2))

### SIGNATURE_MATCHED_THREAT
- **Requires**: `suricata_signature_match` present (a real Suricata rule hit, from the
  reactive-capture batch pcap scan)
- **3.0** if weight ≥ 0.6, tier not (1,2)
- **4.0** if weight ≥ 0.85, OR if 2+ separate signature hits present

### PEER_COHORT_DEVIATION
- **Requires**: `peer_deviation` present — synthesized by `live_engine.py` when this device's
  own 7-day distinct-destination count is ≥3x its `device_type` cohort's average (min 2 real
  peers, min absolute count 5)
- **3.0 ceiling — can never reach 4.0 on its own**, deliberately: this is a genuinely new,
  unvalidated anomaly heuristic (Release 14, N2). It needs a second, independently-sourced
  hypothesis to ever reach HIGH (the decision engine's own ≥2-independent-source gate, §3).
- ⚠️ Same 2026-09-08 bugfix as COORDINATED_TARGETING, different mechanism: the underlying
  `GraphStore.get_distinct_destination_count()` used to compute "my destination count" now
  excludes multicast/broadcast destinations too — every device's count was inflated by the same
  handful of protocol-group addresses (mDNS/SSDP/ICMPv6-ND), which distorted the peer-cohort
  comparison independent of any real behavioral difference between devices.

---

## 3. Layer 1 — the four hard-stops (checked BEFORE any hypothesis score)

Hard-stops are a **pluggable registry** (`v13/decision/engine.py::DEFAULT_HARD_STOP_REGISTRY`),
checked first, in order; first match wins and skips hypothesis-score logic entirely.

| Hard-stop | Trigger | Freshness | Needs corroboration to reach CRITICAL? |
|---|---|---|---|
| `honeypot` | `features["zeek_honeypot_hits"] > 0` and device not in `safe_ips` | n/a (raw feature, not evidence-store TTL) | No — always CRITICAL/block |
| `arp_spoof` | Fresh `arp_spoofing` evidence (a **second** MAC flip within 600s on the same IP) | 120s | No — always CRITICAL/block |
| `geofence` | Fresh `geofencing_violation` evidence | 120s | **Yes** — needs `num_independent_sources≥1 AND attack_score>benign_score`; uncorroborated → HIGH/alert instead of CRITICAL/block, confidence 0.70, explanation suffixed "(Uncorroborated)" |
| `confirmed_exploit` | Fresh `suricata_signature_match` evidence with `confidence≥0.9` | 120s | No — always CRITICAL/block |

v13's freshness-aware-by-default behavior for all four is a genuine, deliberate divergence from
v-current's *current live* code (which only makes `honeypot` freshness-aware today; the other
three's freshness checks exist in v-current but stay shadow-only pending divergence data per
Gap 3 — see `DECISION_LOGIC_DEPENDENCY_MAP.md`). v13 simply always applies it.

---

## 4. Layer 1 — the full decision tree (after hard-stops)

Checked in this exact order once no hard-stop fired (`v13/decision/engine.py::evaluate()`):

1. **`rep.tier == 5`** (confirmed-tier reputation):
   - `rep.verified_ioc` (real curated threat-intel match, `ti_score>2.0`) → **CRITICAL** /
     block / "Confirmed Malicious IOC", confidence 0.99
   - else, `num_independent_sources≥1 AND attack_score>benign_score` → **CRITICAL** / block /
     "Corroborated Reputation Signal", confidence 0.85
   - else → **SUSPICIOUS** / monitor / "Elevated Reputation Signal (Unconfirmed, Tier 5 Score)",
     confidence 0.45
2. **`attack_score > benign_score AND attack_score ≥ 2.0`** (a hypothesis from §2 fired and beat
   the best benign explanation):
   - `num_independent_sources≥2 AND attack_score≥3.0` → **HIGH** / alert, confidence 0.85
   - else → **SUSPICIOUS** / monitor, confidence 0.40
3. Neither of the above:
   - `rep.tier==4 AND max(vt,ti,abuse)≥1.5` → **SUSPICIOUS** / monitor / "Elevated Reputation
     Signal (Unconfirmed)", confidence 0.45
   - else `ml_anomaly` evidence with `value>0.90` → **ANOMALOUS** / log / "ML Anomaly Only",
     confidence 0.10
   - else → **BENIGN** / suppress (never written to `alerts.json` at all)

**`num_independent_sources`** = count of DISTINCT `independence_family` values across
`attack_evidence` (all evidence whose family isn't in `NON_ATTACK_FAMILIES` —
`local_context`/`novelty_context`), after a domain-linkage filter strips a `reputation`-family
item that names a destination different from the winning hypothesis's own relevant evidence.
See `v13/hypotheses/independence.py` for the full family map — this is the single number that
decides whether an attack hypothesis reaches HIGH or stalls at SUSPICIOUS, so a hypothesis
firing on evidence from only ONE family (e.g. `DNS_TUNNELING` on `dns_behavior` alone) can never
reach HIGH by itself, no matter how high its own score climbs.

### Independence families (evidence type → family)

| Family | Evidence types | Notes |
|---|---|---|
| `dns_behavior` | `dns_entropy`, `dns_rate`, `dns_unique_ratio`, `dns_tunnel_v2`, `dns_dga_burst`, `dns_evasion_anomaly` | All derived from the same DNS query stream |
| `tls_fingerprint` | `malicious_ja3`, `malicious_ja4` | Same underlying sensor (ClientHello) |
| `network_behavior` | `zeek_notice`, `zeek_lateral_scan`, `zeek_conn_abuse`, `zeek_long_conn` | General Zeek flow-level notices |
| `data_transfer_pattern` | `zeek_exfiltration`, `zeek_beaconing` | Traffic volume/timing — distinct vantage point from flow notices even though both are Zeek |
| `network_recon` | `arp_sweep`, `arp_spoof_pending`, `arp_spoofing` | ARP-layer, same underlying sensor |
| `reputation` | `reputation` | External TI lookup — independent of any on-network sensor |
| `direct_observation` | `honeypot_access` | A device actually touching the honeypot |
| `policy` | `geofencing_violation` | A fact about the destination, not first-hand device behavior |
| `signature_match` | `suricata_signature_match` | A curated ruleset, not behavioral inference |
| `ml_anomaly` | `ml_anomaly` | An ML model's own output |
| `cross_device_correlation` | `coordinated_targeting`, `fingerprint_campaign`, `dga_seed_campaign` | "Another device independently corroborating this" — same vantage point across all three shared-signal types |
| `peer_cohort_deviation` | `peer_deviation` | THIS device diverging from its own peer cohort — distinct from cross-device correlation |
| `local_context` *(non-attack)* | `local_device_discovery` | Legitimate UPnP/SSDP discovery — never counts toward an attack verdict |
| `novelty_context` *(non-attack)* | `first_contact` | A fact ABOUT an observation (novelty), not an independent signal on its own |

---

## 5. Worked example — the exact live incident that found the two bugfixes above

`amazon-FireTV-LG` (192.168.77.42), 2026-09-08 22:18, real production alert:

1. A Zeek policy notice fires: `SSL::Invalid_Server_Cert` on `192.168.77.47` → one
   `zeek_notice` evidence item, family `network_behavior`. **NETWORK_INTRUSION** required-bar is
   just "any notable notice," so it fires at the base **2.0**.
2. `live_engine.py` separately synthesizes `coordinated_targeting` evidence because
   `192.168.77.47` (this household's OTHER Fire TV) was touched by several other devices —
   family `cross_device_correlation`, a SECOND, DIFFERENT family from the zeek_notice above.
   **COORDINATED_TARGETING** fires at its own 3.0.
3. Decision engine: winning attack = `COORDINATED_TARGETING` (3.0) > benign (0.0),
   `num_independent_sources = 2` (`network_behavior` + `cross_device_correlation`) →
   **2≥2 and 3.0≥3.0 → HIGH**, and Telegram fires + a Pi-hole domain block executes.
4. Ground truth: `.47` is legitimate shared household infrastructure (7/7 known devices touch
   it) and the SSL cert warning is the ordinary self-signed-cert shape a local device presents —
   **not an attack**. `hee_evidence_families` on the persisted alert only ever showed
   `["zeek_network"]` (one family) because that field is computed from a DIFFERENT, narrower
   evidence list than `num_independent_sources` (which correctly includes the ephemeral,
   never-persisted synthetic evidence) — a real, separate display-confusion issue, not itself a
   scoring bug.
   - **Fixed 2026-09-09** (`f027a6f`), same underlying gap generalized: a live 7h audit against
     the `9e150ba` deploy found `COORDINATED_TARGETING`/`PEER_COHORT_DEVIATION` were 57% of
     unsuppressed HIGH alerts, almost all displayed against a multicast/broadcast/`unknown`
     destination — `pipeline.py`'s per-signature destination-attribution switch (§8 below) had no
     branch for either, so display fell through to "whatever this device connected to most
     recently." `v13/decision/engine.py::evaluate()` now returns `winning_evidence` (the winning
     hypothesis's own relevant evidence, real destination + features) specifically so
     `pipeline.py` never has to re-derive this from a differently-scoped list again. A follow-up
     pass the same day found and fixed the identical gap for 4 more signatures
     (`DNS_TUNNELING`/`DATA_EXFILTRATION`/`C2_BEACONING`/`SIGNATURE_MATCHED_THREAT`) — see §8.
   - **Correction**: `f027a6f` fixed the DESTINATION display for these two signatures, but the
     `hee_evidence_families`/WHY-block problem described in the paragraph above was a SEPARATE
     bug that fix didn't reach — confirmed live via a real 24h alert pull (an external
     architecture review's audit of 2 real alerts prompted the check): 34 of 121 real alerts
     still showed `hee_evidence_families=[]` while `hee_independent_sources` correctly showed
     2-4. Actually fixed 2026-09-09 (`cd3d747`, corrected same day in `7d70e10` — the first
     version wrongly let `peer_deviation` count toward the family total, when
     `hypotheses/independence.py`'s own `NON_ATTACK_FAMILIES` deliberately excludes it):
     `decision/engine.py::evaluate()` now also returns `evidence_families`/`evidence_types`
     (the literal set `independent_sources` counts against); `pipeline.py` unions these into
     the persisted fields and bridges `winning_evidence` into the WHY-block's evidence grouping
     for the same 4 synthetic types, routing `peer_cohort_deviation` into the existing
     "shown, not counted" bucket (`context_evidence`, same treatment `local_context` gets).
     Live-verified against a real post-deploy alert.

This example is preserved here specifically because it demonstrates the general pattern this
whole document exists to make legible: **a HIGH verdict routinely comes from two cheap,
independently-weak signals landing in two different families on the same cycle**, not from one
strong signal. Auditing "is this a real threat" always requires checking what's BEHIND
`num_independent_sources`, never trusting the count alone.

---

## 6. Layer 2 — CL-AFPE (`v13/cl_afpe/engine.py`), exact stage order

Runs on every alert AFTER Layer 1, independently of it. Can suppress a HIGH/CRITICAL verdict or
confirm a low one; never sees or modifies the Layer‑1 state field itself.

1. **Trust-cache fast path**: if the target (base eTLD+1 domain, or dest IP) is in the 14-day
   dynamic trust cache (`immunize()`), re-run Stage 1 anyway (a cached target is never blindly
   trusted past a hard-stop re-firing):
   - Stage 1 fires anyway → `CONFIRMED_THREAT`, stage `TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP`
   - Stage 1 clean → `FALSE_POSITIVE`, confidence 1.0, stage `TRUST_CACHE`, `suppress=True`
2. **Stage 1 hard-stop** (8 checks, first any-match short-circuits): (0) Layer‑1 already said
   CRITICAL; (1) `ti_risk > 2.0`; (2) lateral movement with ≥2 distinct targets; (3) malicious
   JA3/JA4; (4) honeypot hit; (5) `abuseipdb_risk ≥ 4.0`; (6) exfil payload burst
   (`outbound_bytes_z > 5.0` AND `outbound_bytes > 2.5MB`, exempting known telemetry/CDN
   domains); (7) local confirmed-intel store match. Any hit → `CONFIRMED_THREAT`, stage
   `STAGE_1_HARD_STOP`, sigma TUNE_UP, feeds the local confirmed-intel store.
3. **Stage 2 (LightGBM)** + **Stage 3 (FastEmbed)**: `combined = combine_scores(lgbm_prob,
   embed_sim, 0.82)`. Compared against `effective_suppress_threshold` (per-device profile,
   default **0.80**) and a fixed **uncertain floor of 0.55**:
   - `combined ≥ 0.80` → attempt `mark_false_positive()`. If it refuses (alert carries a
     hard-stop-equivalent signature) → `UNCERTAIN`, publishes at full severity anyway. Else →
     `FALSE_POSITIVE`, `suppress=True`, immunizes the domain.
   - `0.55 ≤ combined < 0.80` → `UNCERTAIN`, publishes normally, flagged low-confidence.
   - `combined < 0.55` → `CONFIRMED_THREAT`, publishes at full severity, sigma TUNE_UP.

`v13/ops/live_llm_review.py` re-derives `coordinated_targeting` at review time (anchored to the
ORIGINAL decision's own timestamp, not review-time "now") purely so the LLM prompt sees the same
context the live decision saw — it does not feed back into live suppression.

---

## 7. Layer 3 — LLM batch review (`scripts/ollama_soc.py`, still v-current, live)

Runs every 4 hours, `classification: benign|malicious`, gated by
`DeterministicValidator` (`intelligence/ai_soc.py`) which rejects an LLM verdict outright when:
- `benign` claimed but a confirmed IOC (`≥4.0`) is present in reconstructed reputation evidence
- `benign` claimed but the deterministic verdict already corroborated an attack hypothesis
  across independent families for this exact alert (ground-truth cross-check against
  `hee_independent_sources`/`hee_decision_path` persisted by Layer 1)
- `benign` claimed but persisted `hee_evidence_types` includes an attack-shaped type
  (`arp_sweep`, `zeek_lateral_scan`, a malicious TLS fingerprint, etc.)
- `benign` claimed but the destination isn't trusted/familiar to this specific device
- the model's own `supporting_evidence` is empty or self-contradictory
- `malicious` claimed but the model's reasoning cites a prior risk score it was never shown
  (circular-reasoning guard)

`benign + suppress + valid` → autonomous `mark_false_positive(source="llm_validated")` + release
any active containment. `malicious + valid` → `record_confirmed_threat()` + sigma TUNE_UP.

---

## 8. Destination attribution — what a persisted alert's `network_context.destination_ip` /
Telegram "Contacted" line actually shows, per signature

The winning hypothesis (§2/§4) decides the VERDICT; a separate, per-signature switch in
`pipeline.py` (`src/core/pipeline.py`, ~1713-1935) decides what destination gets DISPLAYED and
PERSISTED as the cause. These are two different code paths reading two different evidence
representations, and a signature missing from this switch silently displays "whatever this
device connected to most recently" instead of its own real evidence — not a scoring bug, but
routinely mistaken for one (§5's worked example, the original Telegram-formatting complaint that
started the 2026-09-08/09 review).

| Signature | Real destination source | Notes |
|---|---|---|
| `DNS_EVASION`/`DNS_ATTRIBUTION_GAP`/`DNS_POLICY_BYPASS` | `dns_evasion_anomaly.domain` | Structurally has no queried domain by design — `alert_target_domain` explicitly `"unknown"`, never the coincidentally-queried fallback |
| `DNS_COVERT_TUNNELING` | `dns_tunnel_v2.domain` | |
| `DGA_BOTNET_C2` | `dns_dga_burst.domain` | |
| `Confirmed Malicious IOC` | `reputation_target` (the same value `rep_vector` was classified from) | |
| `CONNECTION_ABUSE`/`PORT_SCAN`/`INTERNAL_RECONNAISSANCE` | `zeek_conn_abuse.domain`, else `arp_sweep.domain` | Prefers the more specific single-target signal over an arbitrary one of many swept IPs |
| `NETWORK_INTRUSION`/`LATERAL_MOVEMENT` | `zeek_lateral_scan`/`malicious_ja3`/`malicious_ja4`/`zeek_notice.domain` | |
| `COORDINATED_TARGETING` | `decision["winning_evidence"]`, `evidence_type=="coordinated_targeting"` | v13-only synthetic evidence (§2) — never in `pipeline.py`'s own v1 evidence store, only ever existed inside `decision/engine.py::evaluate()`'s own call. **Fixed 2026-09-09 (`f027a6f`)** — no branch existed before this |
| `PEER_COHORT_DEVIATION` | n/a — explicit `"unknown"` | `peer_deviation` evidence is device-level by design (`destination_id=NO_DESTINATION`, live_engine.py) — no destination to show. Telegram message shows the real behavioral stat (`my_count`/`peer_avg`/`peer_count`) instead of a "Contacted" line. **Fixed 2026-09-09 (`f027a6f`)** |
| `DNS_TUNNELING` | n/a — explicit `"unknown"` | `dns_rate`/`dns_entropy`/`dns_unique_ratio` (`detectors/dns_behavior.py`) never set `.domain` — a genuine device-wide DNS-rate aggregate, no single destination. **Fixed 2026-09-09 (`428d35a`+same-day follow-up)** |
| `DATA_EXFILTRATION` | `decision["winning_evidence"]`, `evidence_type=="zeek_exfiltration"` | `zeek_exfiltration` never sets `.domain` in `threat_signals.py` either, but `v13/ops/live_engine.py`'s own `_NEEDS_LAST_DEST_IP_FALLBACK` already patches this with a last-known-dest-IP fallback when converting to v13's evidence model — `winning_evidence` gets it for free. **Fixed 2026-09-09 (same-day follow-up)** |
| `C2_BEACONING` | `decision["winning_evidence"]`, `evidence_type=="zeek_beaconing"` | Same fallback mechanism as `DATA_EXFILTRATION` above. **Fixed 2026-09-09 (same-day follow-up)** |
| `SIGNATURE_MATCHED_THREAT` / `Confirmed Exploit/Malware Signature (Suricata)` | `suricata_signature_match.domain` (`detectors/suricata_scan.py` sets this directly, `target_ip`) | Two different verdict PATHS (§2 hypothesis vs. §3 hard-stop) over the same evidence type. **Fixed 2026-09-09 (same-day follow-up)** |
| `Layer-2 ARP Spoofing Detected` | `arp_spoofing.domain` | |
| `Internal Honeypot Accessed` | `honeypot_access.domain` | |
| `Geofencing Policy Violation` (± `(Uncorroborated)`) | `geofencing_violation.domain` | |

**If a NEW signature is ever added** (a new hypothesis name, or a new hard-stop explanation),
check this table — a missing branch doesn't error, it silently degrades to "most recent
connection," which is how this whole class of bug went unnoticed for as long as it did.
`decision["winning_evidence"]` (populated for any attack-hypothesis-driven verdict, empty list
otherwise) is the right source for any hypothesis whose real evidence is v13-only-synthetic or
carries a fallback destination; `active_evidence` (`pipeline.py`'s own v1 evidence store) is
right for anything a real detector attaches `.domain` to directly.
