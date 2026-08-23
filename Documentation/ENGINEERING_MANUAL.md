# ⚙️ Home-IDS: Engineering & Architecture Manual

This manual is written for developers, security engineers, and data scientists. It explores the internal mathematics, system architecture, and code-level orchestration of Home-IDS.

Unlike the User Manual (which explains *how to use* the system), this document explains exactly **how the system is built** and **why the mathematics work**.

**A note on accuracy**: an earlier revision of this document described an `asyncio`-based event loop, a Fourier-transform diurnal-rhythm analysis, and a learned, per-device Markov transition matrix that "mathematically approaches 0.0001" over months of history — none of which exist anywhere in this codebase. Every claim below has been checked directly against the running source (file and line references included) rather than carried forward from that earlier description.

---

## 📋 Table of Contents
1. [Core Architecture & The Real-Time Pipeline (`pipeline.py`)](#1-core-architecture--the-real-time-pipeline-pipelinepy)
2. [The Hypothesis & Evidence Engine (HEE)](#2-the-hypothesis--evidence-engine-hee)
3. [Machine Learning Methodologies](#3-machine-learning-methodologies)
4. [Temporal Mathematics & Baselining](#4-temporal-mathematics--baselining)
5. [The Autonomous Self-Calibration Loop](#5-the-autonomous-self-calibration-loop)
6. [Mitigation Pipeline & IPS Integrity](#6-mitigation-pipeline--ips-integrity)
7. [Reactive Fritzbox WLAN Capture](#7-reactive-fritzbox-wlan-capture)
8. [Network-Effect Threat Learning](#8-network-effect-threat-learning)
9. [Training Data Integrity](#9-training-data-integrity)

---

## 1. Core Architecture & The Real-Time Pipeline (`pipeline.py`)

The heart of Home-IDS is `src/core/pipeline.py`. It is a **threaded** (`threading.Lock`/`threading.RLock`, background `threading.Thread` daemon workers) execution loop — there is no `asyncio` anywhere in this codebase. High throughput comes from disciplined lock scoping, not from an event loop.

### 1.1 Ingestion & File Cursors
Home-IDS fuses two data streams:
1. **Pi-hole (SQLite)**: polled on `poll_interval` (default 2s) by `pihole_collector.py`.
2. **Zeek NDR (JSON Logs)**: tailed continuously by `zeek_collector.py`.

**The `tail -F` problem**: naive file trailing loses events across a restart (or duplicates them, depending on how you recover). The fix is a cursor file per Zeek log type (`state/zeek_cursor_conn.json`, `_dns.json`, `_http.json`, `_notice.json`, `_ssl.json`, `_dhcp.json`) storing the exact byte offset processed so far. On restart, the collector seeks to that offset before resuming.

### 1.2 The 5-Phase Execution Loop
Verified against the actual `# ─── PHASE N:` comments in `pipeline.py`'s device-evaluation loop:

```python
# ─── PHASE 1: Snapshot state data (short lock window) ───────────────────
# ─── PHASE 2: Pre-fetch Zeek data outside the lock ──────────────────────
# ─── PHASE 3: Compute localized features (re-acquire lock) ──────────────
# ─── PHASE 4: Expensive I/O outside the lock ────────────────────────────
# ─── PHASE 5: ML scoring + risk computation (re-acquire lock) ───────────
```

1. **Phase 1 (short lock)**: copy the device's current baseline variables (rate/entropy/variance state) into local memory, release immediately.
2. **Phase 2 (no lock)**: parse raw Zeek dictionaries — purely functional, no shared state touched.
3. **Phase 3 (short lock)**: compute local temporal features (z-scores, entropy) against the snapshot from Phase 1.
4. **Phase 4 (no lock)**: HTTP calls to OTX/AbuseIPDB/VirusTotal, and (if configured) GeoIP/ASN lookups. This is the phase that matters most for throughput — if a threat-intel API is slow or unreachable, the pipeline does not hold the state lock while it waits, so every other device's evaluation this cycle is unaffected.
5. **Phase 5 (short lock)**: push the computed feature matrix into the Hypothesis Engine, ML scorer, and CL-AFPE; commit the decision.

Separate `Evidence`-generating detectors (`intelligence/detectors/*.py`, `intelligence/hypotheses/engine.py`) run inside Phase 5's window, consuming only already-computed feature values — no additional I/O, no additional feature extraction of their own.

### 1.3 Cross-Address-Family Device Identity (MAC Correlation)

One physical device shows up on the network under multiple, unrelated-looking addresses over its lifetime — a DHCPv4 lease, a SLAAC/privacy-rotated IPv6 address that changes periodically, an IPv6 link-local address — and without correlation each of those would cold-start its own separate `DeviceState`, permanently fragmenting that device's actual behavioral baseline across several never-merged, statistically-thin profiles instead of one continuous one.

`extractors/zeek_features.py`'s `_bind_mac(ip, mac)` is the single correlation point both ingestion paths feed: the DHCPv4 branch of `ingest()` (IPv4 only — a lease is inherently IPv4-only) and `_process_conn()`'s read of `conn.log`'s `orig_l2_addr` field (protocol-family-agnostic — this is what makes IPv6 addresses correlatable at all). `core/identity.py` resolves a device_id by MAC first when one is bound, falling back to per-IP cold-start only when no binding exists yet. `tests/test_phase6_mac_correlation.py` exercises this end-to-end, including the specific case of an IPv6 link-local address correctly resolving to the same `device_id` as that device's already-known IPv4 identity.

**Critical, easy-to-miss deployment dependency**: `orig_l2_addr` is not in `conn.log` by default — it only appears once Zeek's `policy/protocols/conn/mac-logging.zeek` is loaded (`@load` line in the real site-policy file, `$(zeek-config --site_dir)/local.zeek` — for a `zeekctl`-managed install from the `security:zeek` OBS package this is typically `/opt/zeek/share/zeek/site/local.zeek`, **not** `/etc/zeek/local.zeek`; run `zeek-config --site_dir` to confirm on your own install. See `INSTALL.md` §3.3.1). Without it, `_bind_mac()` has nothing to bind for any non-DHCPv4 traffic — the code path is correct and tested, but silently idle. This was true of this project for some time before being caught: the mechanism was built, tested, and referenced in a source comment as "see the Phase 6 README" for its one-line deployment step, but that step was never actually written into the install guide, so IPv6 correlation was live in code but inert in practice. If you're investigating why the same physical device appears to have many entries in the Master Threat Ledger with `hostname` values that are raw IPv6 addresses rather than a resolved name, this is the first thing to check.

### 1.3.1 When the MAC itself changes (Phase 4 fuzzy re-identification)

§1.3 above only helps a device that keeps the *same* MAC across address changes. It does nothing once the MAC itself rotates — which modern phones increasingly do (iOS "Private Wi-Fi Address," Android's per-network randomized MAC) — since `_bind_mac()` has no shared key left to correlate on.

`core/device_matching.py` is a separate, deliberately conservative fuzzy-matching pass for exactly this case, invoked from `StateManager.get_or_create()` via `identity.py`'s `_reidentify_kwargs()` whenever `resolve_device_id()` is about to cold-start a device under a brand-new MAC. It compares the new identity against every device seen within `identity_reidentify_window_seconds` (default 1800s) on two independent signals:

- **DHCP fingerprint** (`dhcp_fingerprint_match()`): exact match on Option 60 vendor class + Option 55 parameter list. A *device-class* signal, not a unique-device one — two identical-firmware IoT units present an identical fingerprint (confirmed on the project's own network) — so this alone tops out at confidence 0.40, below both thresholds.
- **JA4 TLS-fingerprint overlap** (`ja4_overlap()`): Jaccard similarity of the set of TLS client fingerprints (not just malicious ones) a device's apps have presented over time — a real behavioral signal, since a given phone's app mix tends to be stable session-to-session.

`match_confidence()` combines these (plus an exact non-generic-hostname match as a third, weaker corroborator): a DHCP match alone never clears `AUTO_MERGE_CONFIDENCE` (0.75) on its own, but DHCP + decent JA4 overlap does, and strong-enough JA4 overlap (≥0.5 Jaccard) can clear the bar with no DHCP fingerprint at all — the higher-leverage signal to get working first if only one is feasible. Below `MIN_CANDIDATE_CONFIDENCE` (0.45) a candidate isn't even logged. This is a probabilistic match by design, not a guarantee — a wrong merge silently blends two different devices' security history, judged worse than a missed one, so the bar stays conservative rather than optimistic. Tested in `tests/test_phase4_reidentify.py`.

**Same class of deployment gap as §1.3, plus one more.** Both signals need Zeek-side data this project doesn't ship by default: the maintained `zeek/foxio/ja4` package (`zkg install`, compiled plugin, not stock Zeek), and DHCP fingerprint fields need a small custom script, `zeek_scripts/local-dhcp-fingerprint.zeek` in this repo, confirmed loading cleanly on a live Zeek 8.0.8 instance (Zeek scripts fail loudly at `zeekctl deploy` time if wrong, not silently). **The real root cause behind both was a separate, more fundamental gap**: `zeekctl`'s `extra_args=-C` (meant to make Zeek tolerate checksum-offloaded packets) is quietly ignored by `zeekctl` entirely, so without `redef ignore_checksums = T;` set directly in `local.zeek`, Zeek was discarding every LAN device's outbound handshake packet (ClientHello) while still processing the server's response fine. This was first found while debugging JA4, and initially misattributed to `zeek/salesforce/ja3` (the older JA3 package) being "unmaintained, broken on modern Zeek" — that conclusion was reached *before* the checksum bug was found and fixed, and never re-tested afterward. **Retested live with the fix already active: `zeek/salesforce/ja3` works fine and coexists cleanly with `zeek/foxio/ja4`** — both packages' fields populate simultaneously on the same connections. Worth installing both: `intelligence/threat_intel.py`'s `_start_ja3_feed` already pulls a live, actively-maintained malicious-JA3 blocklist from abuse.ch's SSL Blacklist, which had nothing to check against until `ja3` started populating — no code change needed, `extractors/zeek_features.py`'s `_MALICIOUS_JA3`/`dynamic_ja3` matching was already there, just fed by an empty field. JA4 remains what `device_matching.py`'s re-identification reads (see above). See `INSTALL.md` §3.2 and §3.3.2 for both deployment steps and verification commands.

---

## 2. The Hypothesis & Evidence Engine (HEE)

Located in `src/core/decision_engine.py` (state machine + evaluation order) and `src/intelligence/hypotheses/` (the hypothesis classes themselves), the HEE replaces a single additive risk score with a typed evidence graph.

### 2.1 The Evidence Store
```python
Evidence(
    type="zeek_lateral_scan",
    source="zeek",
    value=450,               # raw S0/REJ packet count
    confidence=0.90,         # sensor reliability
    independence_group="zeek_network",
)
```
`independence_group` prevents evidence-stuffing: two anomalies from the same underlying sensor category collapse into one vote when counting independent sources toward an escalation decision — a single noisy sensor cannot manufacture apparent corroboration by tripping multiple related signals at once.

`EvidenceStore.get_for_device()` also applies age-based decay: general behavioral evidence has a 10-minute TTL, reputation evidence a 24-hour TTL, with linear freshness decay inside that window (`effective_weight() = confidence × freshness`).

### 2.2 Hypothesis Scoring
Each `Hypothesis` subclass (`hypotheses/engine.py`) evaluates required, strong, and contradicting evidence and returns a 0–4 confidence score:
- **0.0** — required evidence absent, hypothesis doesn't apply.
- **2.0 (Suspicious)** — required evidence present, nothing more.
- **3.0 (Probable)** — required + at least one strong corroborating signal, no contradiction.
- **4.0 (High)** — required + strong + no contradiction + (for some hypotheses) reputation tier supports it.

Nine attack hypotheses are registered: `DNS_TUNNELING` (rate+entropy burst — distinct from the newer, richer `DNS_COVERT_TUNNELING`), `NETWORK_INTRUSION`, `DGA_BOTNET_C2`, `DATA_EXFILTRATION`, `C2_BEACONING`, `DNS_COVERT_TUNNELING` (encoded labels / TXT-NULL abuse / suspicious-TLD concentration), `CONNECTION_ABUSE`, `DNSEvasionHypothesis` (dynamically named `DNS_EVASION` / `DNS_ATTRIBUTION_GAP` / `DNS_POLICY_BYPASS` per-evaluation — see §2.2a, new in 11.0), and `SIGNATURE_MATCHED_THREAT` (batch-mode Suricata matches, new in 11.0 — §2.6). Three benign hypotheses compete against them: `ADVERTISING_BURST` (known ad-network reputation tiers), `LOCAL_DEVICE_DISCOVERY` (SSDP/UPnP/media-discovery on the LAN), and `DEVICE_PROFILE_TELEMETRY` (device-category + trusted-tier-or-**learned-per-device-familiarity** — new in 11.0, see §2.2b).

#### 2.2a `DNSEvasionHypothesis`'s three names (new in 11.0)
Same evidence type (`dns_evasion_anomaly`, from `dns_evasion.py`'s blind-spot audit), same detection thresholds — but `self.name` is set dynamically per `evaluate()` call from a stable subtag in the evidence's `provenance` string, precedence: `policy_bypass` (a direct port-53/853 connection to a non-Pi-hole resolver — `ZeekFeatureExtractor.get_dest_ports()` is what makes this detectable, new in 11.0) → `no_dns_history` (device has zero DNS footprint at all in the window — the strong, unambiguous case, keeps the original `DNS_EVASION` name) → `partial_attribution_gap` (otherwise-normal DNS history, one connection outlived its lookup window — the weakest evidence, gets the most honest name, `DNS_ATTRIBUTION_GAP`). A third-party review of a real production alert history flagged the old uniform naming as misleading for the weaker cases.

#### 2.2b Per-device learned baseline familiarity (new in 11.0)
`Hypothesis.evaluate()` gained a `baseline_familiarity: float = 0.0` parameter (backward-compatible default, threaded through `HypothesisEngine.evaluate_all()` → `DecisionEngine.evaluate()`), computed by `pipeline.py` from `AutonomousFPEngine.get_baseline_familiarity()` before each cycle's decision. `DeviceProfileBenignHypothesis` accepts EITHER the existing trusted-reputation-tier path OR `baseline_familiarity >= 0.6` (3 of the 5 observations needed for full 1.0 familiarity) as satisfying its "is this destination routine for this device" requirement — a genuinely per-device learned pattern, not a global reputation change. See §5.1a for how familiarity itself is recorded.

### 2.3 The Decision Order (`decision_engine.py`)
Evaluated strictly in this sequence — a hard-stop earlier in the list always wins:

```mermaid
flowchart TD
    A["Honeypot access?"] -->|yes| Z1["CRITICAL / block, conf=1.0"]
    A -->|no| B["ARP/NDP spoofing?"]
    B -->|yes| Z1
    B -->|no| C["Geofencing violation?"]
    C -->|yes| Z1
    C -->|no| CX["High-severity Suricata<br/>signature match?<br/>(confidence≥0.9 — new in 11.0)"]
    CX -->|yes| Z1
    CX -->|no| D["Reputation tier 5?<br/>(corroborated: TI/VT hit,<br/>or AbuseIPDB alone at a genuinely high bar)"]
    D -->|yes| Z2["CRITICAL / block, conf=0.99"]
    D -->|no| E["attack_score > benign_score<br/>AND attack_score ≥ 2.0?"]
    E -->|yes, ≥2 independent sources<br/>AND score ≥3.0| Z3["HIGH / alert, conf=0.85"]
    E -->|yes, otherwise| Z4["SUSPICIOUS / monitor, conf=0.40"]
    E -->|no| F["Reputation tier 4?<br/>(one unconfirmed signal)<br/>max signal ≥ 1.5?"]
    F -->|yes| Z5["SUSPICIOUS / monitor, conf=0.45<br/>— NEVER auto-blocks on this alone"]
    F -->|no| G["ML anomaly > 0.90?"]
    G -->|yes| Z6["ANOMALOUS / log, conf=0.10"]
    G -->|no| Z7["BENIGN / suppress"]
```

**Why tier 4 exists as its own branch (fixed in 8.0)**: before this branch existed, a reputation signal that never rose to "confirmed" (tier 5) had exactly one path through this function — silence. The gap between "99% Confirmed Malicious IOC" and "nothing at all" was a single classification threshold in `reputation/classifier.py`. This was found by tracing a real production alert: a connection to Telegram's own infrastructure reached `CRITICAL`/auto-block purely from a single AbuseIPDB score, with VirusTotal and ThreatIntel both clean. `reputation/classifier.py`'s confirmed-IOC threshold for AbuseIPDB alone is now `≥4.0` (aligned with the exact bar `fp_engine.py`'s own hard-stop check already used for the same metric — previously the two disagreed, `>2.0` vs `≥4.0`, for the identical input). VirusTotal and ThreatIntel — curated, multi-vendor, or blacklist-backed signals — keep the lower `>2.0` bar; they're more authoritative single-source signals than a crowd-sourced abuse-report aggregate.

Every evaluation builds a `reasoning_trail` (list of strings) alongside the decision — hard-stop check results, reputation context (tier, VT/TI/AbuseIPDB values, and now IP ownership via ASN lookup), hypothesis scores, and the final verdict with an explicit note when neither an attack nor a benign hypothesis found supporting evidence ("this rests on reputation context alone"). This is what Telegram alerts render under **🧭 REASONING**, and what `ollama_soc.py`'s LLM prompts now also receive (`alert_payload["reasoning_trail"]`) for better-grounded analysis.

### 2.4 Kill-Chain Phase & the Markov Anomaly Signal
`extractors/dns_features.py` classifies each device's recent window into one of `NORMAL / SUSPECTED_RECON / SUSPECTED_LATERAL / SUSPECTED_C2 / SUSPECTED_EXFIL` using simple threshold rules over already-computed features (e.g. beaconing count + suspicious TLD ratio → `SUSPECTED_C2`; lateral-move count + S0/REJ count → `SUSPECTED_LATERAL`). This is **not** a separate model — it's a deterministic function of numbers already computed elsewhere, and — as of 11.0 — the non-`NORMAL` labels are explicitly `SUSPECTED_`-prefixed: they're heuristic feature-threshold guesses, not confirmed kill-chain stages, and a third-party review flagged the un-prefixed form as reading like a confirmed verdict on a Grafana panel. Nothing in `decision_engine.py`/`hypotheses/engine.py` ever consumed the bare form either way — this value only ever reaches `killchain_phase_metric` (Prometheus/Grafana telemetry), never a containment decision.

The "Markov anomaly" score is a small, deliberately simple addition on top: a hand-authored, static transition-probability table (`_MARKOV_TRANSITIONS`) maps `(previous_phase, current_phase) → probability`, e.g.:
```python
"NORMAL":  {"NORMAL": 0.90, "SUSPECTED_RECON": 0.08, "SUSPECTED_C2": 0.01, "SUSPECTED_LATERAL": 0.01, "SUSPECTED_EXFIL": 0.00}
"SUSPECTED_C2": {"NORMAL": 0.20, "SUSPECTED_RECON": 0.10, "SUSPECTED_C2": 0.60, "SUSPECTED_LATERAL": 0.05, "SUSPECTED_EXFIL": 0.05}
```
The anomaly score is `1.0 − transition_prob`. This is an analyst-estimated kill-chain progression model, not a per-device learned Markov chain — it doesn't change based on a device's individual history, and there is no `MarkovStateTracker` class or NxN learned matrix anywhere in the code.

### 2.5 One Verdict Path, Not Two (new in 11.0)
A third-party review of a real production alert history found that `decision_engine.py` (this section) and `fp_engine.py`'s Stage-1 hard-stop filter (§3.2) could independently reach *different* verdicts on the identical alert — Stage-1 re-derived confirmed-threat signals from raw `features` with its own thresholds, instead of reading what the HEE above had already decided. Fixed at the root: `fp_engine.evaluate()` now takes the already-computed `decision` dict as a parameter, and Stage-1's first check is simply `decision["state"] == "CRITICAL"` — every hard-stop this section already computes (honeypot, ARP spoof, geofence, confirmed exploit, tier-5 IOC) is recognized directly, not rediscovered. Two concrete threshold mismatches this gap had caused are fixed too (see §3.2's Stage 1 description) — Checks 2/3/4/5/7 were audited against this section's current thresholds and found already consistent, left as-is.

### 2.6 Batch-Mode Suricata Signature Matching (new in 11.0)
`intelligence/detectors/suricata_scan.py` — real exploit/malware-signature detection, a genuine gap this section's evidence-based hypotheses couldn't fill (Zeek is a behavioral/flow analyzer, not a signature-matching engine). Runs Suricata in pure batch/offline mode (`suricata -r burst.pcap`) against the exact same reactive-capture burst pcap Zeek already reprocesses (§7) — never continuously against live traffic, so idle cost between bursts is exactly zero, keeping it workable on a Raspberry Pi target. Alerts are attributed to a tracked device by src/dest IP match against `state_manager`, then turned into `Evidence(type="suricata_signature_match", independence_group="suricata")` with confidence mapped from Suricata's own severity (1/"high"→0.95, 2→0.70, 3→0.45). `SuricataSignatureHypothesis` scores it like any other hypothesis; a confidence≥0.9 match (severity=1 only) is the `has_confirmed_exploit` hard-stop in §2.3's decision diagram. No rules shipped or authored by this project — see INSTALL.md §3.7. Disabled by default (`reactive_capture_suricata_enabled: false`).

---

## 3. Machine Learning Methodologies

### 3.1 `ml_engine.py` — Bespoke IsolationForests
`scikit-learn`'s `IsolationForest`, chosen because it requires no labeled training data.
- **Global model** (`models/ids_model.pkl`): trained on aggregate home-network traffic, the default scorer for new/unwarmed devices.
- **Bespoke per-device fork** (`models/devices/<id>.pkl`): once a device passes `ml_warmup_samples` (default 5,000), a personalized model forks for that device specifically.
- **Anti-poisoning**: `reject_threat()` opens a 120-second exclusion window after a confirmed threat, during which `learn_normal()` calls for that device are skipped — a confirmed-malicious sample can no longer train the model to think its own behavior is normal.

### 3.2 `fp_engine.py` — CL-AFPE
Prevents Brain 1 from blocking legitimate traffic before containment fires. Three stages, evaluated in order, each cheaper than the last is expensive:

1. **Stage 1 — hard-stop filter** (<1ms): Check 0 (new in 11.0) — `decision_engine.py`'s own CRITICAL verdict, checked first and directly (§2.5), so this is no longer a second independent path to the same conclusion. Then: confirmed TI IOC (`ti_risk > 2.0` — was `> 0` before 11.0, which let a weak score hard-stop far below the bar `classifier.py` itself requires for "confirmed"), active lateral movement (genuine distinct-target count, not a raw connection count), malicious JA3/JA4 fingerprint, honeypot access, AbuseIPDB ≥4.0, local confirmed-intel cross-device match, or an exfiltration payload-burst — as of 11.0 this ALSO requires an absolute-byte floor (>2.5MB) and a telemetry/vendor-cloud exemption, matching the equivalent `zeek_exfiltration` evidence check in §2; the z-score-alone version hard-stopped a real Amazon Echo device on 261 actual bytes moved. Any hit bypasses everything else — `CONFIRMED_THREAT`, no ML consulted. Re-run on **every** trust-cache hit too, not just first evaluation — an immunized domain can never permanently blind the system to a later confirmed IOC on the same registrable domain.
2. **Stage 2 — LightGBM/GBDT ONNX classifier** (<2ms): 11-dimensional tabular feature vector (Tranco rank, label entropy, label length, outbound-bytes z-score, device-type weight, historical-FP flag, lateral-moves, port-scan intensity, app-protocol weight, ARP-sweep intensity, DNS-evasion unexplained-connection ratio — the last two added in the 21D-LGBM-EXTEND work, once ARP-sweep/DNS-evasion evidence existed to feed) → `FP_MODEL_SCORE` (named `P(FP)` before 11.0 — the raw classifier output was never a calibrated probability, so implying one in the label was misleading regardless of whether a calibration curve existed). **As of 9.0, Tranco rank is a real, populated value** — `threat_intel.py`'s Tranco loader already downloaded the full ranked 1M-row list to build its Top-10k allowlist, but discarded the rank number itself; `features["tranco_rank"]` was never written anywhere, so this dimension was silently zero for every alert, ever. `ThreatIntel.get_tranco_rank(domain)` now exposes the rank half of the same already-downloaded data (no extra network cost), and `pipeline.py` populates `features["tranco_rank"]` from it alongside `ti_risk`/`ti_match` in the same Phase-4 block. **As of 11.0, this score can be genuinely calibrated**: `train_fp_classifier.py` holds out a stratified 25% validation split (never seen during training) and fits isotonic regression against predictions on it, saved as `state/models/fp_calibration.json` and applied at inference via dependency-free linear interpolation (`fp_engine.py`'s `_apply_calibration()` — no sklearn needed in the lean runtime path). Purely additive to the audit trail (a `[calibrated: X.XXX]` suffix on the `FP_MODEL_SCORE` line) — does **not** change what drives the actual suppress/uncertain/threat branching below, since those thresholds were chosen against the raw score's distribution. Writes an explicit `reliable: false` marker instead of a fabricated curve when there's too little held-out data (needs ≥20 samples spanning both classes).
3. **Stage 3 — FastEmbed semantic similarity** (<15ms): `bge-small-en-v1.5`, 384-dim embeddings, cosine similarity against ~50 known-safe vendor telemetry patterns. **As of 8.0, this stage is skipped entirely when there's no real domain/hostname to compare** (a raw-IP connection has `domain="unknown"`, and scoring that literal string against vendor embeddings was producing a real-looking but meaningless similarity number that materially swayed the combined suppression decision — found by tracing the same Telegram-infrastructure alert mentioned in §2.3). When skipped, the combined score falls back to LightGBM alone at full weight rather than silently blending in a zero.

Combined score = `0.45 × LGBM + 0.55 × Embed` (or `LGBM` alone if Stage 3 was skipped). Compared against **the requesting device's own calibrated threshold if one exists, else the global default** (`get_device_suppress_threshold()` — new in 8.0, see §5).

All four Stage 2/3/combined thresholds are read via a fresh `self.config.get(...)` call on every evaluation — no cached copy anywhere in the path, so a `config.yaml` edit or an autonomous override takes effect on the very next alert.

### 3.3 `scripts/ollama_soc.py` — Batch LLM Analyst
Runs out-of-band, every 4 hours, launched by `scripts/scheduler.py` as a fresh subprocess — never in the real-time per-alert path. (An earlier real-time analyzer class, `intelligence/ollama_analyzer.py`, was instantiated at boot but its only method was never actually called from anywhere in the codebase — a permanently-idle background thread polling an empty queue for the lifetime of every process. Removed in 8.0.)

Groups the last 24h of published, non-suppressed alerts by `device_id + target + signature` before querying anything — a single recurring pattern costs one LLM call regardless of how many times it fired. Checks a 7-day verdict cache (`state/ollama_analysis_cache.json`) before that one call, and hard-caps fresh calls per run (default 5) — added after a live diagnostic call to the actual production Ollama server measured **849 seconds of `total_duration` for a trivial "say hello" prompt**, while the model's own reported load+eval durations summed to only ~13 seconds; the remaining ~836 seconds was pure CPU-contention queueing on the host hardware.

`intelligence/ai_soc.py`'s `DeterministicValidator` is the hallucination guardrail: it reconstructs the alert's reputation evidence from persisted feature values (`max(ti_risk, abuseipdb_risk, vt_risk)`) and rejects any "benign" LLM verdict where that reconstructed evidence shows a confirmed IOC (`≥4.0`) or contradicts a "just telemetry" claim (`≥3.0`). Validated corrections call `fp_engine.mark_false_positive(..., source="llm_validated")` — same mechanism as an operator's Telegram correction (`source="operator"`), distinguished only by an audit-log tag so downstream consumers (the self-calibration pass, §5) can pool or separate the two evidence sources.

---

## 4. Temporal Mathematics & Baselining

Rolling statistical baselines, not static thresholds, implemented in `src/core/state_guard.py`.

### 4.1 Exponentially Weighted Moving Average (EWMA)
$$ \mu_t = \alpha \cdot x_t + (1 - \alpha) \cdot \mu_{t-1} $$
`baseline_alpha` (default 0.05) controls memory. A small $\alpha$ resists sudden spikes — a fresh infection cannot quickly poison the baseline into thinking its own traffic is normal.

### 4.2 Welford's Online Algorithm for Variance
$$ \sigma^2_t = (1 - \alpha) \cdot (\sigma^2_{t-1} + \alpha \cdot (x_t - \mu_{t-1})^2) $$
$$ Z = \frac{x_t - \mu_t}{\sigma_t} $$
Computed incrementally — no need to retain the full sample history in memory. $Z > 3.0$ is a 3-sigma anomaly (top ~0.3% of the statistical distribution for that feature).

### 4.3 Per-Hour Rate Anomaly Bound
Distinct from the general EWMA/z-score baselining above: `pipeline.py` maintains a **per-hour-of-day** rate baseline (`state.rate_baseline`, 24 buckets) and computes a live anomaly bound every cycle:
$$ \text{threshold\_limit} = \text{rate\_mean}_h + \text{threshold\_std\_dev} \times \sqrt{\text{rate\_var}_h} $$
where $h$ is the current hour and `threshold_std_dev` (default 3.0) is read live from config. This is exported as the `home_ids_query_rate_threshold_limit` telemetry gauge for operator visibility — it is **not** a scheduled "weekly autotune" recalculation of `alert_threshold`; it's computed fresh every ~2-second cycle, purely for that hour's rate baseline.

### 4.4 Shannon Entropy for DGA Detection
`src/utils.py`:
$$ H = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i) $$
High entropy ($H > 3.2$ for labels ≥12 chars, with digit-ratio and vowel-ratio guards to avoid flagging legitimate brand-name-plus-hash patterns) combined with a high NXDOMAIN ratio is the DGA/botnet-C2-hunting signal.

---

## 5. The Autonomous Self-Calibration Loop

New in 8.0. Full mechanics in the User Manual §3 — this section covers the implementation specifics relevant to extending it.

`scripts/train_fp_classifier.py` runs `calibrate_suppress_threshold()` — one function, shared by both the global calibration pass and the per-device pass (different `current`/`min_samples` arguments, not two parallel implementations that could quietly drift apart):

```python
def calibrate_suppress_threshold(corrected_fp_scores, uncorrected_uncertain_scores,
                                  current, min_samples=AUTOTUNE_MIN_SAMPLES):
    if len(corrected_fp_scores) < min_samples:
        return None, "not enough evidence"
    lowest_corrected = min(corrected_fp_scores)
    if uncorrected_uncertain_scores and max(uncorrected_uncertain_scores) >= lowest_corrected:
        return None, "ambiguous overlap — refusing"
    candidate = max(lowest_corrected - SAFETY_MARGIN, ABSOLUTE_FLOOR)
    candidate = min(candidate, current)  # never raises
    if candidate >= current:
        return None, "no change needed"
    return candidate, "<full audit reason string>"
```

Evidence is pulled from `state/autonomous_muted.jsonl` (both `OPERATOR_MARKED_FALSE_POSITIVE` and `LLM_VALIDATED_FALSE_POSITIVE` entries — pooled for the global pass, grouped by `device.id` for the per-device pass) cross-referenced against each corrected alert's *original* CL-AFPE combined confidence, which `pipeline.py` now persists into every alert record as `alert_payload["fp_verdict"]` (verdict/confidence/stage) — this field didn't previously exist, so there was no data to calibrate against at all before 8.0.

Two independent triggers run this same function: the scheduler's standalone daily 3am cron invocation of `train_fp_classifier.py`'s `main()`, and `fp_engine.py`'s own internal 7-day in-process retrain thread (`_weekly_retrain_loop()`) — both now call `run_threshold_calibration()` after their respective model-retrain step, regardless of whether that retrain succeeded (calibration reads a different, if overlapping, slice of the same evidence and shouldn't be gated on ONNX export success).

Output is written via `_write_config_override()` (global → `state/config_overrides.json`) or `AutonomousFPEngine.apply_device_fp_profile()` (per-device → `state/device_fp_profiles.json`, the same architectural home as the existing per-device sigma-shift and trust-cache state). Both are plain JSON, read by `config.py`'s `LiveConfig._load_overrides()` (global) or `fp_engine.py`'s `get_device_suppress_threshold()` (per-device) respectively — neither ever touches `config.yaml`.

---

## 6. Mitigation Pipeline & IPS Integrity

`src/mitigation/ips.py`, engineered for fail-safe resilience.

### 6.1 Layer 7 (Pi-hole Sinkhole)
POST to Pi-hole v6's `/api/domains/deny/exact` endpoint (`{"domain": [domain], "comment": ...}`); release is a DELETE to `/api/domains/deny/exact/{domain}`. Both the list-type (`deny`) and match-kind (`exact`) live in the URL path, not the request body — a live test against a running Pi-hole v6 instance is what surfaced this; the URL shape this code used before always 404'd. On failure, the domain enters a thread-safe retry queue with exponential backoff (`30s × 2^attempts`), falling to a dead-letter queue after 5 attempts. Automatically retried on subsequent cycles.

### 6.2 Layer 3 (Fritz!Box WAN Sever)
TR-064 SOAP API. Applies a "Blocked" profile to the infected MAC, severing WAN access while leaving LAN access intact for remediation. Only reachable at `risk_score ≥ 8.5` or an active lateral-movement flag — and only actually fires if `ips_router_enabled` is set and (when `interactive_blocking_enabled` is true) an operator has approved it.

### 6.3 Layer 2 (Scapy ARP/NDP Tarpit)
The most aggressive mitigation, `risk_score ≥ 9.0` or lateral movement. A daemonized Scapy thread forges ARP (IPv4) and NDP (IPv6) responses telling the infected device the gateway's MAC is unreachable, blackholing its outbound traffic at Layer 2 even if Layer 3 isolation fails or is disabled.

### 6.4 The `interactive_blocking_enabled` Fix (8.0)
Previously, the Telegram "🔒 Approve Hardware Isolation" button and the "⏳ WAITING FOR APPROVAL" status text appeared on **every** alert whenever `interactive_blocking_enabled` was true — including `SUSPICIOUS`/monitor-only alerts where `mitigate()` never reached either isolation branch (both gated behind the 8.5/9.0 risk floors above). The bug: `pipeline.py`'s post-processing checked only "does the containment status contain the word UNBLOCKED", with no check on whether anything was actually pending. Found by tracing a real alert where the decision engine said `SUSPICIOUS / monitor` and the Telegram message simultaneously said `WAITING FOR APPROVAL` — a direct contradiction. Both the status-text override and the inline-button attachment are now gated on `risk ≥ 8.5 or lateral_threat`, matching `mitigate()`'s own floor exactly.

---

## 7. Reactive Fritzbox WLAN Capture

New in 9.0. Closes a real, confirmed-live visibility gap: on an all-in-one modem+router+AP (the common home-network shape, including this deployment's Fritzbox), neither a mirror port nor an inline bridge can see WiFi-to-WiFi traffic at all — only the wired devices get genuine Zeek flow visibility (lateral movement, JA3/JA4 fingerprinting). AVM's own per-radio diagnostic capture (`ath0`/`ath1`) *does* see WiFi-to-WiFi traffic (confirmed with a controlled live ping test), but continuous dual-radio capture measured ~3GB/hour (~2TB/month) with observable router latency overhead under sustained load — reactive, triggered bursts instead of 24/7 capture.

**Auth and capture control** (`src/extractors/fritzbox_capture.py`): `login()` implements the Fritzbox TR-064 challenge-response flow (PBKDF2 with legacy MD5 fallback for older firmware). `run_burst()` starts capture on the configured radios, waits `reactive_capture_burst_seconds`, stops, and retrieves the raw AVM-format pcap bytes.

**Pcap conversion and reprocessing, not a custom parser**: `avm_pcap_to_standard()` converts AVM's non-standard pcap variant to a format Zeek can read; `reprocess_with_zeek()` then runs the SAME `local.zeek` policy the live capture uses (JSON logging, MAC-logging, DHCP fingerprinting, both `zeek/foxio/ja4` and `zeek/salesforce/ja3`) offline against the burst window, producing real `conn.log`/`dns.log`/`ssl.log`/`arp.log` for that window. `ingest_zeek_logs()` then feeds those logs through the exact same `ZeekFeatureExtractor.ingest()` live traffic uses — meaning a burst's data flows through every already-tuned detector with zero new detection logic, and, as a direct consequence of this design choice rather than a separate feature, WiFi devices get real JA3/JA4 signal (feeding both `fp_engine.py`'s Stage-1 Check 3 and `device_matching.py`'s JA4-overlap re-identification) for the first time whenever a TLS connection occurred during the capture window.

**ARP host-discovery sweep detection** (independent of the Fritzbox pieces — works off broadcast-visible ARP traffic any device on the LAN can see, WiFi included, no capture burst needed): `zeek_features.py` tails a new `arp.log` (stock Zeek doesn't emit one without an explicit logging script — deployed as `zeek_scripts/local-arp-log.zeek`) and tracks a rolling per-device set of distinct ARP-requested target IPs. `threat_signals.py` emits an `arp_sweep` evidence item (`independence_group="lan_recon"`) once `arp_sweep_unique_targets_threshold` (default 8, per-device auto-calibrated — see §5's sibling `calibrate_arp_sweep_threshold()`) is exceeded; `ConnectionAbuseHypothesis` (`hypotheses/engine.py`) accepts it as an alternate trigger alongside the existing `zeek_conn_abuse`/`zeek_long_conn` evidence. Deliberately **not** a Stage-1 hard-stop — some legitimate IoT discovery protocols behave similarly, so it corroborates rather than auto-confirms.

**Blind-spot audit** (`fritzbox_capture.run_dns_evasion_audit()` orchestrates; `intelligence/detectors/dns_evasion.py`'s `audit_device()`/`audit_burst()` do the actual scoring): for every device seen in a burst's reprocessed `conn.log`/`ssl.log`, compares real destination IPs actually talked to against domains resolved via Pi-hole in the same window. `_is_private_lan_ip()` excludes RFC1918 destinations first (a real false-positive class found live — intra-LAN traffic has no DNS record by nature and was being flagged as "unexplained"); `_reverse_dns_explains()` and `_vpn_explains()` (a curated commercial-VPN-provider IP range list, needed after a live false-positive on a device's own NordVPN traffic) exclude anything with a legitimate explanation. What's left — real connections with no DNS explanation, no recognized-infra explanation, and no reputation data — is the `dns_evasion_anomaly` evidence signal, scored via `DNSEvasionHypothesis` (`hypotheses/engine.py`), needing the same 2-independent-source corroboration bar as any other hypothesis before it can authorize containment or a Telegram alert.

**Trigger wiring and shared budget** (`ReactiveCaptureDispatcher` in `fritzbox_capture.py`, invoked from `pipeline.py`): six independently-enable-able trigger sources — any non-benign `decision_path`, an `arp_sweep` evidence emission, a cold-start on a never-seen MAC, a `state_guard.py` re-identification candidate landing in the genuinely-ambiguous confidence band, a new source IP contacting a wired-visibility device (`reactive_capture_wired_probe_ips`), and any HIGH/CRITICAL decision anywhere on the network — plus a periodic in-process spot-check (not a separate scheduled script, since a burst's findings only reach live detection by ingesting into the *same* long-running `ZeekFeatureExtractor` instance the pipeline already holds; a separate subprocess couldn't share it). All draw from one shared `reactive_capture_max_bursts_per_hour` budget (`_check_and_consume_budget()`) rather than a per-trigger cooldown, since a single burst captures the whole radio regardless of which source fired it — trigger-source count doesn't multiply capture cost, only actual burst-execution count does. Bursts run on a background thread (`try_dispatch()`'s `_run()`), never blocking a pipeline cycle.

**Self-healing extensions** (Phase 21D2/D3, layered on top of the existing false-positive self-healing in the User Manual §1): the count/threshold-based new detectors (ARP-sweep, DNS-evasion) don't fit the existing z-score-based `sigma_shift` mechanism, so a correction on either routes through `mark_false_positive()`'s signature-based dispatch to a sibling per-device threshold-multiplier file (raises that device's `arp_sweep_unique_targets_threshold` immediately, not just after the next weekly retrain) or — for `dns_evasion_anomaly`, which has no domain by definition — an IP-keyed trust-cache sibling to the existing domain-keyed one, so a VPN/safe-destination correction generalizes instead of repeating forever.

---

## 8. Network-Effect Threat Learning

New in 9.0. `src/intelligence/local_intel.py`'s `LocalConfirmedIntel` class, backed by `state/local_confirmed_intel.json`. Fed by `fp_engine.py`'s `record_confirmed_threat()` whenever any alert reaches Stage-1 `CONFIRMED_THREAT` or the tightened 2-independent-source HIGH/CRITICAL bar; read by a new Stage-1 hard-stop check (alongside the five in §3.2) that hard-stops a *different* device connecting to the same previously-confirmed domain/IP, instead of that device having to re-earn independent corroboration from scratch. TTL-bounded (`local_confirmed_intel_ttl_seconds`, default 30 days) since confirmed-malicious infrastructure can be repurposed or abandoned.

### 8.1 The poisoning bug and its fix
`.record()`/`.check()` match domains at the eTLD+1 base-domain level and IPs by exact literal string. Both granularities are far too coarse in the failure cases that actually occurred in production: a single hard-stop hit against a subdomain of a huge shared vendor domain (`amazon.com`, `netflix.com`, `microsoft.com`) permanently "confirmed" the *entire* base domain as malicious for every device thereafter, and a single hit against a private/multicast/loopback address (including this network's own router and server) did the same for an IP that structurally can never be external malicious infrastructure. Worse, the poisoning was **self-reinforcing**: every subsequent hard-stop via the new Check 7 called `record_confirmed_threat()` again with reason `TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP`, refreshing the poisoned entry's TTL indefinitely — a bug that, left alone, would never expire on its own.

Fixed on **both** sides, per the general lesson in `CLAUDE.md`'s pre-flight checklist (a learned-state store needs a floor on write AND read):
- **Write guard**: `record_confirmed_threat()` refuses to persist a base domain matched by `utils.is_telemetry_domain()` (the same CDN/vendor allowlist already used elsewhere in the codebase) or an IP that is private/multicast/loopback/link-local/reserved/unspecified (stdlib `ipaddress`) or explicitly listed in `config.yaml`'s `safe_ips` — a config key that was already documented as "never treated as suspicious" but, until this fix, was never actually consulted by this store at all.
- **Read guard**: Stage-1 Check 7 independently re-checks the same conditions before honoring an existing store entry (`domain_hit_eligible`/`ip_hit_eligible` in `fp_engine.py`'s `_stage1_hard_stop()`), neutralizing already-poisoned historical entries immediately, with no need to touch the data file at all.
- **Cleanup utility**: `src/clean_confirmed_intel.py` (dry-run by default, `--apply` to remove) audits the on-disk store against the same two conditions, for the ongoing case where a *newly*-added `safe_ips`/allowlist entry should retroactively prune data already poisoned before that entry existed.

---

## 9. Training Data Integrity

New in 9.0. Two related, previously-open gaps in `scripts/train_fp_classifier.py`'s 11-dimension feature extraction (`extract_features_from_alert()`):

### 9.1 Historically-corrupted rows from fixed domain-attribution bugs
`f1_entropy` (Feature 1) is computed from `domain = context.get("queried_domain", "") or src.get("domain", "")` — the exact field two now-fixed bugs corrupted for `DNS_COVERT_TUNNELING` (commit `192d5dc`) and `DGA_BOTNET_C2` (commit `851835a`) alerts: both signatures previously fell back to `_select_target_domain()`'s generic "most notable domain in the window" pick, structurally disconnected from which domain actually triggered that cycle's evidence. Fixing `pipeline.py` stops new corruption but does nothing for rows already persisted to `alerts.json`/`autonomous_muted.jsonl` before each fix landed.

`src/identify_corrupted_training_rows.py` identifies them via a conservative, provable timestamp cutoff — each fix commit's own unix timestamp (`git show -s --format=%ct <sha>`), per signature — and writes matching rows' dedup keys (the same `device_id|domain|timestamp` convention `_alert_dedup_key()` already uses to cross-reference the threat-stream and `autonomous_muted.jsonl`) to `state/training_row_exclusions.json`. Deliberately **never mutates or deletes anything in the underlying alert logs** — both are read by other consumers (Grafana, `retro_hunter.py`, manual audit) that need the full, real history — this is a separate, deletable overlay file, the same "baseline untouched, override layer additive" pattern `config_overrides.json` already established for config. `load_dataset()`'s `_load_training_row_exclusions()` reads it and skips matching rows during the next retrain only; absent by default (strictly opt-in — run the script with `--apply` to populate it).

### 9.2 The Tranco-rank feature was always zero
`threat_intel.py`'s `_refresh_tranco_trust_list()` already downloaded the full ranked 1M-row Tranco list on a 24h cadence to build its Top-10k allowlist set — but discarded the rank number (`parts[0]`) on every single line, keeping only the domain. `features["tranco_rank"]` (Feature 0, `f0_tranco_rank_norm`) was read by both `fp_engine.py`'s Stage 2 and `extract_features_from_alert()` but never written anywhere in the codebase — a fully-wired reader with no writer, silently contributing zero information to every LightGBM prediction and every retrain, indefinitely. Fixed by capturing the rank half of the same already-downloaded data into a new `self._tranco_ranks` dict (persisted to `ti_cache/tranco_ranks.cache`, no extra network cost) and a new `ThreatIntel.get_tranco_rank(domain)` method; `pipeline.py` now populates `features["tranco_rank"]` from it in the same Phase-4 block that already computes `ti_risk`/`ti_match` against the same `top_domain`.
