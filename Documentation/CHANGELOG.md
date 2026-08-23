# Changelog

All notable changes to the Home IDS project will be documented in this file.

## [v11.0.0] - 2026-08-23

A response to a full third-party architectural review of a real production alert history (8,443+ JSONL records, `state/alerts.json`). Every review finding was checked against the live running code — several turned out to already be fixed by v10.0.0 (dated correctly against the review, since the review's data predated that release); the rest are fixed here, or explicitly declined with the reasoning recorded, never silently ignored. New golden-regression and comprehensive end-to-end scenario test suites (`tests/test_phase36_review_regression.py`, `tests/test_phase37_suricata_batch_scan.py`, `tests/test_phase38_comprehensive_scenarios.py`) pin down both the specific bugs found and the full decision-making behavior across every major signature type.

### 🔗 The Core Architectural Fix: One Verdict Path, Not Two

The review's central finding: `fp_engine.py`'s Stage-1 hard-stop filter and `decision_engine.py`'s Hypothesis & Evidence Engine could independently reach *different* verdicts on the identical alert, because Stage-1 re-derived signals from raw features with its own thresholds instead of reading what the HEE had already decided.

- **`fp_engine.py` Stage-1 Check 0 (new)**: recognizes `decision_engine.py`'s own `CRITICAL` verdict directly — honeypot, verified ARP spoofing, geofencing, and tier-5 confirmed IOC now flow through one path, not two that happen to usually agree.
- **Check 1 (ThreatIntel) threshold fixed**: was `ti_risk > 0` — ANY nonzero score, however weak, unconditionally hard-stopped, bypassing `classifier.py`'s own more careful `ti_score > 2.0` confirmed-IOC bar. Now the same bar both subsystems use.
- **Check 6 (exfiltration burst) fixed — a live bug, not just a theoretical mismatch**: was missing the absolute-byte floor (`>2.5MB`, not just a z-score spike) and the telemetry/vendor-cloud exemption `threat_signals.py`'s equivalent `zeek_exfiltration` evidence check already had. Confirmed live against the tail of the running `state/alerts.json`: an Amazon Echo device's AWS IoT/MQTT connection (TCP:8883, 261 actual bytes moved) was hard-stopping to `CONFIRMED_THREAT` purely from `outbound_bytes_z=9.3`, while `decision_engine.py` simultaneously called the same alert `SUSPICIOUS/monitor (confidence=0.40)` — the exact two-verdict shape the review described.
- Checks 2 (lateral movement), 3 (malicious TLS), 4 (honeypot), 5 (AbuseIPDB), and 7 (local confirmed-intel) were audited against `decision_engine.py`'s current thresholds and found already consistent — deliberately left as-is rather than rewritten for its own sake; see the session notes on why a full evidence-store migration of these was scoped out as unjustified risk for a live containment system with no corresponding bug found.

### 🎯 `DNS_EVASION` Now Says What It Actually Found

The review flagged this signature name as misleadingly uniform: a device with zero DNS footprint, a device with one attribution-window miss on otherwise-normal history, and a device directly bypassing Pi-hole on port 53 all produced the identical, equally-alarming `DNS_EVASION` name.

- **`DNSEvasionHypothesis` now picks one of three names** from a stable subtag `dns_evasion.py`'s blind-spot audit attaches to its evidence: `DNS_POLICY_BYPASS` (a direct port-53/853 connection to a non-Pi-hole resolver — the most specific, most actionable finding) → `DNS_EVASION` (genuinely zero DNS history at all) → `DNS_ATTRIBUTION_GAP` (otherwise-normal history, one connection outlived its lookup window — the weakest, most honest name for the weakest evidence). Detection thresholds are completely unchanged; only the name reflects what was actually found.
- **`ZeekFeatureExtractor` gained port tracking** (`get_dest_ports()`, parallel to the existing `get_dest_ips()`) so `DeviceBurstAudit` can see which port an unexplained connection used — the data `DNS_POLICY_BYPASS` detection needed and didn't have before.
- Every `primary_sig_base`-keyed branch in `pipeline.py` and `fp_engine.py`'s human-correction routing updated to treat all three names identically (same "no domain, dest_ip is the real target" attribution shape either way).

### 🧬 Per-Device Learned Behavioral Baseline

- **`AutonomousFPEngine.record_device_baseline_observation()` / `get_baseline_familiarity()`** (new): each device learns its own normal ports/ASN-owners/domain-bases over time, persisted in the existing `state/device_fp_profiles.json`. Deliberately gated on the HEE's own verdict for that cycle already being BENIGN/ANOMALOUS — a device beaconing to a C2 host every cycle cannot launder itself into a trusted baseline through repetition, which would be exactly backwards for a self-healing mechanism.
- Wired into `dns_evasion.py`'s blind-spot audit (damps confidence for an unexplained IP whose ASN this device has legitimately talked to before) and into `DeviceProfileBenignHypothesis` as an alternate path to the same "routine, not surprising" conclusion the global reputation tier already grants — scoped to what this one device's own history actually supports, not a global classification change. `Hypothesis.evaluate()`'s signature gained a `baseline_familiarity` parameter (backward-compatible, defaulted) threaded through `HypothesisEngine.evaluate_all()` and `DecisionEngine.evaluate()`.

### 🔎 Real Signature/Exploit Detection: Batch-Mode Suricata

Zeek is a behavioral/flow analyzer, not a signature-matching engine — real exploit/malware-signature detection was a genuine, previously-unaddressed gap. Evaluated and rejected: running Suricata continuously (heavyweight, and a poor fit for a Raspberry Pi target this project also needs to run on). Shipped instead:

- **`intelligence/detectors/suricata_scan.py`** (new) — runs Suricata in pure batch/offline mode (`suricata -r burst.pcap`) against the exact same reactive-capture burst pcap Zeek already reprocesses, never continuously against live traffic, so idle cost is exactly zero between bursts. Parses `eve.json` alerts, attributes each to a tracked device by src/dest IP match, and turns real signature matches into `Evidence` — never a second independent verdict path (learned from the architectural fix above).
- **`SuricataSignatureHypothesis`** (new) scores it like every other hypothesis; a genuinely high-severity match (Suricata's own `severity=1`/"high", confidence≥0.9) is a new explicit `decision_engine.py` hard-stop (`has_confirmed_exploit`) — matching the review's own "confirmed exploit"/"known malware signature" hard-stop category.
- No rules shipped or authored by this project (re-curating threat intelligence Suricata/Emerging Threats already maintains would be low-value reinvention) — point `reactive_capture_suricata_rules_path` at a ruleset you manage yourself (e.g. `suricata-update --etopen` with a trimmed policy). **Disabled by default** (`reactive_capture_suricata_enabled: false`) — inert until installed and configured.

### 📐 Calibration and Other Labeling Honesty

- **`train_fp_classifier.py` now holds out a genuine validation split** (stratified 75/25, when enough data exists) and fits isotonic regression against predictions on the HELD-OUT split only — never against the same data the classifier trained on, which would just restate training accuracy in a different shape, not calibrate anything. Saved as `state/models/fp_calibration.json`, applied at inference time via dependency-free linear interpolation (`fp_engine.py`'s `_apply_calibration()` — no sklearn import needed in the lean runtime path). An explicit `reliable: false` marker (not a fabricated curve) when there's too little held-out data.
- **`P(FP)` relabeled `FP_MODEL_SCORE`** everywhere it reaches a human or an LLM, explicitly noted as uncalibrated when no calibration is loaded — the raw LightGBM/GBDT output was never a calibrated probability regardless of whether a curve exists yet. FastEmbed similarity text now explicitly says "contextual evidence, not a verdict."
- **Kill-chain phase labels `SUSPECTED_`-prefixed** (`RECON`/`C2`/`LATERAL`/`EXFIL` → `SUSPECTED_RECON`/etc., `NORMAL` unchanged) — these are heuristic feature-threshold guesses (`dns_features.py`'s `_determine_killchain_phase()`), not confirmed kill-chain stages; nothing in `decision_engine.py`/`hypotheses/engine.py` ever consumed the bare form (Grafana-telemetry only), but a human reading "EXFIL" on a dashboard panel had no way to know that from the label alone.
- **`classify_payload_size()` stopped guessing protocol from byte count** — a sub-128-byte TCP/UDP/ICMP/anything packet no longer displays as "Standard DNS/Control Packet" regardless of actual protocol; `classify_service(port, proto)` a few lines away already does correct protocol/service naming from data the same alert payload already carries.

### 🕸️ Parent-Domain DNS Tunneling Signal

- **`fanout_label_entropy`** (new `dns_features.py` feature): average Shannon entropy of the first label across every child domain sharing the winning subdomain-fanout parent. Fanout COUNT alone can't distinguish "many meaningfully-named subdomains" (a legitimate multi-tenant SaaS) from "many randomized/encoded chunks" (the real tunneling shape) — `threat_signals.py`'s `subdomain_fanout` check now scales confidence with this, on top of the existing count-based baseline and CDN/telemetry exemption.

### 🔍 Visibility: Incident Rollup

- **`src/scripts/incident_report.py`** (new, read-only, doesn't touch `alerts.json`) — groups the training log by the `incident_id` already stamped onto every alert record, giving a human "ONE INCIDENT, N occurrences" view instead of requiring a manual read of raw JSONL (exactly what the third-party review had to do by hand to reach its own conclusions). `alerts.json` itself deliberately stays append-only-per-cycle — that's correct for CL-AFPE training data, unaffected by this.

### Verification

Golden regression suite (`test_phase36`) pins the two live bugs found plus golden cases for the review's own named examples (weak AbuseIPDB signal → tier 4 not 5, CDN telemetry domain → no false tunneling verdict). Comprehensive end-to-end suite (`test_phase38`) exercises the real `DecisionEngine`/`HypothesisEngine`/`ReputationClassifier` stack across every major signature family — benign device telemetry, per-device learned baseline, VPN false-positive exclusion, DGA, DNS tunneling, all three DNS-evasion names, lateral-movement corroboration, Suricata hard-stop vs. evidence-only, every hard-stop condition, reputation-tier golden cases, corroboration-requirement regression guards, kill-chain labeling, and the payload classifier fix. Full test suite (30 files) run before this release.

## [v10.0.0] - 2026-08-23

Evidence-families corroboration fix, incident-volume aggregation, per-device benign device-category profiles, and an Ollama circular-reasoning guard — the four items a prior third-party review flagged as reasonable forward-looking architecture improvements (not live bugs). Bundled with a same-day live-data audit that found and fixed three additional real production bugs.

- **Evidence-families registry** (`hypotheses/evidence.py`'s `EVIDENCE_FAMILIES`/`ATTACK_EVIDENCE_FAMILIES`) replaces `decision_engine.py`'s old hand-maintained hybrid type-prefix-or-group-membership filter for "how many independent evidence sources does this device have" — the old filter had silently never been updated when `arp_sweep`/`lan_recon` evidence was added, so a real ARP-sweep-plus-corroborating-signal case never counted toward the 2-independent-sources bar a HIGH verdict requires.
- **`IncidentTracker`** (`core/incident_tracker.py`, new) collapses repeat Telegram notifications for the same ongoing incident (same device+target+signature) into: first occurrence, any severity escalation, and periodic "still ongoing" updates — instead of a full alert every qualifying cycle. `alerts.json` itself is unaffected (still one line per qualifying cycle, for CL-AFPE training); this only gates the Telegram layer on top. `incident_key.py` (new) is the shared "same incident" identity both this and `ollama_soc.py`'s offline batch grouping now import, replacing a previously-duplicated definition.
- **`DeviceProfileBenignHypothesis`** (new) — device CATEGORY (smart_tv/iot/gaming_console/nas/router/gateway/dns_server, from `utils.infer_device_type()`; deliberately no brand dimension, since there's no detection basis to distinguish "Amazon Fire TV" from "Google Chromecast") combined with trusted/known-infrastructure reputation tier and elevated DNS activity now scores a named `DEVICE_PROFILE_TELEMETRY` benign verdict instead of falling through to the generic `UNKNOWN_BENIGN` catch-all. Explicitly backs off when genuine attack-shaped evidence exists on the same device, so it can never silently outscore a real (if currently-dampened) attack finding.
- **`DeterministicValidator` circular-reasoning guard** (`intelligence/ai_soc.py`) — Ollama is no longer shown risk score, signature, factors, or fp_verdict at all (`ollama_soc.py`'s `_build_evidence_only_payload`); a "malicious" verdict whose own justification cites the exact prior risk score anyway (a leaked/stale prompt, or a future regression reintroducing it) is now rejected the same way a hallucinated benign-despite-IOC verdict already was.
- **Same-day live-audit bugfixes**: `safe_ips` wasn't actually protecting infrastructure from three separate alert paths; lateral-movement/reputation/persistence-suffix misattribution bugs found via a post-v9.0.0 state-folder audit; a DNS_EVASION false-positive storm and two alert-text contradictions traced to CDN/telemetry false-positive-and-negative gaps in the DNS tunneling detector.

## [v9.0.0] - 2026-08-22

The largest release since the Hypothesis & Evidence Engine rewrite. Two major bodies of work: a new **reactive Fritzbox WLAN capture subsystem** that gives this deployment its first real (if partial) network-flow visibility into WiFi devices — previously 100% dark to Zeek on an all-in-one router — and a wide correctness pass across detection, false-positive suppression, and the ML training pipeline, driven by tracing real production alerts (`alerts.json`, `journalctl`, live service restarts) line-by-line back through the code rather than working from assumptions. Every fix below was verified against a concrete, reproducible case; several against a live production instance via real curl/API round-trips. Full 22-file phase test suite (up from 9 at v7.0.1) passes.

### 📡 New: Reactive Fritzbox WLAN Capture (Phase 21)

Closes a real, live-confirmed gap: on an all-in-one modem+router+AP (this deployment's Fritzbox, and most consumer routers), neither a mirror port nor an inline bridge can see WiFi-to-WiFi traffic at all — only the two wired devices had genuine Zeek flow visibility (lateral movement, JA3/JA4). AVM's own per-radio diagnostic capture (`ath0`/`ath1`) *does* see it (confirmed with a live controlled ping test), but continuous dual-radio capture measured ~3GB/hour with observable router latency under load — this ships the reactive, triggered-burst alternative instead. Full architecture in [ENGINEERING_MANUAL.md §7](ENGINEERING_MANUAL.md#7-reactive-fritzbox-wlan-capture).

- **Fritzbox capture client** (`extractors/fritzbox_capture.py`) — TR-064 challenge-response auth (PBKDF2 + legacy MD5 fallback), live-verified capture-burst start/stop against the real `capture_notimeout` endpoint, AVM-format→standard pcap conversion, and reprocessing through the same live `local.zeek` policy (JSON logging, MAC-logging, DHCP fingerprinting, JA4/JA3) — feeding results into the exact same `ZeekFeatureExtractor` instance live traffic uses, so WiFi devices get real JA3/JA4 signal (both Stage-1 malicious-fingerprint matching and JA4-overlap device re-identification) for the first time, as a direct consequence of the design rather than new logic.
- **ARP host-discovery sweep detection** — broadcast-visible, works without any Fritzbox integration (ARP reaches WiFi devices the same way MAC correlation already does). Required a missing Zeek script: stock Zeek 8.0.8 ships the underlying `arp_request`/`arp_reply` events but no script that writes `arp.log` — added `zeek_scripts/local-arp-log.zeek`, confirmed end-to-end against 71/71 real request/reply pairs from a live capture. New `arp_sweep` evidence wired into `ConnectionAbuseHypothesis` as an alternate trigger; per-device auto-calibrated threshold (see Autonomous Learning below).
- **DNS-evasion blind-spot audit** (`intelligence/detectors/dns_evasion.py`) — compares a device's real captured destinations against its own DNS query history, flagging connections neither DNS nor known infrastructure explains: the one detector class structurally invisible to every DNS-shape-based detector this system already had. Excludes intra-LAN/RFC1918 destinations and recognized commercial VPN-provider ASNs (modeled on a real live false-positive against a device's own NordVPN traffic) before flagging anything.
- **Six trigger sources**, all sharing one hourly budget (`reactive_capture_max_bursts_per_hour`) rather than a per-trigger cooldown, since one burst captures the whole radio regardless of which source fired it: any non-benign decision path, an ARP-sweep hit, a cold-start on a never-seen MAC, a genuinely-ambiguous device re-identification candidate, a new source contacting a wired-visibility device, and any HIGH/CRITICAL decision — plus an in-process periodic spot-check. All fire on a background thread, never blocking a pipeline cycle.
- **Self-healing extensions** — the new count/threshold-based detectors don't fit the existing z-score `sigma_shift` mechanism, so `mark_false_positive()` gained signature-based dispatch: a `DNS_EVASION` correction immunizes the alert's actual flagged destination IP (not a generic "last known IP", which could be the wrong one — fixed separately after the routing itself was wired in) via the existing IP-checked trust-cache fast path; a `CONNECTION_ABUSE`/`arp_sweep` correction raises that device's own sweep threshold immediately via a new per-device multiplier file, not just after the next weekly retrain.
- **Autonomous network-wide threat learning** (Phase 21D3) — a new self-growing local confirmed-threat store (see below) plus `retro_hunter.py` cross-referencing it against recent alert history to catch "device B also touched this IOC days ago but wasn't over its own threshold at the time."
- **Disk safety** — try/finally cleanup of each burst's raw pcaps/Zeek scratch output right after ingestion, a permanent compact JSONL history trail (`reactive_capture_history.jsonl`) kept regardless, and a periodic crash-orphan sweep.
- **`reactive_capture_wired_probe_ips` activated** with this deployment's real NAS and Ubuntu-server IPs, turning the wired-probe trigger on for real.
- **Telegram alert volume tightened** as an explicit, deliberate reversal of an earlier "alert on any single strong signal" decision: notifications now require the same genuinely-corroborated HIGH/CRITICAL bar that already authorizes a Pi-hole block, never firing for SUSPICIOUS/monitor-only decisions — shipped independently, no new infrastructure required.

### 🧠 New: Network-Effect Threat Learning, and the poisoning bug found in it

- **`local_confirmed_intel.json`** (`intelligence/local_intel.py`) — once any device's traffic reaches a Stage-1 hard-stop or a genuinely-corroborated HIGH/CRITICAL verdict, the triggering domain/IP is recorded so a *different* device touching the same infrastructure later gets an immediate hard-stop instead of re-earning independent corroboration from scratch. TTL-bounded (30 days).
- **Found and fixed a severe, self-reinforcing poisoning bug in this exact store**, on both the domain and IP side: matching at the eTLD+1 base-domain level meant one bad hit against a subdomain of `amazon.com`/`netflix.com`/`microsoft.com` permanently "confirmed" the entire shared vendor domain as malicious for every device thereafter; matching IPs by exact string did the same for private/multicast/loopback addresses — including this network's own router and server. Worse, every subsequent hard-stop re-recorded the same entry (`TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP`), refreshing its TTL indefinitely — a bug that would never have expired on its own. Fixed on **both** the write path (refuses to record a known-safe telemetry/CDN base domain or a private/multicast/`safe_ips`-listed address) and the read path (Stage-1 Check 7 independently re-validates before honoring an existing entry, neutralizing already-poisoned historical data with no file migration needed) — the general "floor on write AND read" lesson now codified in `CLAUDE.md`'s pre-flight checklist.
- **`safe_ips` was documented but never actually consulted** by this store until this fix — a config key that existed and was even referenced in the User Manual, but was dead weight for this exact purpose.
- **`src/clean_confirmed_intel.py`** — new dry-run-by-default maintenance CLI to audit/prune the store for the two poisoning categories above, for the ongoing case where a newly-added allowlist entry should retroactively clean data poisoned before it existed.

### 🎯 Detection Correctness

- **Alert domain/target attribution fixed in three separate signatures**, all sharing the same root cause: `pipeline.py`'s target-domain picker falls back to "most notable domain in the whole window," structurally disconnected from which specific evidence actually fired that cycle. Found independently in `DNS_EVASION` (fixed earlier), then `DNS_COVERT_TUNNELING` (confirmed live: a 19-character domain shown as "Target" alongside evidence reading `max_label=57`, measured on a completely different, never-displayed domain), then `DGA_BOTNET_C2` (worse in kind — `dns_dga_burst` carried no domain examples at all pre-fix, and the misattribution was initially mistaken for a real coordinated attack across 6+ unrelated devices before being traced to this gap). All three now attach `Evidence.domain` from the same per-domain loop that generates the evidence, not a window-wide aggregate.
- **A recurring, 5+ day false-positive against Telegram's own infrastructure** (`149.154.166.110`, AS62041) — the exact case a prior fix had only reduced, not eliminated, since AbuseIPDB's crowd-sourced score for a huge shared IP block naturally drifts above and below any fixed threshold over time, and a raw IP with no resolved domain can't be immunized by any domain-based safe-list. Fixed with the same pattern already proven for VPN providers — ASN-org-name matching, not a brittle IP list.
- **A deeper tier-escalation bug found while fixing the above**: the reputation classifier's confirmed-IOC escalation logic ran unconditionally on every evaluation, meaning even an explicit tier-0/1/2 ("trusted") classification could be overridden straight back to tier 5 by a single stray reputation score — contradicting the class's own documented intent. Now only escalates from the unclassified tier; an explicit safe classification is a floor, not a suggestion.
- **Persistence-escalation could silently bypass the HIGH/CRITICAL containment severity gate.** A cross-cycle mechanism (predating the severity gate) promotes `SUSPICIOUS`→`HIGH` purely from a signature recurring on the same device for ≥10 minutes with no new evidence — harmless when it only affected alert urgency, but once containment started trusting `decision["state"]` alone, this became a silent door around "block only after genuine corroboration": a single uncorroborated, merely-repeating signal could earn an auto-block after 10 minutes while its own published alert still (truthfully) read `SUSPICIOUS`. Fixed with a separate `containment_decision_state` that downgrades back to `SUSPICIOUS` specifically for persistence-driven escalation, while every other display of the decision is untouched.
- **The ARP/NDP spoof detector false-positived on legitimate mesh-WiFi MAC oscillation**, feeding a Stage-0 hard-stop. It compared only against the single last-seen MAC-to-IP binding, treating every re-appearance of a previously-valid pairing as new spoofing. Now tracks a real per-IP MAC history and only fires when the MAC genuinely wasn't previously known for that IP.
- **The DNS-evasion blind-spot detector flagged intra-LAN traffic as "unexplained," causing continuous re-alerts** — private/RFC1918 destinations are now excluded before anything can be called unexplained external traffic.
- **Pi-hole v6 REST API was never actually reachable** — the code sent list-type and match-kind in the request body; v6 requires them in the URL path (`/api/domains/{type}/{kind}[/{domain}]`). Every real block had been silently falling through to the CLI fallback; confirmed via a live curl round-trip (POST 201/GET/DELETE 204) after the fix, comment text now confirmed actually reaching Pi-hole.
- **Self-healing immunization only released an exact base-domain string match**, but blocks are keyed by the specific queried FQDN — almost always a subdomain. Confirmed live: 21 domains (WhatsApp, Facebook, Netflix, NTP, Samsung Apps, `zee5.com` subdomains) sat blocked despite their base domain already being trusted, one still blocked 7 minutes after the correction that should have released it. New `unblock_by_base_domain()` sweeps every blocked entry sharing a newly-trusted base domain, applied at all three self-healing call sites (autonomous CL-AFPE, LLM-validated, and the operator Telegram handler — which previously had no local-state check at all).
- **Ollama's batch analysis reached contradictory verdicts on the identical DGA-shaped pattern across devices in the same run**, because each call analyzes one device+target+signature group in total isolation. A multi-device spread guard now withholds auto-suppress (deferred, not skipped) when the same signature is independently firing on ≥3 distinct devices at once, rather than letting one instance's benign verdict silently write false-positive training data for what a cross-device view shows is DGA-shaped.
- **`zeek/salesforce/ja3` never actually worked on modern Zeek** (unmaintained since 2020, client-hello handler doesn't fire on Zeek 8.0.8) — switched to FoxIO's actively-maintained `zeek/foxio/ja4`, renaming the re-identification path throughout (`ja3_overlap`→`ja4_overlap`, etc.). Separately found the real root cause behind JA3/JA4 looking broken regardless of which package was installed: `zeekctl` silently ignores `node.cfg`'s `extra_args=-C`, so Zeek was discarding checksum-offloaded LAN-device outbound packets by default — fixed via `redef ignore_checksums = T;` directly in `local.zeek`.
- **`state.killchain_history` was read every cycle but never appended to anywhere** — `markov_anomaly` had been permanently `0.0` for every device since the feature was introduced.

### 🤖 Machine Learning & Training Data Integrity

- **The Tranco-rank feature (`tranco_rank`, Feature 0 of the LightGBM vector) was always zero.** `threat_intel.py` already downloaded the full ranked 1M-row Tranco list to build its Top-10k allowlist, but discarded the rank number on every line — `features["tranco_rank"]` was read by both Stage 2 and the trainer but never written anywhere. Fixed by capturing the rank half of the same already-downloaded data (`ThreatIntel.get_tranco_rank()`, persisted to `tranco_ranks.cache`, no extra network cost) and wiring `pipeline.py` to populate it.
- **New: identification/exclusion of historically-corrupted training rows.** The two domain-attribution fixes above (`DNS_COVERT_TUNNELING`, `DGA_BOTNET_C2`) mean `f1_entropy` was computed from the wrong domain for every affected alert predating each fix. Fixing the code doesn't fix rows already on disk — `src/identify_corrupted_training_rows.py` identifies them via each fix commit's own timestamp as a conservative, provable per-signature cutoff, and writes their dedup keys to a new, deletable overlay file (`state/training_row_exclusions.json`) that `train_fp_classifier.py` consults during training, without ever mutating `alerts.json`/`autonomous_muted.jsonl` themselves (both are read by other consumers that need the full real history).
- **LightGBM/ONNX classifier extended from 9 to 11 feature dimensions** (`arp_sweep_norm`, `dns_evasion_ratio`) to actually see the two new detectors — an earlier assumption that these were "inherited for free" by the classifier was wrong for this specific fixed-shape vector (true only for Ollama, which sees the full raw payload, and training-set inclusion generally). Verified with a real ONNX export + inference run.

### 🔍 Metrics, Observability & Grafana

- **Implemented the full metrics-audit report**: dropped unbounded-cardinality labels (lat/long crossed with country/ASN/org, attacker-chosen domain/IP labels), removed 4 redundant/dead counters, and added a new `home_ids_decision_path_total` gauge as the direct "is the system getting smarter over time" signal, plus source-labeled (`autonomous`/`operator`/`llm_validated`) self-healing counters. Every scheduled job now syncs its own JSON stats file into Prometheus gauges (`metrics_sync.py`'s new relay pattern) — job staleness is now a Grafana panel, not a manual log check.
- **New 5th Grafana dashboard**, "Autonomous Behavior & Self-Healing": decision-path mix, self-healing activity by source, autotune calibration, Ollama run transparency, containment unblock/release activity, scheduled-job health.
- **Fixed two classes of broken Grafana navigation link** found by actually testing them: cross-dashboard links using the wrong routing field (`uid` vs. this instance's `name`-based routing, across 20 links in 5 dashboards), and the Master Ledger's Isolate/Release links pointing at `127.0.0.1` (unreachable from a remote Grafana client).
- **Fixed the geomap panel** by adding a bounded static country-centroid table (~250 countries) after lat/long were deliberately removed from the traffic metric for cardinality reasons.
- **34 new full-transparency panels** for reactive capture, local confirmed-intel, and the new detectors — closing what had been zero-metrics visibility gaps.

### 🐛 Reliability & Concurrency

- **Two `UnboundLocalError` crashes, one crashing every single pipeline step.** A mis-indented `elif` attached to the wrong `if`, and a missing default assignment for `containment_decision_state` on the CL-AFPE auto-suppress path — both meant a variable could be read on a code path that never assigned it. Fixed by re-tracing every branch of both conditional chains, not just the lines originally touched.
- **Concurrent reactive-capture bursts were corrupting each other's output** — burst execution is now serialized.
- **Zeek reprocessing of a capture burst never found the pcap** — a relative path resolved against the wrong working directory.

### 🧹 Dead Code / Silent-Feature Audit

A full pass checking every function for "is this called at all, and correctly" turned up code that was built and tested in isolation but never reached from a real runtime path, alongside genuinely dead code:

- **ML anomaly models now migrate on device re-identification** — `MLRegistry.migrate_device()` existed and was accepted as a parameter by the identity-processing call sites, but nothing ever actually called it.
- **Stale isolation bookkeeping now actually clears on a re-identify merge** — `IPSMitigator.unisolate_all()` existed but was never invoked at the one point a merge could make it necessary.
- **`pipeline.py`'s `dest_ip` fallback now prefers Zeek's real wire-observed DNS resolution** over a live blocking `socket.gethostbyname()` call — more accurate, zero latency, and stops the IDS generating its own outbound DNS traffic as a side effect of alerting.
- **The FastAPI IPC/webhook server previously never started under default config** despite Telegram's revoke buttons pointing at it — it was gated solely on `ips_router_enabled` (default `false`), not the separate flag (`fp_revoke_notifications_enabled`, default `true`) that actually sends those buttons.
- **Deleted dead code**: an unbatched/uncached/no-rate-limit `OllamaSOCAnalyst` class that would have reintroduced the 849-second-blocking-call resource crisis fixed in 8.0 if ever wired in; three `StateManager` methods superseded by code paths that evolved independently (one of which referenced unimported names and would have raised `NameError` the one time it was called); two fully-unused `utils.py` functions.

### ⚙️ Configuration

- **Path-hardcoding cleanup**: every installation-specific path (`pihole_db`, `zeek_log_dir`, `reactive_capture_zeek_bin`) consolidated into a new `external_system_paths` config section at the bottom of `config.yaml`, with a "DO NOT TOUCH unless you know what you're doing" warning banner — separated from this app's own relocatable data-file paths.
- **`config.yaml` grew to 14 categories** with the addition of `reactive_capture`.
- **`requirements.txt` fixed**: 4 packages actually imported but missing (`skl2onnx`, `geoip2`, `joblib`, `urllib3`); stale Docker-era hardcoded fallback paths removed from `main.py`/`retro_hunter.py`.

### 🛠️ New Maintenance CLI Scripts

All dry-run-by-default, `--apply` to act — see [USER_MANUAL.md](USER_MANUAL.md#maintenance-cli-scripts-src-new-in-90):

- `src/clean_confirmed_intel.py` — audits/prunes the confirmed-intel poisoning categories above.
- `src/release_wrongly_blocked_domains.py` — classifies every currently-blocked Pi-hole domain (recognized-safe / manually-reviewed-safe / suspicious DGA-pattern / unclassified) and releases the safe categories.
- `src/clear_stale_isolation.py` — removes stale isolation bookkeeping for a single device without touching its domain blocks, for the case of a manual out-of-band router release the IDS's own state doesn't know about.
- `src/identify_corrupted_training_rows.py` — see Training Data Integrity above.

### 📚 Documentation

- **`CLAUDE.md` gained a "pre-flight checklist"** distilling ~12 recurring bug *classes* found this release (attribution-picker disconnection, non-exhaustive branches, unguarded learned-state poisoning, documented-but-unwired config keys, dead ML feature dimensions, legitimate-oscillation false positives, config-key collisions, historically-corrupted training data, mutating shared historical logs, escalation overriding an explicit trust floor) into concrete checks for future work — ported in generalized form to the `IDS_Product` sibling fork.
- Zeek installation docs corrected throughout (`/var/log/zeek` → the real `/opt/zeek/logs/current`, missing `mac-logging.zeek`/`local-arp-log.zeek` dependencies, a fabricated `detect-recon.zeek` load line removed, the checksum-offload gotcha documented).

## [v8.0.1] - 2026-08-18

Follow-up to v8.0.0, closing a gap in the autonomous suppression → containment relationship: immunizing a domain stopped *future* alerts for it, but nothing actually released a block that had already been placed by an *earlier* cycle. Per explicit direction — block only what's absolutely necessary; over-blocking risks breaking the legitimate function of a device.

### 🔓 Autonomous Unblock-on-Immunize

- **`pipeline.py`'s primary autonomous suppression path now releases stale blocks.** Every CL-AFPE Stage 2/3 auto-suppress runs through this path (the highest-volume one, by far). It previously immunized the domain but never checked whether an earlier cycle — before the pattern was learned as safe — had already blocked it in Pi-hole. Now checks local state first (`state_manager.get_ips_state()["blocked_domains"]`, no network call) and calls `unblock_domain()` only when the domain is actually currently blocked, avoiding both wasted Pi-hole API traffic and an inaccurate "released" log line for domains that were never blocked.
- **`ollama_soc.py`'s LLM-validated correction path gets the identical fix**, via its own `IPSMitigator` instance (same pattern `middleware/routers/pihole_api.py`'s existing Telegram-button handler already uses for exactly this — a fresh `StateManager` + `IPSMitigator` per invocation, since `unblock_domain()` makes a real Pi-hole API call regardless of which process instantiated the client).
- **The operator "Mark False Positive" Telegram path already had this** (`_ipc_immunize_logic()`'s existing FIX #3) — it was the two *autonomous* correction paths that were missing it, both now closed.

### 🏷️ Block Attribution Made Durable

- **Every Pi-hole block already carried a `"Home-IDS Auto-Block | Device: ... | Trigger: ..."` comment** on the primary (v6) API call path — this already existed prior to this release. What was missing: the two fallback paths (local `pihole deny` CLI, legacy v5 API) had no verified way to carry that comment through to Pi-hole without risking the block call itself failing on an unfamiliar CLI flag, so on those paths the attribution existed nowhere at all if Pi-hole's own comment field wasn't reachable.
- **Fixed by storing the same comment text in local state** (`ips.py`'s `_finalize_block()` now writes a `comment` field into `state/ids_state.json`'s `blocked_domains[domain]` entry, on every successful block regardless of which of the three Pi-hole paths executed it). This is now the durable, always-present answer to "was this blocked by the script, and why" — queryable locally even when Pi-hole's own UI doesn't show the comment (fallback paths) or is unreachable.

## [v8.0.0] - 2026-08-18

This release started from a third-party review of a single live alert (a connection to Telegram's own infrastructure that had been auto-blocked as a "99% Confirmed Malicious IOC") and expanded into a full trace of the detection, false-positive, and self-healing pipelines against the actual running code — plus a resource-usage crisis with the local LLM discovered via live diagnostics on production hardware, and the autonomous self-calibration system that request led to. Every fix below was verified against a concrete, reproducible scenario before being called done; several were confirmed against real entries in a live `alerts.json`, not synthetic test data.

### 🎯 Detection Correctness

- **Fixed a real false-block.** `reputation/classifier.py` was promoting a destination to "confirmed malicious IOC" (tier 5, `CRITICAL`, auto-block, 99% confidence) from a single AbuseIPDB score alone (`>2.0`), with VirusTotal and ThreatIntel both showing clean. The live case: a device talking to `149.154.166.110` — Telegram Messenger's own infrastructure. AbuseIPDB's crowd-sourced score is now required to clear `≥4.0` to reach "confirmed" — the exact bar `fp_engine.py`'s own hard-stop check already trusted it at (previously the two disagreed for the identical input). VT/TI keep the lower `>2.0` bar; they're more authoritative single-source signals.
- **Added a real `SUSPICIOUS`/monitor path for unconfirmed reputation signals.** Before this fix, a reputation signal that didn't reach "confirmed" had exactly one path through `decision_engine.py`: silence. Devices with a moderate, unconfirmed reputation ping now get a `SUSPICIOUS`/monitor-only verdict (never auto-blocks on this alone) instead of either a false "confirmed" block or nothing at all.
- **Fixed `intelligence/fp_engine.py` feeding the literal string `"unknown"` into semantic similarity scoring.** Raw-IP connections with no resolved hostname had `domain="unknown"`; Stage 3's FastEmbed cosine-similarity was scoring that literal word against vendor-domain embeddings and getting back a real-looking-but-meaningless number that materially swayed the combined false-positive score. Stage 3 is now skipped entirely when there's no real domain/hostname, falling back to LightGBM alone at full weight.
- **Fixed a raw IP address being mangled through the domain-suffix extractor.** `utils.py:etld1()`'s naive last-two-labels fallback was chopping bare IPs into fake 2-octet "domains" (e.g. `149.154.166.110` → `"166.110"`) — found sitting in `state/fp_trust_cache.json` as a literal `"166.110"` key, a meaningless, collision-prone trust-cache entry. IP-shaped input is now rejected before either extraction path runs.
- **Fixed the Telegram "⏳ WAITING FOR APPROVAL" contradiction.** `mitigate()`'s interactive-approval branches are only reachable at `risk ≥ 8.5` or an active lateral-movement flag — below that, nothing is ever queued. But `pipeline.py`'s alert formatter rewrote *any* "unblocked" containment status to "WAITING FOR APPROVAL" whenever `interactive_blocking_enabled` was on, with no check on whether anything was actually pending. A live `SUSPICIOUS`/monitor alert at risk 4.5 was showing "Action Required" approval buttons for an isolation that was never queued. Both the status-text override and the button attachment are now gated on the same `risk ≥ 8.5 or lateral_threat` floor `mitigate()` itself uses.
- **Closed a 43%-of-alert-volume false-positive gap.** Traced a live `alerts.json`: 169 of 227 alerts (74%) were `DNS_COVERT_TUNNELING`, and 97 of those (43% of *all* alerts) were a single benign Amazon telemetry hostname (`msh.amazon.co.uk`) — the same long-encoded-subdomain shape as an earlier Prime Video false-positive fix, just never extended to this domain. Added `amazon.co.uk`, `amazon.de`, `facebook.com`, `whatsapp.com`/`.net`, `netflix.net`, `pluto.tv`, `bugsnag.com`, and `ntp.org` to the CDN/vendor allowlist after confirming each was a real repeat offender in production traffic (and confirming a genuinely suspicious `.ru`-TLD domain in the same alert set correctly still trips detection).

### 🧭 Alert Transparency

- **Alerts now show a step-by-step reasoning trail** (`decision_engine.py` builds a `reasoning_trail` list alongside every decision: hard-stop check results, reputation context including IP ownership via ASN lookup, hypothesis scores, final verdict) instead of a bare confidence number. `ReputationVector.asn_owner` existed as a dataclass field but was never populated by anything — it's wired to the existing GeoIP ASN lookup now.
- **The Telegram headline no longer disagrees with its own trigger line.** It previously read `decision["hypotheses"]["attack"]["name"]` — which falls back to a generic placeholder (`DIRECT_IOC_HIT`) whenever no attack hypothesis's own evidence matched, even when the real trigger was a reputation hard-stop. Now reads `decision["explanation"]`, the same source the trigger line already used, so they can never disagree.
- **The false-positive engine's own combined confidence is now labeled explicitly** as a separate measurement from the decision engine's threat confidence, instead of two bare percentages sitting side by side with no explanation of what either one is (a third-party review flagged this as reading like an internal contradiction — it was really two independently-computed numbers with no labels).
- **Reputation "tier" is now documented and displayed as context, not a verdict** — `ReputationVector`'s docstring and the reasoning-trail text now spell out what each tier actually means (tier 4 = "one unconfirmed signal, not a verdict", not "4× more dangerous than tier 1").
- **`pipeline.py` now persists CL-AFPE's own verdict into every alert record** (`alert_payload["fp_verdict"]` — verdict/confidence/stage). This field didn't exist before 8.0; without it there was no data for the self-calibration pass below to learn from at all.

### 🤖 Autonomous Self-Calibration (new)

- **The false-positive engine now calibrates its own suppression threshold from real evidence**, both global and per-device, with zero human involvement required. Full mechanics in [USER_MANUAL.md §2](USER_MANUAL.md#-autonomous-self-calibration--the-override-layer) and [ENGINEERING_MANUAL.md §5](ENGINEERING_MANUAL.md#5-the-autonomous-self-calibration-loop). Summary: needs ≥5 pooled (or ≥3 per-device) confirmed false positives, only ever lowers the threshold, refuses outright on any ambiguous overlap with never-corrected alerts, has a hard floor.
- **A new, layered config-override system replaces "the LLM edits `config.yaml` directly"** (an earlier, never-fully-working design). `config.py`'s `LiveConfig` now also watches `state/config_overrides.json` (global autonomous adjustments) and `fp_engine.py` owns `state/device_fp_profiles.json` (per-device adjustments) — both layer on top of the hand-authored `config.yaml` baseline at read time, both are watched live (~5s), and **neither is ever written to `config.yaml` itself.** Deleting a key from either file instantly reverts to the `config.yaml` value.
- **`ollama_soc.py`'s LLM-validated corrections are now a first-class, human-independent evidence source.** `fp_engine.mark_false_positive()` gained a `source` parameter (`"operator"` vs `"llm_validated"`) so the calibration pass can tell a real Telegram tap apart from the batch analyst's own validated correction — or pool both. Previously both were mislabeled identically as `OPERATOR_MARKED_FALSE_POSITIVE`, and the batch analyst's autonomous action wrote to `safe_host_patterns` (a device-*hostname* matcher, not a domain-suppression mechanism — it could never have suppressed anything even before this fix, an independent bug found while tracing the mislabeling).
- **Two independent retrain triggers now both run calibration.** `fp_engine.py` has its own internal 7-day in-process retrain thread, separate from the scheduler's standalone daily 3am cron invocation of `train_fp_classifier.py` — both call the same `train_and_export_onnx()`, but only the cron path was also calling the new calibration function. Fixed so both paths run calibration after their retrain step, regardless of whether the retrain itself succeeded.

### 🚫 Ollama Resource Usage

- **Diagnosed a resource crisis, not just a bug.** A live `curl` to the production Ollama server's `/api/generate` endpoint measured **849 seconds** of `total_duration` for a trivial "say hello" prompt, while the model's own reported `load_duration` + `eval_duration` summed to only ~13 seconds — the other ~836 seconds was pure CPU-contention queueing under real load (300%+ CPU observed). This explained three days of `ollama_soc.py` producing empty reports with zero successful analyses ever recorded — a symptom that had been invisible because of the logging bug below.
- **`ollama_soc.py` rewritten around dedup, caching, and a hard cap.** Alerts are grouped by `device + target + signature` before any LLM call — a single pattern that fired 50 times costs one call, not 50. Verdicts are cached for 7 days (`ollama_cache_ttl_seconds`); fresh calls per run are hard-capped at 5 (`ollama_max_queries_per_run`), with anything beyond the cap deferred to the next run, prioritized by which pattern repeated most. Also now skips alerts CL-AFPE already suppressed cheaply, spending the LLM only on alerts that genuinely needed a judgment call.
- **Fixed `ollama_soc.py` re-analyzing its own prior output.** It read the last-24h alert window with no `type` filter, meaning its own `ollama_transparency` log entries (appended to the same `alerts.json` it reads from) would be re-ingested and re-queried on the next run. Now explicitly filters to `type=="ids_alert"`.
- **A second, real-time, unthrottled Ollama pathway removed entirely.** `intelligence/ollama_analyzer.py` was instantiated at boot (spinning up a background thread + queue) but its only method, `.analyze()`, was never actually called from anywhere — the one call site in `pipeline.py` was commented out. Left in place, it would have duplicated `ollama_soc.py`'s now-carefully-throttled responsibility via a completely unthrottled path if ever re-enabled. Removed, along with the now-orphaned `ollama_api_key` config key it alone consumed.

### 🔍 Scheduler & Observability Gaps

- **Fixed the scheduler's own output going to `/dev/null`.** `main.py` piped the `scheduler.py` subprocess's stdout/stderr to `DEVNULL` — and since `scheduler.py` launches every scheduled job (`ollama_soc.py`, `retro_hunter.py`, `top_domains_report.py`, `train_fp_classifier.py`) as a child process with no redirect of its own, every one of those scripts' log output was unrecoverable too. There was already a documented precedent for this exact fix two sections above in the same file (the FastAPI subprocess got a real log file); it just never reached the scheduler. Now redirected to `state/scheduler.log`.
- **`retro_hunter.py`'s findings had no durable record or real-time alert** — its only output was `LOGGER.critical()`, which the bug above was silently swallowing. A genuine zero-day retroactive match would have produced nothing an operator could ever see. Matches now append to `state/retro_hunt_findings.jsonl` (kept deliberately separate from `alerts.json` — a retro-hunt match has no live device state/features, and forcing it into that schema risked either crashing feature extraction or being silently misinterpreted by the training pipeline) and send a real-time Telegram alert.
- **Fixed a dead/wrong fallback path in `retro_hunter.py`.** Its default `alert_json_path` fallback (`/app/state/alerts_stream.jsonl`) was a leftover from an earlier Docker-based layout this project no longer uses, pointing at a filename the project's own internal engineering guidelines explicitly say must never be referenced. Dead in practice (the real config always resolved correctly) but a real trap if `alert_json_path` were ever briefly unset.

### 🧹 Dead Code Removal

- **`mitigation/scoring.py`** (418 lines) — the legacy risk-scoring engine, confirmed still dead (zero real imports anywhere) after its logic was fully ported into `threat_signals.py`/`hypotheses/engine.py` in an earlier release but the original file was never deleted.
- **`intelligence/ollama_analyzer.py`** — see "Ollama Resource Usage" above.
- **`ollama_api_key` / `OLLAMA_API_KEY`** — orphaned by the above; `ollama_soc.py`, the sole remaining Ollama consumer, sends no auth header.
- **`ruamel.yaml` dependency** — existed only for `ollama_soc.py`'s old `save_config_key()` (comment-preserving writes to `safe_host_patterns`), itself removed as part of the mislabeling fix above (that write target was always wrong regardless — see "Autonomous Self-Calibration"). Nothing in the codebase writes to `config.yaml` at runtime anymore.

### ⚙️ Portability

- **`config.py`'s production config loader was missing explicit UTF-8 encoding** on both read and write of `config.yaml` — the one inconsistent reader; its sibling scripts (`scheduler.py`, `ollama_soc.py`) already specified it correctly. Would silently break config reload under any non-UTF-8-locale deployment (not just the Windows dev environment this was first caught on) — `config.yaml`'s comments are full of UTF-8 emoji and em-dashes. Fixed both directions.

## [v7.0.1] - 2026-08-17

This release closes out a full end-to-end audit of the configuration system and the background job scheduler. Nothing in the detection math changed — this is a reliability, transparency, and maintainability pass: two silent scheduling bugs are fixed, every configuration key was individually verified against the code that reads it, and the entire configuration file was migrated from `config.json` to a documented, categorized `config.yaml`.

### 🐛 Scheduler Fixes (Phase 7)

- **Fixed `retro_hunter` never actually running.** `scripts/scheduler.py` looked up each scheduled job's script filename using the job's config key directly (`retro_hunter` → `retro_hunter.py`), but the real script is invoked differently, so the cron entry silently matched nothing and the job never fired — with no error, no log line, nothing. Added an explicit `script:` override field to the job definition (see `scheduled_jobs.scheduler.retro_hunter.script: retro_hunter.py` in the new `config.yaml`) and made the scheduler prefer it over the filename-guessing default. Historical threat-intel re-scans are now confirmed running on schedule.
- **Fixed `ollama_transparency` / `ollama_soc` training-data contamination.** The batch LLM analyst job was reading from the same alert stream file it writes its own derived annotations back into, which meant each run's output was partially re-ingested as if it were new evidence on the next run — a slow feedback loop that could bias Brain 3's reasoning over time. The read path and the write path are now backed by clearly separated files, and a regression test (`tests/test_phase7_scheduling.py`) locks in both this fix and the `retro_hunter` fix above.

### 🔍 Full Configuration Audit

Every single key previously read via `config.get(...)` anywhere in the codebase was cross-checked one-by-one against `config.json`, and every key in `config.json` was cross-checked against the code that was supposed to read it. This surfaced several issues that had been silently accumulating:

- **Discovered the `scheduler` block was effectively undocumented and partially unwired.** The cron definitions driving `ollama_soc`, `retro_hunter`, and `top_domains_report` existed in code defaults but were never clearly exposed as first-class, documented configuration — contributing to the `retro_hunter` bug above going unnoticed.
- **Removed 5 dead configuration keys** that are no longer read anywhere in the code: `scheduled_tasks` (superseded by the `scheduler` block), `geofencing_mode`, `geofencing_time_policies` (geofencing has always been blocklist-only in the actual implementation — no allowlist or time-policy logic exists), `autotune_min_risk_threshold`, and `layer2_spoofing_detection_enabled` (Layer-2 spoofing detection is unconditional in the code — it was never actually gated by this flag, so the key was pure dead weight).
- **Added 12 configuration keys** that code was already reading via `config.get(key, <hardcoded default>)` but which were never listed anywhere for operators to discover or override: `env_file`, `home_subnets`, `identity_reidentify_enabled`, `identity_reidentify_min_confidence`, `identity_reidentify_window_seconds`, `simulation_mode`, `router_hosts_url`, `router_hosts_timeout_seconds`, `router_webhook_timeout_seconds`, `pihole_api_timeout_seconds`, `suspicious_escalation_seconds`, and the `fp_revoke_notifications_enabled` / `fp_revoke_action_ttl_seconds` / `fp_operator_feedback_ttl_seconds` trio.
- **Fixed a broken `geoip_db` / `geoip_asn_db` default path.** The shipped default (`../geoiop/GeoLite2-City.mmdb`) pointed one directory *above* the repo root, into a directory name that was itself misspelled (`geoiop`). Since `GeoIPEngine` silently sets `self.reader = None` and logs a single startup line when the `.mmdb` file fails to load, this meant GeoIP telemetry — and **geofencing enforcement, which depends entirely on GeoIP resolving successfully** — could be silently inert on a fresh install with nobody the wiser. Corrected to `models/GeoLite2-City.mmdb` / `models/GeoLite2-ASN.mmdb`, and the new docs call this dependency out explicitly.
- **Removed a duplicate `fastapi_port` definition** that existed in two places in the old config with no code-level guarantee that both stayed in sync.
- **Enforced the mandated directory layout.** `src/`, `state/`, `models/`, `config.yaml`, `alerts.json`, `.env`, `reports/`, and `tests/` are now all verified as siblings directly under the repo root, matching what `config.py`'s relative-path resolution actually assumes at runtime.
- **Relocated the test suite.** All 9 `test_phaseN_*.py` files (`test_phase0_fixes.py` through `test_phase7_scheduling.py`, covering fixes 0 through 7) were moved out of `src/` into a new top-level `tests/` directory, with `sys.path` bootstrapping added to each so they resolve `src` imports correctly from their new location. 151/151 checks pass across all 9 files.

### 🎯 False-Positive Engine: Live Threshold Tuning

- **`fp_lgbm_threshold`, `fp_embed_similarity_threshold`, `fp_combined_suppress_threshold`, and `fp_combined_uncertain_threshold` are now genuinely live-tunable.** These four thresholds govern Stage 2 (LightGBM) and Stage 3 (FastEmbed) of the CL-AFPE pipeline in `intelligence/fp_engine.py`. Previously they existed as config keys but several code paths read them once at object construction time rather than freshly on every alert evaluation, so editing them at runtime had no effect until a full service restart — despite living in what operators would reasonably assume was the "live-reload" part of the config. All four are now read via `self.config.get(...)` at evaluation time, confirmed by direct inspection of the evaluation call path, and are annotated `[LIVE]` in the new `config.yaml`.

### ⚙️ Configuration System: Migrated `config.json` → `config.yaml`

The single biggest change in this release. The old `config.json` had grown into a flat, hard-to-audit file split only by a rigid `static_requires_restart` / `dynamic_live_reload` top-level schema that forced every new key into one of two buckets regardless of what it actually configured. It's been replaced entirely by a categorized, heavily-commented `config.yaml`:

- **13 logical categories** replace the old 2-bucket split: `service_ports`, `paths`, `network_and_devices`, `detection_engine`, `false_positive_engine`, `device_identity`, `geofencing`, `threat_intel_and_ai`, `ips_mitigation`, `pihole_integration`, `fritzbox_router`, `telegram`, and `scheduled_jobs`. Keys are grouped by *what they control*, not by restart behavior.
- **Restart-vs-live behavior is now a per-key `[LIVE]` / `[RESTART]` annotation** in the comment above each key, instead of being encoded in which top-level section the key happened to live in. This is a documentation change only — the actual enforcement mechanism (`config.py`'s `_STATIC_KEYS` set, matched by key name) is unchanged and was verified to still correctly gate every key regardless of its new category.
- **`config.py`'s loader is now category-agnostic.** Instead of hardcoding the two old section names, `_load()` now flattens *any* top-level YAML mapping whose name doesn't start with `_` or `#` into one flat runtime namespace. This means the 13 categories above are a purely organizational/documentation convenience for operators — adding a 14th category in the future requires zero code changes.
- **Secrets are fully out of the file.** API keys, tokens, and passwords (`TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `OTX_API_KEY`, `ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY`, `PIHOLE_API_PASSWORD`, `PIHOLE_API_URL`, `FRITZ_USER`, `FRITZ_PASS`, `API_SECRET_TOKEN`, `ROUTER_WEBHOOK_URL`, `IDS_IPS_PIHOLE_ENABLED`, `IDS_IPS_ROUTER_ENABLED`, `IDS_IPS_TARPIT_ENABLED`, `OLLAMA_API_KEY`) live exclusively in `.env` (path configurable via the new `paths.env_file` key) and are applied on every reload via `config.py`'s `apply_env_overrides()`. They were previously scattered directly in `config.json` in plaintext next to non-sensitive settings.
- **`scripts/scheduler.py` and `scripts/ollama_soc.py` updated for YAML.** Both scripts deliberately avoid booting the full `config.py` singleton (they're short-lived subprocess jobs and don't need the whole engine spinning up just to read a cron string), so each has always maintained its own lightweight `load_config()`. Both were updated to parse YAML and mirror `config.py`'s new category-flattening logic.
- **Found and fixed a comment-loss bug in `ollama_soc.py`'s self-healing write path.** `save_config_key()` is what Brain 3 calls when it autonomously adds a newly-learned benign domain to `network_and_devices.safe_host_patterns`. Because this needs to preserve every human-written comment in `config.yaml` on every write (not just the value being changed), it uses `ruamel.yaml`'s round-trip mode rather than plain `pyyaml`. Testing surfaced an edge case: `ruamel` attaches a comment that sits between the end of a list and the following key to that list's *last index* — so when the list's length changes, the comment can end up silently orphaned or attached to the wrong line. The fix pops the comment from its old index, mutates the list in place via slice-assignment (preserving `ruamel`'s object identity tracking), and re-attaches the comment at the new last index. Covered by `tests/test_phase6_fp_selfheal.py`.
- **New dependencies**: `pyyaml>=6.0` (used by `config.py`, `scripts/scheduler.py`, and `scripts/ollama_soc.py` for standard read paths) and `ruamel.yaml>=0.18` (used exclusively by `ollama_soc.py`'s comment-preserving write path). Both are now pinned in `requirements.txt` — a plain `pip install -r requirements.txt` picks them up automatically.

## [Unreleased] - 2026-08-13

### 📊 Grafana Observability & UI Overhaul
- Completely refactored and consolidated 5 legacy Grafana dashboards into 4 streamlined modules (`1_main_overview`, `2_threat_landscape`, `3_device_deep_dive`, `4_system_health`), backing up legacy dashboards to `dashboard_backup/`.
- Fixed Loki log querying syntax and UID alignment across all Grafana panels for seamless drill-down alerting.
- Added comprehensive Prometheus telemetry panels tracking CPU, Memory, Pipeline Latency, and Zeek processing metrics.

### 🛡️ False Positive Engine & Telegram SecOps
- Fixed critical `Trust Cache` poisoning bug where raw IP connections without a domain caused the Telegram bot to generate a broken `immunize:unknown` payload.
- Added a hard guard clause in `fp_engine.py` rejecting `"unknown"`, `"null"`, and empty strings from being permanently immunized.
- Increased the Ollama API timeout from 5.0 to 30.0 seconds to prevent LLaMA 3.1 AI summaries from silently failing in Telegram.

### ⚙️ System Configuration & Performance
- Silenced aggressive scikit-learn and joblib `UserWarning` Loky thread-worker spam in `journalctl` by enforcing a global `PYTHONWARNINGS="ignore"` policy.
- Officially added integration support for internal Docker `Cowrie` Honeypots via `config.json`'s `honeypot_ips` array. *(As of v7.0.0, this key lives in `config.yaml`'s `network_and_devices` category.)*
- Updated `README.md` and `USER_MANUAL.md` with sections detailing the ultra-optimized, asynchronous, multi-threaded architecture explicitly designed for low-spec servers (e.g., Raspberry Pi).

## [Unreleased] - 2026-08-11

### 🧩 Stability & Security Hotfixes
- Fixed webhook auth behavior to reject remote unauthenticated requests when `fritz_api_token` is unset (loopback IPC remains trusted).
- Fixed hypothesis engine score carry-over by resetting per-evaluation state.
- Fixed ML learning order in pipeline to avoid pre-verdict poisoning in alert paths.
- Fixed retro hunter domain extraction for JSONL alert payload schema and config-resolved stream paths.
- Added Prometheus no-op fallback in `metrics.py` for constrained/offline environments.
- Fixed DNS zero-feature schema consistency (`dns_txt_null_ratio`, `suspicious_tld_ratio`, `beaconing_c2_1h`).
- Fixed regression test compatibility for trainer/FP-engine API drift.

## [Unreleased] - 2026-08-09

### 🔎 Operator Visibility & Mitigation Hardening
- Added explicit evidence-verification indicators to threat alerts and Telegram notifications for partially supported detections.
- Hardened Layer-2 tarpit handling so existing targets are refreshed with later MAC identification and unknown-MAC cases are logged clearly.
- Persisted Pi-hole block state across restarts with explicit active status metadata for better recovery and operator visibility.
- Preserved IP-first device identity while continuing to update MAC and hostname information from newer Zeek and ARP telemetry.
- Improved resilience around Pi-hole API failures so mitigation continues to proceed for router isolation and tarpit containment even when the Pi-hole endpoint is temporarily unreachable.

## [v5.0.0] - 2026-08-08

### 🚀 Major Architecture Overhaul: Hypothesis & Evidence Engine (HEE)
- **Completely Rebuilt Decision Engine** (`pipeline.py`, `ai_soc.py`): Transitioned from a flat arithmetic risk score to a deterministic, graph-based Evidence Store. The system now collects behavioral facts (e.g. `repeated_parent_domain`, `high_entropy`, `dns_tunneling`) and evaluates them against strict hypotheses (e.g. `DNS_TUNNELING`, `BEACONING`, `EXFIL`).
- **Local AI SOC Analyst (Ollama Integration)**: Integrated `llama3.1` running natively on `localhost:11434`. The LLM receives full JSON context for each alert and operates as an autonomous Tier 2 SOC Analyst to evaluate the evidence graph.
- **Deterministic AI Validator Guardrail**: Introduced a deterministic reputation guardrail. If an IP or domain holds a known Tier 5 malicious reputation from Threat Intel, the system will aggressively reject the LLM's opinion if it hallucinates a "BENIGN" verdict.
- **Telegram AI Summarization**: The Telegram alert dispatcher now offloads alert payloads to Ollama in a background thread to generate 1-sentence executive summaries of the threat, appended directly to Telegram messages.
- **Grafana Triage Hub Upgrades**: Overhauled the Grafana dashboards to replace the deprecated 0-10 Risk Score with the new `home_ids_threat_confidence` emitted by the HEE engine.

### 🧠 Machine Learning & Temporal Context
- **Temporal/Diurnal Awareness**: Injected `time_sin` and `time_cos` features into the `LightGBM` / `IsolationForest` ML pipelines to give the models contextual awareness of the time of day, vastly reducing false positive anomalies during non-standard hours.
- **Graceful Dimensionality Upgrades**: Upgraded the device state schemas to dynamically invalidate legacy 9-feature models and rebuild the new 11-feature temporal baselines without crashing.

### 🔧 Bug Fixes & Optimizations
- **Fixed StateManager Evidence Leak**: Ensured `self.evidence_store.clear_device(dev_id)` is explicitly called when stale devices are pruned from the pipeline, permanently fixing memory accumulation.
- **Hardened System Polling Loop**: Hardcoded strict `time.sleep()` blocking across all internal `while True` polling loops (Zeek, API requests, Alert Managers) to prevent catastrophic infinite-loop log spam that could previously overwhelm `rsyslogd`.

## [v4.0.8] - 2026-08-06

### 🔴 Critical Bug Fixes
- **Fixed `NameError`-class bug: `is_poisoned` used before definition** (`pipeline.py`): `is_poisoned` was
  referenced on line 309 of the ML training guard `if dev_id in all_active_ids and not is_poisoned` before
  being assigned on line 338. On the first device in every 2s cycle this caused a `NameError`; on subsequent
  devices it used a stale value from the previous loop iteration, silently poisoning ML training.
  `is_poisoned = state.is_poisoned(risk)` is now computed immediately after `risk_details` is available.
- **Fixed `UnboundLocalError` for `webhook_log_file`** (`main.py`): When `ips_router_enabled = false`
  (the default config), `webhook_log_file` was never assigned. `shutdown_handler()` referenced it
  unconditionally, raising `UnboundLocalError`. Initialized to `None` before the conditional block.

### 🟡 Performance & Reliability Fixes
- **Reduced `_global_lock` scope for expensive I/O** (`pipeline.py`): Per-device processing was restructured
  into 4 phases. ThreatIntel lookups, AbuseIPDB, and VirusTotal queries now run in Phase 2/3 **outside** the
  global device lock. The lock is now held only for quick state reads (Phase 1) and risk/ML writes (Phase 4),
  eliminating HTTP round-trip latency from the critical lock window.
- **Fixed `rolling.domains` unbounded accumulation** (`pipeline.py`, `state.py`): The per-device DNS domain
  `Counter` grew unboundedly across the device's lifetime. Now pruned each cycle via `domain_timestamps`
  entries older than `window_seconds`. `rolling.blocked` and `rolling.nxdomain` are now re-derived from
  the bounded `events` deque on each cycle so they can't inflate beyond the window.
- **Switched `AlertJSONWriter` to O(1) JSONL append mode** (`alerts.py`): Previously `write()` read the
  entire alert JSON array, parsed it, appended, and rewrote it on every alert (O(N) per write). Now uses
  `file.open("a")` append mode with one compact JSON line per alert. Existing JSON array files are
  automatically converted to JSONL on first startup.
- **Added O(1) MAC update via reverse IP index** (`state_guard.py`): `update_device_mac()` previously
  performed an O(N) linear scan across all device states for every Zeek ARP event. A `_ip_to_device_id`
  reverse index is now maintained on all device create/register/migrate operations, making MAC binding O(1).
- **Fixed HTTP call under lock in `release_device()`** (`ips.py`): `_unisolate_device_router()` was called
  while holding `self._lock`, causing the Fritz!Box HTTP round-trip (up to 10s timeout) to block all
  lock-protected operations. Restructured into: Phase 1 (collect targets under lock) → Phase 2 (HTTP outside
  lock).

### 🔒 Security Fixes
- **Telegram command authentication** (`alerts.py`): `/unblock`, `/release`, `/release_all` and inline
  button callbacks can now be restricted to authorized sender IDs via `telegram_allowed_chat_ids` in
  `config.json`. Default is empty list (allow all) for backward compatibility.
- **Uvicorn CWD-independent startup** (`main.py`): Changed module import from `src.middleware.fritz_webhook:app`
  to `middleware.fritz_webhook:app` with `--app-dir <src_dir>` flag so the daemon starts correctly regardless
  of the process working directory (e.g., systemd unit with a custom `WorkingDirectory`).

### 🟢 Minor Fixes & Configuration
- **Pi-hole API path is now configurable** (`ips.py`, `config.py`): Hardcoded `/api/v2/domains` replaced
  with `config.get("pihole_api_path", "/api/v2/domains")`. Set `pihole_api_path` in `config.json` to use
  Pi-hole v5 (`/api/dns/blacklist`) or a custom path.
- **`release_all_devices()` uses MAC as canonical key** (`ips.py`): Fixed edge case where two devices with
  identical hostnames would only generate one release call. Now uses MAC address as primary identifier,
  falling back to IP, then hostname.
- **`fastapi_port` and `telegram_allowed_chat_ids` added to `DEFAULT_CONFIG`** (`config.py`): Both keys
  were previously used in code without being documented in the defaults dict.
- **`router_isolated_devices` and `operator_released_devices` added to `_ips_state` defaults** (`state_guard.py`):
  Prevents `KeyError` if code accesses these keys on a fresh install before the first isolation event.
- **Honeypot IP sourced from `config["honeypot_ips"]`** (`scoring.py`, `pipeline.py`): Alert detail message
  previously hardcoded `192.168.1.200`. Now reads from `config.json["honeypot_ips"]` list, injected into
  the feature dict before scoring.
- **`_bot_updates_worker` responsive shutdown** (`alerts.py`): Replaced `time.sleep(5)` with
  `threading.Event.wait()`. Thread now stops within ≤1 second of `stop()` being called, instead of waiting
  up to 25 seconds for the Telegram long-poll to time out.
- **`get_ips_state()` TOCTOU warning added** (`state_guard.py`): Docstring now clearly warns that inner
  dicts are mutable references and directs callers to `update_ips_state_atomic()` for read-modify-write.

## [v4.0.7] - 2026-08-06

### 🔒 Security & Local Loopback IPC Trust
- **Local Loopback IPC Authentication**: Updated `verify_token` in `src/middleware/fritz_webhook.py` to automatically trust loopback requests (`127.0.0.1`, `::1`, `localhost`). This allows local CLI utilities (like `release_device.py`) to execute live daemon memory releases seamlessly without needing `API_SECRET_TOKEN` exported in the user's interactive shell profile.

## [v4.0.6] - 2026-08-06

### 🐛 Bug Fixes & Diagnostics
- **Enhanced CLI IPC Fallback Telemetry**: Updated `src/release_device.py` to output explicit exception details (`ConnectionRefusedError`, HTTP status codes) when live daemon IPC is offline or unconfigured, making CLI diagnostics transparent.

## [v4.0.5] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Unauthenticated Local IPC Support**: Updated `verify_token` in `src/middleware/fritz_webhook.py` to allow local IPC release calls (`POST /api/ipc/release`) when `fritz_api_token` is unconfigured (`""`) without throwing HTTP 500 configuration errors.

## [v4.0.4] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Telegram Alert Plain Text Fallback**: Added automatic plain text fallback in `AlertManager._dispatch_worker()` if Telegram rejects formatted alert messages with HTTP 400 (`can't parse entities`).
- **Telegram Inline Button Read Timeout Fix**: Increased local IPC timeout in `_handle_telegram_callback()` from `3.0s` to `10.0s` to prevent `HTTPConnectionPool Read timed out` exceptions when operators tap Telegram inline action buttons.

## [v4.0.3] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Fixed `NameError: name 'alert_threshold' is not defined`**: Defined `alert_threshold` float evaluation in `IPSMitigator.mitigate()` in `src/mitigation/ips.py` from `config.json` before checking Pi-hole domain block threshold conditions.

## [v4.0.2] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Fixed `NameError: name 'pihole_enabled' is not defined`**: Defined `pihole_enabled` boolean evaluation in `IPSMitigator.mitigate()` in `src/mitigation/ips.py` before checking Pi-hole domain block threshold conditions.
- **Regression Test Alignment**: Updated `test_09` in `src/test/test_ids_regression.py` to match the 5.5 risk score threshold for baseline poisoning freeze.

## [v4.0.1] - 2026-08-06

### 🐛 Bug Fixes & Resilience
- **Graceful `tldextract` Fallback**: Updated `etld1()` in `src/utils.py` with try/except fallback logic so system execution operates smoothly without throwing `ModuleNotFoundError` if `tldextract` is missing from system Python.
- **Immediate Pi-hole DNS Sinkholing**: Ensured Pi-hole domain sinkholing executes 100% immediately upon threat detection; interactive Telegram approval (`interactive_blocking_enabled`) applies strictly to Layer-2/3 Hardware Isolation (Fritz!Box WAN drop and Scapy ARP/NDP tarpit).
- **Explicit HITL Startup Log Banner**: Added startup log banner in `IPSMitigator` notifying operators of active HITL vs Auto-block configuration on boot.
- **Repository Privacy & Clean Git Tracking**: Added root `.gitignore` excluding runtime logs, state snapshots, and compiled bytecode.

## [v4.0.0] - 2026-08-06

### 🚀 Major Features & Architectural Redesign

#### 1. Interactive Telegram Human-in-the-Loop (HITL) Mode
- **Configurable HITL**: Added `interactive_blocking_enabled: true/false` option in `config.py`.
- **Immediate DNS Sinkholing**: Pi-hole domain blocking remains 100% immediate and autonomous upon threat detection.
- **Interactive Hardware Isolation**: When `interactive_blocking_enabled: true` is set, Layer-2/3 Hardware Isolation (Fritz!Box WAN Drop and Scapy Layer-2 ARP/NDP Tarpit) is queued for Telegram operator approval.
- **Inline Action Buttons**: Telegram alerts feature live inline keyboard buttons:
  - `[ 🔒 Approve Hardware Isolation ]`
  - `[ 🔓 Release Device ]`
  - `[ 🛡️ Immunize FP Domain ]`
- **Telegram Bot Command Listener**: Asynchronous background worker (`_bot_updates_worker`) handles `/unblock <target>`, `/release <target>`, `/release_all`, and `/status` commands directly via Telegram chat.

#### 2. Process IPC & State Synchronization Architecture
- **FastAPI Local IPC Server**: Added local IPC endpoint `POST /api/ipc/release` on port 8010.
- **Split-Brain Prevention**: Updated CLI tool `release_device.py` to communicate directly with the running `soc.service` process memory over local IPC, preventing stale memory overwrites.
- **Full Scope Unblocking**: `release_device()` releases Layer-2 ARP tarpits, Fritz!Box WAN drops, and associated Pi-hole blocked domains simultaneously.

#### 3. 1-Hour Operator Release Cooldown & Lateral Movement Override
- **1-Hour Release Cooldown**: Releasing a device registers a 3600-second cooldown period, preventing immediate re-blocking on decaying background metrics.
- **Hard Safety Override**: If internal subnet port scanning or lateral movement (`zeek_lateral_moves > 0`) is detected during cooldown, the cooldown is **instantly bypassed**, hardware containment is re-enforced, and a high-priority alert is logged.

#### 4. Multi-Threat 9-Feature Matrix Alignment & Model Validation
- **Unified 9-Feature Vector**: Expanded anomaly feature vectors across `DeviceMLEngine` and `GlobalMLEngine` to include `zeek_lateral_moves`, `zeek_s0_rej_count`, and `zeek_app_protocol_weight`.
- **Automated Retraining & Hot-Reload**: Created `src/scripts/train_fp_classifier.py` and weekly daemon `_weekly_retrain_loop()` in `fp_engine.py` to auto-retrain and hot-reload `models/fp_classifier.onnx` on the full 9-feature matrix.
- **Dynamic ONNX Input Shape Guard**: Updated `_stage2_lgbm()` in `fp_engine.py` to dynamically inspect ONNX input tensor signatures at runtime (`[None, 6]` vs `[None, 9]`).

#### 5. Real-Time Prometheus & Grafana Metrics Synchronization
- **Real-Time Garbage Collection**: Added `garbage_collect_ips_metrics()` to the pipeline execution loop in `pipeline.py` to synchronize active gauge labels with live state.
- **Clean Label Removal**: Updated `unblock_domain()`, `release_device()`, and `release_all_devices()` to call `.set(0.0)` and `.remove()` on Prometheus metrics (`ips_tarpit_active`, `ips_router_isolated_active`, `ips_active_blocks_gauge`).

#### 6. Core Stability & Code Quality Fixes
- **Non-Blocking IsolationForest Training**: Replaced synchronous `.fit()` in `ml_engine.py` with background daemon threads (`_fit_worker`) and atomic model swapping under `_fit_lock`.
- **Atomic State Guard**: Added `update_ips_state_atomic()` to eliminate TOCTOU disk state race conditions.
- **LRU Cache Concurrency**: Wrapped `_ip_cache` in `identity.py` with thread locks and converted to `OrderedDict` with LRU eviction.
- **Clean Shutdown Handling**: Added explicit file handle closure (`webhook_log_file.close()`) in `main.py` signal handler to eliminate exit `ResourceWarning`.
