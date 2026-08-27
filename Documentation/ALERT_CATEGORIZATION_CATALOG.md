# Alert Categorization Catalog

Every verdict this engine can produce, the exact code condition that generates it, and
what real production data (`state/alerts.json` on the live box, queried 2026-08-27) shows
about how often each one actually fires. Built as a systematic consistency audit — the
same methodology that found Gaps 1-3, now applied to every category, not just the ones a
specific incident happened to surface.

**How to keep this current:** update this file in the same change that touches any
function listed below, same discipline as `DECISION_LOGIC_DEPENDENCY_MAP.md`.

## Layer 1 — `DecisionEngine.evaluate()` (`core/decision_engine.py`)

Checked in this exact order; first match wins. All real production counts below are from
grouping every alert's own `reasoning_trail` "Verdict:" line (16,000+ alerts).

| # | State / Action / Explanation | Exact trigger condition | Confidence | Live count |
|---|---|---|---|---|
| 1 | CRITICAL / block / "Internal Honeypot Accessed" | `any(e.type=="honeypot_access")`. Evidence created in `pipeline.py` when `features["zeek_honeypot_hits"] > 0 and not is_safe` (the `not is_safe` gate is Gap 3 Fix B, added 2026-08-27) | 1.0 | 16 |
| 2 | CRITICAL / block / "Layer-2 ARP Spoofing Detected" | `any(e.type=="arp_spoofing")`. Evidence created on a **second** MAC-flip within 600s on the same IP (a lone flip is weak/corroboration-required evidence instead — see `arp_spoof_pending`), gated on `not is_safe` | 1.0 | 191 (all `hostname="unknown"`, all Aug 19-22, **zero since** — see audit note below) |
| 3 | CRITICAL / block / "Geofencing Policy Violation" | `any(e.type=="geofencing_violation")`. `geofencing_enabled=true` and the destination's GeoIP country ISO code is in `geofencing_countries` | 1.0 | 20 (all `paperless`/`unknown` — see audit note, attribution bug found + fixed 2026-08-27) |
| 4 | CRITICAL / block / "Confirmed Exploit/Malware Signature (Suricata)" | `any(e.type=="suricata_signature_match" and e.confidence>=0.9)`. Real Suricata rule match, severity=1/"high", from batch-mode scan of a reactive-capture burst pcap | 0.98 | 18 (as `SIGNATURE_MATCHED_THREAT` hypothesis name — see note) |
| 5 | CRITICAL / block / "Confirmed Malicious IOC" | `rep.tier == 5`, i.e. `classifier.py`: `vt_score>2.0 OR ti_score>2.0 OR abuse_score>=4.0` | 0.99 | 83 total signature occurrences (67 pre-date `reasoning_trail` existing in the schema — not a bug, just older records); of the 16 with a trail, **0 had `ti_score>2.0`** — see Gap 1 |
| 6 | HIGH / alert / `<attack hypothesis name>` | `attack_score > benign_score AND attack_score>=2.0 AND num_independent_sources>=2 AND attack_score>=3.0` | 0.85 | NETWORK_INTRUSION 140, DNS_EVASION 989, CONNECTION_ABUSE 326, DNS_POLICY_BYPASS 103, DNS_ATTRIBUTION_GAP 60, DGA_BOTNET_C2 17, DATA_EXFILTRATION 3, DNS_COVERT_TUNNELING 4 |
| 7 | SUSPICIOUS / monitor / `<attack hypothesis name>` | `attack_score > benign_score AND attack_score>=2.0`, not clearing the HIGH bar above (single-source, or score in [2.0,3.0)) | 0.40 | NETWORK_INTRUSION 9810 (by far the largest category in the whole system), DNS_EVASION 3638, DNS_COVERT_TUNNELING 1467, CONNECTION_ABUSE 1256, DATA_EXFILTRATION 124, DNS_ATTRIBUTION_GAP 41, SIGNATURE_MATCHED_THREAT 18, DGA_BOTNET_C2 9, DNS_POLICY_BYPASS 1 |
| 8 | SUSPICIOUS / monitor / "Elevated Reputation Signal (Unconfirmed)" | `rep.tier==4 AND max(vt,ti,abuse)>=1.5`. tier 4 itself = `weak_signal` (any of vt/ti/abuse > 0) without clearing the tier-5 `confirmed_ioc` bar | 0.45 | 590 |
| 9 | ANOMALOUS / log / "ML Anomaly Only" | `any(e.type=="ml_anomaly" and e.value>0.90)` | 0.10 | (not separately tallied this pass — low-volume, log-only) |
| 10 | BENIGN / suppress / `<benign hypothesis name or UNKNOWN_BENIGN>` | Default — nothing above matched | 0.0 | (not written to alerts.json at all — BENIGN never publishes) |

### Attack hypothesis names (feeding rows 6-7) — `intelligence/hypotheses/engine.py`
`DNS_TUNNELING`, `NETWORK_INTRUSION`, `DGA_BOTNET_C2`, `DATA_EXFILTRATION`, `C2_BEACONING`,
`DNS_COVERT_TUNNELING`, `CONNECTION_ABUSE`, `DNS_EVASION`/`DNS_ATTRIBUTION_GAP`/`DNS_POLICY_BYPASS`
(same hypothesis class, three names by evidence subtag), `SIGNATURE_MATCHED_THREAT`. Each has
its own `required_satisfied` gate and strong/contradicting scoring — see that file directly
for the exact per-hypothesis logic; too much to duplicate here without drifting out of sync.

### Benign hypothesis names (row 10) — same file
`ADVERTISING_BURST`, `LOCAL_DEVICE_DISCOVERY`, `DEVICE_PROFILE_TELEMETRY`, or the
`UNKNOWN_BENIGN`/`DIRECT_IOC_HIT` fallbacks when no hypothesis on either side fires at all.

## Layer 2 — `AutonomousFPEngine.evaluate()` (`intelligence/fp_engine.py`)

Runs on every alert *after* Layer 1, independently of it — can suppress a CRITICAL/HIGH
verdict or confirm a low one. This is CL-AFPE, described fully in that file's own module
docstring.

| Verdict / suppress | Stage | Trigger |
|---|---|---|
| FALSE_POSITIVE / True | `TRUST_CACHE` | Target (base domain or dest IP) is in the 14-day dynamic trust cache, and Stage-1 hard-stop does NOT re-fire on this specific alert |
| CONFIRMED_THREAT / False | `TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP` | Trust-cached target, but a hard-stop signal fires anyway — re-checked every time, immunization never blindly trusted |
| CONFIRMED_THREAT / False | `STAGE_1_HARD_STOP` | Recognizes `decision["state"]=="CRITICAL"` directly (Check 0) plus its own 7 checks: ti_score>2.0, lateral movement (distinct-target gated), malicious JA3/JA4, honeypot, AbuseIPDB>=4.0, exfil payload burst, local confirmed-intel store match |
| FALSE_POSITIVE / True | `STAGE_3_COMBINED` | Weighted LightGBM(Stage 2) + FastEmbed(Stage 3) `combined >= effective_suppress_threshold` (config, per-device profile, default 0.80). Triggers `mark_false_positive()` |
| UNCERTAIN / False | `STAGE_3_COMBINED` (refused) | Combined cleared the suppress bar, but `mark_false_positive()` refused because the alert carries a hard-stop-equivalent signature — publishes normally instead of forcing a wrong suppression |
| UNCERTAIN / False | `STAGE_3_COMBINED` | `combined` in `[uncertain_threshold(0.55), suppress_threshold)` — published, flagged low-confidence |
| CONFIRMED_THREAT / False | `STAGE_3_COMBINED` | `combined < 0.55` — published at full severity, sigma tuned up |

## Layer 3 — `ollama_soc.py` batch classification (offline, 4-hourly)

`classification: benign|malicious`, `recommended_action: suppress|block|none`, gated by
`DeterministicValidator` (rejects "benign" against a confirmed-IOC evidence reconstruction;
rejects "malicious" if the model's own reasoning cites the exact prior risk score it was
never shown — circular-reasoning guard).
- `benign + suppress + valid + not multi-device-spread + not already-actioned` → autonomous
  `mark_false_positive(source="llm_validated")`
- `malicious + valid + not already-actioned` → (since 2026-08-27) `record_confirmed_threat()`
  + sigma TUNE_UP + a batched Telegram digest, instead of sitting inert in a report

## Audit findings from this pass (2026-08-27)

**"Confirmed Malicious IOC" signature/trail count mismatch (83 vs 16) — investigated, NOT a
bug.** 67 of the 83 have no `reasoning_trail` field at all (older alerts, predate that field
being added to the schema). Of the 16 that do have a trail, all 16 agree with the signature.
No inconsistency once accounted for.

**"Layer-2 ARP Spoofing Detected", 191 occurrences, 100% on `hostname="unknown"` devices —
investigated, HISTORICAL, already resolved.** All 3 device_ids behind these are
`192.168.1.2`/`192.168.1.3` (mesh Wi-Fi repeaters, explicitly `safe_ips`-listed) plus one
minor device. Every single occurrence falls between 2026-08-19 and 2026-08-22 — **zero
since**, consistent with the `is_safe` gate on this specific hard-stop (documented in
`pipeline.py`'s own comments as a fix for exactly this repeater false-positive shape) having
been deployed and holding since Aug 22. Not a live concern, but a good example of why "high
volume in history" needs a recency check before being treated as an open problem.

**"Geofencing Policy Violation", 20 occurrences, 19 on device `paperless` — REAL BUG FOUND
AND FIXED.** Pulled a raw record: `network_context.destination_ip` showed `192.168.1.1` —
the router's own private LAN address, which is geographically meaningless and which GeoIP
(confirmed via direct query against the box's own `GeoLite2-City.mmdb`) correctly returns
`AddressNotFoundError` for. The real trigger was never this IP; `geofencing_violation`
Evidence (`pipeline.py`, the `dest_ips` loop under "Feature 3: Geofencing Policy
Enforcement") never carried a `.domain` attribute recording which destination actually
tripped it — the exact same attribution gap already fixed for
`honeypot_access`/`arp_spoofing`/`zeek_lateral_scan`/`CONNECTION_ABUSE`/`DGA_BOTNET_C2`, just
never extended to geofencing. The alert's "Contacted" line was falling back to whatever this
device connected to most recently, which is how a private IP ended up displayed for a
"connected to a blocklisted country" verdict. **Fixed**: `domain=d_ip` added to the evidence,
plus a new `primary_sig_base == "Geofencing Policy Violation"` attribution branch consuming
it, mirroring the honeypot pattern exactly. Live, not shadow — this is a display-correctness
fix, not a change to when the hard-stop fires.

**Known, already-tracked issues (see `DECISION_LOGIC_DEPENDENCY_MAP.md` for full detail,
not repeated here):**
- Gap 1: tier-5 doesn't distinguish `ti_score` (real feed) from `vt`/`abuse` (aggregate) — shadow-live, 2 real divergences logged and confirmed correct as of this writing
- Gap 2: `NetworkIntrusionHypothesis` conflates `zeek_notice` with real JA3/JA4 — shadow-live, no divergence observed yet
- Gap 3: hard-stop evidence staleness (honeypot re-firing on stale `EvidenceStore` presence) — shadow-live

**Not yet audited this pass** (flagged for a future pass, not because anything's known wrong):
`ml_anomaly`/ANOMALOUS volume, the exact per-hypothesis `required_satisfied` conditions in
`hypotheses/engine.py` for `DNS_TUNNELING`/`C2_BEACONING`/`DATA_EXFILTRATION` (lower volume,
lower audit priority given SUSPICIOUS/monitor-only severity for most of them), and fp_engine's
Layer 2 stage transitions against real `combined` score distributions.
