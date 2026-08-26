# Decision-Logic Dependency Map

Living reference for the alert-classification path (`ReputationClassifier` →
`HypothesisEngine` → `DecisionEngine` → `pipeline.py`'s alert/containment
call sites). Built while tracking down a third-party review's "Confirmed
Malicious IOC" critique; extended incrementally as further work touches
this path — **update this file in the same change that touches any
function listed below**, don't let it go stale.

Each function entry lists every parameter: where it's **generated**, every
place it's **transformed** in transit, and every place it's **consumed**
downstream — not just "what calls what."

## Status

| Item | State | Notes |
|---|---|---|
| Gap 1 — reputation tier-5 privilege split (`verified_ioc`) | **Shadow-live** (2026-08-26) | `verified_ioc` field + shadow computation implemented; live `state`/`action`/`explanation` UNCHANGED — only extra `shadow_*` fields + `state/shadow_decisions.jsonl` log added |
| Gap 2 — `has_malicious_tls`/`zeek_notice` conflation | **Shadow-live** (2026-08-26) | `NetworkIntrusionHypothesis.evaluate_shadow()` (`hypotheses/engine.py`) implements the split; `HypothesisEngine.evaluate_all()` returns an extra `shadow_attack` key (name/score using the fixed logic) alongside the unchanged `attack`/`benign` keys; `decision_engine.py`'s shadow block (below) consumes it. Cannot be backtested from `alerts.json` history — see limitation above; only live-observable via `state/shadow_decisions.jsonl` going forward. |
| `scripts/shadow_backtest.py` (Phase A, Gap 1 only) | Built, run 3x, results below | Re-run after Gap 2 wiring landed — numbers unchanged (5/75/0), as expected: the standalone backtest re-derives from stored `alerts.json` fields independently of the live code, so it wasn't and couldn't be affected by the Gap 2 change |
| Live shadow logging (Phase B, Gap 1 + Gap 2 composed) | **Implemented** (2026-08-26) | `decision_engine.py:evaluate()`'s shadow block now composes BOTH gaps in one pass (hard-stops reused as-is; tier==5 branch uses `rep.verified_ioc` + `shadow_attack_score > benign_score`; the hypothesis branch uses `shadow_attack_score`/`shadow_attack_name` in place of the live ones) — mirrors the real branch structure fresh rather than reusing/duplicating the live branch code, so there's exactly one "old" (unedited, still-shipped) and one "new" (fixed) implementation, never two drifting copies of the same logic. `pipeline.py:_log_shadow_divergence()` appends to `state/shadow_decisions.jsonl` whenever `shadow_changed` is True (state OR explanation differs) |
| Targeted test subset (9 files) | **All 9 PASS, 0 regressions, verified twice** (2026-08-26) — once after Gap 1, again after Gap 2 | Run directly as standalone scripts (`.venv/Scripts/python.exe tests/test_phaseN.py` from repo root) — these are NOT pytest-collected despite the filename convention (no `def test_*`/`if __name__`); `pytest` reports "no tests ran" for them, which is expected, not a failure. Must use the project's `.venv` (system `python3` lacks `PyYAML` and other deps — `ModuleNotFoundError: No module named 'yaml'`). First cold run of a file over the network share can take >2 min (model-loading fixtures + import latency) — this is normal, not a hang; confirmed by re-running in isolation with a longer window. `test_phase38` explicitly covers the tier-5/AbuseIPDB boundary Gap 1 reads (ti=3.5 → CRITICAL; abuse=3.78 → stays SUSPICIOUS) — unaffected both times, confirming neither shadow addition touched the live path. |
| Evidence-taxonomy module (`evidence_taxonomy.py`) | Not started | Deferred until after all three gaps' live-flip decision, per plan |
| Gap 3 — hard-stop evidence staleness (`has_honeypot` etc. firing on stale `EvidenceStore` presence, not a fresh cycle) | **Shadow-live** (2026-08-27) | Root cause confirmed via live SSH investigation (see "Gap 3 root cause" below), not inferred. `decision_engine.py` now takes an optional `features` param and computes `fresh_honeypot` (via `features["zeek_honeypot_hits"]`, the same raw signal `pipeline.py` itself gates evidence-creation on) and time-boxed `fresh_arp_spoof`/`fresh_geofence`/`fresh_confirmed_exploit` (via `_HARD_STOP_FRESHNESS_SECONDS = 120` against `e.timestamp` — diagnostic proxy, not yet live-confirmed the way honeypot is). `scripts/shadow_backtest.py` extended with `run_gap3_honeypot_backtest()`. 9/9 targeted tests pass. |
| A few days of live `state/shadow_decisions.jsonl` accumulation | **In progress** — box restarted 2026-08-26 12:58:52 CEST with commit `3dcac19` confirmed as HEAD (verified via SSH, not just the Unison-synced NAS mirror) | Nothing further to build until this has accumulated data |
| `scripts/shadow_watcher.py` (Telegram notification on first divergence) | **Deployed and running** (2026-08-26) | Fires Telegram the moment `state/shadow_decisions.jsonl` gets a new line; runs every 5 min via `scripts/scheduler.py`. Committed locally as `d7f18ad` (NOT pushed to `origin` yet) and deployed directly to the box via `scp` (not `git pull`) so it's live without waiting on a push/pull round-trip — **the box's git working tree is now ahead of its own `git log` for `config.yaml`/`shadow_watcher.py`** until someone pushes from the NAS checkout and pulls on the box to reconcile. Manually dry-run on the box against real production state (`job_health.json` confirms a clean run) before relying on the scheduler to pick it up. |

## Phase A backtest results (`scripts/shadow_backtest.py` against `state/alerts.json`, 80 historical "Confirmed Malicious IOC" alerts, 2026-08-26)

**First pass** (corroboration = `num_independent_sources >= 1` alone): 67 real downgrades, 13 label-only.

**Refined pass**, after finding a live counter-example (see below): corroboration also requires `attack_score > benign_score` (both already computed at the top of `decision_engine.evaluate()`, just never consulted by the tier==5 branch). Result: **75 real downgrades (CRITICAL→HIGH), 5 label-only (stay CRITICAL, relabeled), 0 unchanged** (zero of the 80 had a genuine `ti_score > 2.0` curated-feed match — every single one relied on VT/AbuseIPDB aggregate scores alone).

**The counter-example that drove the refinement** — a live `family_pc_fritz_box` alert (`35.186.224.24`, Google LLC, AbuseIPDB=4.0, VT=0, TI=0) had this reasoning trail:
```
Hypotheses: attack='NETWORK_INTRUSION' (score=2.0) vs benign='LOCAL_DEVICE_DISCOVERY' (score=2.5) — 2 independent evidence source(s)
Verdict: CRITICAL / block — Confirmed Malicious IOC (confidence=0.99)
```
The **benign** hypothesis outscored the **attack** hypothesis (2.5 > 2.0), yet the alert still said "Confirmed Malicious IOC" — because the tier-5 branch is checked *before* the attack-vs-benign comparison and short-circuits it entirely. "Corroborating evidence exists" (`num_independent_sources >= 1`) is not the same claim as "the corroborating evidence supports an attack conclusion" — this alert had 2 independent sources, but they favored innocence, not guilt.

**Honest caveats on the backtest data (found while checking, not assumed):**
- 67 of the 75 downgrades are a single device (`paperless`, id `52a469cfd274`) on a single day (2026-08-17), all against Telegram's own server IP `149.154.166.110` — the exact case `classifier.py`'s own PHASE 8 comment already documents. These pre-date/coincide with the `abuse_score >= 4.0` threshold fix already shipped in the current code, so this specific historical failure mode is likely **already moot** under today's live thresholds — it validates that this *class* of bug is real, not that Gap 1 changes much going forward for this device.
- The other 8 downgrades (7 `family_pc_fritz_box` + 1 `galaxy_note9_fritz_box`) are current and ongoing (2026-08-22 through 2026-08-26) — `family_pc_fritz_box` alone has hit this exact `Confirmed Malicious IOC`/Google-Cloud-IP pattern **at least 7 times over 4 days**, which the original tarpit evidently didn't resolve (still recurring as of the morning of 2026-08-26). This is the more relevant evidence for what Gap 1 changes *today*.
- The `later_corrected_within_14d` check is a loose per-device proxy (any correction on the same device within 14 days, not proof it was correcting this exact alert) — treat "75/75 correlate with a correction" as suggestive, not proof, especially for `family_pc_fritz_box`, which is a generally high-alert-volume device likely to show *some* correction in any 14-day window regardless.
- Zero downgrades correlated with a device that has other confirmed-threat history (`confirmed_threat_counts.json`) — nothing in this backtest looks like it would have downgraded a genuinely dangerous device.

**Next step for Gap 2:** unlike Gap 1 (a single extra branch after the hypothesis competition already runs), Gap 2 lives *inside* `NetworkIntrusionHypothesis.evaluate()`, which directly feeds `attack_score` — splitting `has_malicious_tls`/`zeek_notice` there changes the hypothesis's own score, not just a downstream branch. To shadow it without touching live behavior, it needs a second, parallel `HypothesisEngine` instance running the patched hypothesis alongside the original, logged the same way. Not yet implemented — next concrete task.

## Known limitation found while tracing (important — governs what's backtestable)

`pipeline.py:1156/1194/1283` builds the alert's `factors` field as
`[{"name": decision["explanation"], "score": risk}]` — **one entry, the
final decision's own explanation string**, not a list of which raw
`Evidence.type` values fired. `reasoning_trail` (`decision.get("reasoning_trail")`,
stored at `pipeline.py:1516`) is closer — it's `decision_engine.py`'s own
`trail` list and includes the hard-stop-checks line and the
`"Hypotheses: attack='X' (score=Y) vs benign='Z' (score=W) — N independent
evidence source(s)"` line — but neither retains the raw evidence-type
breakdown `NetworkIntrusionHypothesis` needs (specifically, whether
`malicious_ja3`/`malicious_ja4` vs. `zeek_notice` was the thing that set
`has_malicious_tls=True`). **Conclusion: Gap 1 (reputation tier) is fully
reconstructable from historical `alerts.json`; Gap 2 (evidence-type
conflation inside `NetworkIntrusionHypothesis`) is not — it can only be
validated via live shadow logging going forward, not backtested.**

---

## `ReputationClassifier.classify()` — `intelligence/reputation/classifier.py:64`

```python
def classify(self, domain, vt_score=0.0, afpe_score=0.0, is_new=False,
             ti_score=0.0, abuse_score=0.0, asn_owner="Unknown") -> ReputationVector
```

| Param | Generated at | Transformed | Consumed by |
|---|---|---|---|
| `domain` | `pipeline.py:1073` passes `reputation_target` — itself set at `pipeline.py:782` (`= top_domain`), then overwritten at `:791`/`:800` if `ti_engine.lookup_domain()`/`lookup_ip()` found a higher-risk target, and at `:849`/`:867` if honeypot/VT found a higher one still | `.lower().strip(".")` inside `classify()` | Tier-0/1/2 suffix matching (`_suffix_or_domain_match`) |
| `ti_score` | `pipeline.py:804` `features["ti_risk"] = ti_risk`, computed `:784-802` from `self.ti_engine.lookup_domain()`/`lookup_ip()` — a **real curated-feed match** (Feodo/ThreatFox/OTX via `intelligence/threat_intel.py:229,246`), `confidence * 4.0` | none before reaching `classify()` | `confirmed_ioc = ... or ti_score > 2.0 ...` (`classifier.py:103`) — **this is the only one of the three that should ever grant zero-corroboration privilege (Gap 1 fix target)** |
| `vt_score` | `pipeline.py:868` `features["vt_risk"] = vt_risk`, computed `:855-867` via `self.virustotal.risk_contribution()` (`threat_intel.py:940-946`, VT multi-vendor detection ratio) | none | same `confirmed_ioc` check — **aggregate signal, not a feed match; part of the gap** |
| `abuse_score` | `pipeline.py:841` `features["abuseipdb_risk"] = abuse_risk`, computed `:818-841` (AbuseIPDB crowd-sourced score, capped `>=4.0` bar per the PHASE 8 fix in `classifier.py:92-102`) | none | same `confirmed_ioc` check — **crowd-sourced, weakest of the three; part of the gap** |
| `asn_owner` | `pipeline.py:1073` argument — traced no further yet (not needed for Gap 1/2) | — | `_SAFE_ASN_OWNER_KEYWORDS` tier-2 floor check |

**Returns** `ReputationVector(domain, tier, asn_owner, vt_detection_ratio, ti_risk, abuse_risk, cl_afpe_similarity, first_seen, source_confidence)` → consumed by `DecisionEngine.evaluate()` as `rep`, and by `pipeline.py`'s own reasoning-trail text (`rep_vt`/`rep_ti`/`rep_abuse` read back via `getattr` at `decision_engine.py:74-76`).

**Gap 1 fix point:** add `verified_ioc: bool` to `ReputationVector`, set `True` only when `ti_score > 2.0`, inside `classify()`'s `if tier == 3: if confirmed_ioc: tier = 5` branch (`classifier.py:113-115`).

---

## `HypothesisEngine.evaluate_all()` → `NetworkIntrusionHypothesis.evaluate()` — `intelligence/hypotheses/engine.py:64-104, 524-547`

| Param | Generated at | Transformed | Consumed by |
|---|---|---|---|
| `ev_store` | `pipeline.py`'s `self.evidence_store` (`intelligence/hypotheses/evidence.py`'s `EvidenceStore`), built up across the whole detection cycle via `.add(Evidence(...))` calls scattered through `pipeline.py` (honeypot at `:995`, lateral scan at `:1011`, local device discovery, etc.) | Read back per-device via `EvidenceStore.get_for_device()` (`evidence.py:84-100`), which **applies freshness decay** (10 min TTL default, 24h for `independence_group=="reputation"`) before handing it to any hypothesis | Every `Hypothesis.evaluate()` subclass; `DecisionEngine.evaluate()`'s own `num_independent_sources` count (`decision_engine.py:62-64`) |
| `rep` (`ReputationVector`) | Output of `ReputationClassifier.classify()` above | none | `contradicting_score` checks in every hypothesis (`rep_vector.tier in (1,2)`) |

Inside `NetworkIntrusionHypothesis.evaluate()` (`engine.py:68-104`):
```python
has_lateral_scan = any(e.type == "zeek_lateral_scan" and e.value > 0 for e in ev_store)
has_malicious_tls = any(e.type in ("malicious_ja3", "malicious_ja4", "zeek_notice") for e in ev_store)  # ← Gap 2
has_mac_flip = any(e.type == "arp_spoof_pending" for e in ev_store)
```
- `zeek_lateral_scan` evidence is **only ever created** at `pipeline.py:1006-1011` when `zeek_lateral_unique_targets >= lateral_movement_unique_targets_threshold` (config, default 2) — already fixed, not part of this gap.
- `malicious_ja3`/`malicious_ja4` are real Zeek TLS-fingerprint-database matches.
- `zeek_notice` is **any** Zeek `weird.log` policy notice — created generically wherever `pipeline.py` adds `Evidence(type="zeek_notice", ...)`; most weird types are protocol edge-cases, not malware indicators. Folding it into `has_malicious_tls` is Gap 2.

**Gap 2 fix point:** split into `has_malicious_tls` (ja3/ja4 only) and a separate `has_notable_notice` (zeek_notice), weight the latter lower in `strong_score` (`engine.py:87-88`) — see the fix sketch in the prior turn.

---

## Gap 3 root cause — hard-stop evidence staleness (found 2026-08-27, via live SSH investigation)

`EvidenceStore.get_for_device()` (`evidence.py:84-100`) keeps any evidence "active" for up to
its TTL (600s default) after creation, decaying `freshness` but never removing it early.
`decision_engine.py`'s `has_honeypot = any(e.type == "honeypot_access" for e in ev_store)`
(and the equivalent `has_arp_spoof`/`has_geofence`/`has_confirmed_exploit` checks) only test
**presence**, never `e.freshness` or `e.timestamp`. `pipeline.py:984` only creates a *new*
`honeypot_access` Evidence on the cycle where `features["zeek_honeypot_hits"] > 0` — every
cycle after that, for up to 10 more minutes, the *same* evidence object is still sitting in
`ev_store`, so the identical CRITICAL "Internal Honeypot Accessed" verdict re-fires on every
subsequent cycle, each with that cycle's own unrelated "most notable connection" in the
display line (which is why the Telegram alerts showed mDNS multicast addresses instead of the
honeypot's own IP).

**Confirmed live, not inferred**: pulled `home-router`'s "Internal Honeypot Accessed" alerts
from `state/alerts.json` on the box directly (not the Unison-mirrored NAS copy) — several had
`features["zeek_honeypot_hits"] == 0` in their own persisted snapshot, i.e. the alert's own
recorded evidence contradicts the verdict it produced. `scripts/shadow_backtest.py`'s
`run_gap3_honeypot_backtest()` quantifies this across all history: of every
"Internal Honeypot Accessed" alert ever, roughly a third have `zeek_honeypot_hits == 0`
(stale-echo) vs. a genuine fresh trigger — see the script's live output for current counts.

**Separately** (not a code bug — a real, or at least undiagnosed, deployment fact): several of
`home-router`'s honeypot hits ARE genuinely fresh (`zeek_honeypot_hits > 0`), meaning the
router itself periodically sends real, non-excluded-port traffic to the honeypot's IP —
plausibly Fritzbox's own "Home Network" device-map/UPnP/mDNS-repeater behavior treating the
honeypot's macvlan IP as a normal known host. This is a policy question (should a
`safe_ips`-listed device's honeypot hits be exempted the way its other hard-stops already
are?), not something Gap 3's freshness fix addresses — flagged to the user, decision pending.

Cowrie itself (`docker inspect soc_honeypot`) only exposes `2222/tcp` (SSH) and `2223/tcp`
(Telnet) — confirmed empirically from a separate LAN host that `192.168.1.200:53` gives no
response at all. The `family_pc_fritz_box` "Internal Honeypot Accessed" tarpit that prompted this
whole investigation was a single 41-byte UDP packet to port 53 — real evidence
(`zeek_honeypot_hits: 1`, not a stale echo), but to a service that structurally cannot have
answered it, alongside that same device's alert history being otherwise saturated with
ordinary Windows WSD/DLNA/Spotify-Connect discovery traffic. Not proof of non-infection, but
strong circumstantial evidence against it.

## `DecisionEngine.evaluate()` — `core/decision_engine.py:26-224`

Already traced in full above (`hyp_results`, `attack_score`/`benign_score`, `num_independent_sources`, `has_honeypot`/`has_arp_spoof`/`has_geofence`/`has_confirmed_exploit`, the `tier==5` branch at `:168-173`). Returns the dict consumed at `pipeline.py:1134` as `decision`, which then drives:
- `alert_payload["signature"|"factors"|"reasoning_trail"|...]` (`pipeline.py:1500-1527`)
- `self.ips_mitigator.mitigate(..., decision_state=containment_decision_state, ...)` (`pipeline.py:1690-1700`) → real Pi-hole block / router isolation / Layer-2 tarpit (`mitigation/ips.py`)
- Telegram WHY block (`pipeline.py:2035-2037`)

**Gap 1 fix point:** `decision_engine.py:168-173`, branch on `rep.verified_ioc` as sketched two turns ago.
