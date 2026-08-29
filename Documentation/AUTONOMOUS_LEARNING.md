# 🧠 Home-IDS: Autonomous Learning, Self-Healing & Scheduled Jobs

## What this document is

Home-IDS doesn't just detect and block — it continuously corrects itself, in several
genuinely distinct ways that used to be scattered across code comments with no single
place explaining how they fit together. This document is that place: every autonomous
feedback loop, every scheduled background job, and real examples of the Telegram alerts
each one produces.

If you want the full system architecture (the three "brains," the decision pipeline,
every subsystem), start with [`ENGINEERING_MANUAL.md`](ENGINEERING_MANUAL.md) — this
doc assumes you already know roughly what CL-AFPE, Zeek, and Pi-hole are, and goes deep
on **how the system gets smarter over time**, not what it's made of.

---

## The short version

Every autonomous loop below follows the same shape: **something happens → the system
records a correction → that correction changes future behavior → you get a Telegram
notification either way, with an option to undo it.** None of these loops can silently
make the system less safe without leaving a visible trail — every one either has its own
revoke button, or feeds a threshold that only ever gets *harder* to slip past when a real
threat is confirmed, never easier.

| Loop | What it learns | Where it's stored | How you'd notice |
|---|---|---|---|
| [Sigma-shift](#1-sigma-shift-per-device-sensitivity-tuning) | "This device needs more/less benefit of the doubt" | `state/fp_sigma_shifts.json` | Sigma-shift direction panel on Device Deep Dive |
| [Trust cache](#2-trust-cache--domain-immunization) | "This domain is safe, network-wide" | `state/fp_trust_cache.json` | 🔔 Auto-action: immunized alert |
| [Per-device thresholds](#3-per-device-learned-thresholds-autotune) | "This device's normal traffic volume is different from the fleet average" | `state/device_fp_profiles.json` | Autonomous Behavior dashboard, per-device threshold tables |
| [Behavioral familiarity](#4-per-device-behavioral-familiarity-baseline) | "This exact device has talked to this exact port/ASN/domain before, safely" | `state/device_fp_profiles.json` (`_baseline` key) | `home_ids_baseline_familiarity_entries_total` metric |
| [Transfer learning](#5-transfer-learning-cold-start-seeding) | "A brand-new device probably behaves like its peers" | In-memory, applied once at device creation | `🌱 [TRANSFER LEARNING]` log line at boot |
| [Retroactive identity merge](#6-retroactive-identity-merge-self-healing-device-identity) | "These 3 fragmented device_ids are actually one physical device" | `state/ids_state.json` | `🔗 IDENTITY MERGE` log line, `home_ids_identity_merges_total` |
| [Local confirmed-intel](#7-local-confirmed-intel-cross-device-network-effect) | "This IP/domain is malicious, and now every device benefits from knowing that" | `state/local_confirmed_intel.json` | 🌐 Retroactive Local-Intel Cross-Reference alert |
| [Ollama (Brain 3)](#8-ollama-brain-3-llm-validated-closed-loop) | Independent LLM re-analysis of alerts, feeding back into the same trust cache / sigma-shift / confirmed-intel loops above | `state/ollama_analysis_cache.json` | 🤖 Ollama SOC run digest |

---

## 1. Sigma-shift: per-device sensitivity tuning

**File:** `src/intelligence/fp_engine.py`, `AutonomousFPEngine._apply_sigma_shift()`

Every device has a personal "how suspicious does something need to be before I alert on
it" dial, stored as a σ (sigma) offset from the global baseline. It moves in exactly two
directions:

- **Widen (`TUNE_DOWN`, +0.25σ, capped at +2.0σ):** fires whenever a false positive is
  confirmed for this device — by a human tapping "Mark False Positive," by CL-AFPE's own
  autonomous Stage 2/3 suppression, or by Ollama's LLM-validated benign verdict. The
  device becomes progressively harder to alert on for things that keep turning out to be
  nothing.
- **Tighten (`TUNE_UP`, -0.50σ, floored at -1.5σ):** fires whenever a threat is
  *confirmed* for this device — a Stage 1 hard-stop, a HIGH/CRITICAL decision, a
  retro-hunt local-intel match, or Ollama's LLM-validated malicious verdict. The device
  becomes easier to alert on going forward. Tightening moves twice as fast as widening
  (-0.50σ vs +0.25σ) and the floor is tighter than the ceiling is loose — a device that's
  shown real compromise indicators doesn't get the benefit of the doubt back quickly.

This is genuinely bidirectional and reversible per-device — a device that's been noisy
for months and then shows a real threat gets its sensitivity yanked back immediately, not
gradually re-earned.

---

## 2. Trust cache — domain immunization

**File:** `src/intelligence/fp_engine.py`, `_immunize_domain()` / `revoke_immunization()`

When a domain (or, for DNS_EVASION-style alerts, a raw destination IP) is confirmed as a
false positive, it's added to a 14-day trust cache — network-wide, not per-device. Any
device querying that same domain stops alerting on it for the duration of the TTL.

**Real example** (this alert type prompted the enrichment work in v12.4.0 — see
[CHANGELOG.md](CHANGELOG.md)):

> 🔔 **Auto-action:** immunized `i-scmp.com` for *family_pc_fritz_box* (192.168.1.12)
> This stopped future alerts for this domain because our false-positive check was 81%
> confident it's benign.
> It was originally flagged by: DNS_EVASION (risk 4.5) — contacted `104.20.2.31`
> _(Cloudflare, Inc., United States)_:443 (HTTPS)
> If this was actually a real threat, tap Revoke within 24h.
>
> 🔧 *Technical detail (optional)*
> - LightGBM FP_MODEL_SCORE=0.812 (Stage 2, uncalibrated classifier output)
> - FastEmbed similarity (contextual evidence, not a verdict)=0.79 → closest known
>   pattern: 'news/media CDN' (Stage 3)
> - Combined confidence=0.812 >= 0.80 (suppress threshold)
> - Calibrated confidence: not available
>
> *[↩️ Revoke (this was a real threat)]*

Tapping **Revoke** within the window pulls the domain back out of the trust cache
immediately, marks the device as having a validated threat, and increments its
confirmed-threat counter — but note it does **not** automatically re-block the domain in
Pi-hole or tighten sigma; if you revoke, you're expected to also decide whether to
manually re-block.

---

## 3. Per-device learned thresholds (autotune)

**Files:** `src/scripts/train_fp_classifier.py` (the `autotune` cron job, daily 3am) +
`src/intelligence/fp_engine.py`'s reactive correction path (fires immediately on a
Telegram "Mark False Positive" tap, doesn't wait for the daily job)

Four numeric thresholds are learned per-device instead of using one global number for
every device on the network:

| Threshold | What it gates |
|---|---|
| `fp_combined_suppress_threshold` (per-device override) | How confident CL-AFPE needs to be before autonomously suppressing an alert for this device |
| `arp_sweep_unique_targets_threshold` | How many distinct hosts a device can ARP-probe before it's flagged as sweeping |
| `conn_abuse_unique_ip_threshold` | How many distinct rejected-connection targets before CONNECTION_ABUSE fires |
| `long_conn_duration_threshold` | How long a connection can stay open before it's flagged as anomalous |

A device only gets its own calibrated value once it has enough evidence (≥3 pooled
corrections for a device-level threshold, ≥5 for the global one) — devices without
enough history still use the global default. Calibration is one-directional and safe:
thresholds only ever get corrected in the direction the evidence points, and a global
threshold never auto-lowers below a 0.60 floor.

Where to see it live: the Autonomous Behavior dashboard's per-device threshold tables, or
`home_ids_autotune_device_threshold_effective` / `_arp_sweep_threshold_effective` /
`_conn_abuse_threshold_effective` / `_long_conn_threshold_effective` in Prometheus.

---

## 4. Per-device behavioral-familiarity baseline

**File:** `src/intelligence/fp_engine.py`, `record_device_baseline_observation()` /
`get_baseline_familiarity()`

Distinct from the numeric thresholds above — this learns **what** a device normally
does, not just how sensitive to be. Every cycle, for BENIGN/ANOMALOUS-decision traffic
only (never for anything that reached CONFIRMED_THREAT — a compromised device can't
launder its own attack traffic into looking "familiar"), the device's destination port,
the IP owner's ASN, and the base domain it talked to are recorded. A
{device, destination} pair that recurs 5+ times without ever becoming a confirmed threat
becomes progressively more "known-normal" for that one device — fully generic and
self-updating, no hardcoded vendor list, adapts to whatever *your* network's devices
actually do.

This familiarity score is used as damping evidence (it makes a borderline alert *less*
likely to fire), never as an outright verdict on its own.

Where to see it: `home_ids_baseline_familiarity_entries_total` (per device) shows how
large each device's learned fingerprint has grown.

---

## 5. Transfer learning: cold-start seeding

**File:** `src/core/state_guard.py`, `get_or_create()`

A brand-new device doesn't start from a completely blank baseline. If at least one
existing device of the same `device_type` (smart_tv, phone, iot, router, laptop, ...)
already has ≥10 samples of its own hourly rate/entropy/unique-domain baseline, the new
device's starting baselines are seeded from the average of those peers — instead of
needing to independently learn "what's normal" from zero, alone, for potentially days.

**Real example** (from a production boot log):

```
🌱 [TRANSFER LEARNING] Seeding initial baselines for new home-router (router)
    from 3 peer router profiles
```

This fires once, at device creation — it's not a continuous loop, just a better starting
point than cold-starting alone. Tracked via `home_ids_transfer_learning_seeds_total`
(labeled by `device_type`, since it's a type-level event, not tied to one specific new
device).

---

## 6. Retroactive identity merge: self-healing device identity

**File:** `src/core/state_guard.py`, `merge_into_canonical()` — full detail in
[`DEVICE_IDENTITY_LIFECYCLE.md`](DEVICE_IDENTITY_LIFECYCLE.md)

A dual/triple-stack device (IPv4 + IPv6 link-local + IPv6 ULA, all common for a single
physical device) can get cold-started under separate device_ids before its MAC becomes
known on all three addresses — MAC-first identity anchoring prevents *new* fragmentation
going forward but can't undo one already minted. This loop retroactively detects that
situation and merges the fragments back into one canonical identity the moment a shared
MAC is observed, discarding the orphan's sparse history rather than blending it (the
orphan is typically the cold-started, evidence-poor fragment; the canonical identity is
the one with real history).

**Real example** (from a production log, immediately after the fix shipped):

```
🔗 IDENTITY MERGE (retroactive): orphan 08bdb9a778c2 discarded, 1 address(es)
    redirected to canonical 3028d18cbd7c (home-router)
```

This is a genuine, frequent self-healing event, not a rare edge case — a live scan
before this fix found 24 fragmented groups across 60 of 88 tracked devices on one real
deployment. Tracked via `home_ids_identity_merges_total`.

---

## 7. Local confirmed-intel: cross-device network effect

**Files:** `src/intelligence/local_intel.py` (the store) + `src/scripts/retro_hunter.py`
(the retroactive cross-reference, daily 2am — see [job list](#every-scheduled-job) below)

When any device gets a hard-confirmed threat (Stage 1 hard-stop, a HIGH/CRITICAL
decision, or an Ollama-validated malicious verdict), the matched IP/domain is recorded in
a shared, network-wide store. From that moment on, **any other device** touching that
same IOC gets an instant hard-stop — it doesn't need to independently accumulate enough
evidence on its own first. One device's confirmed compromise immediately protects every
other device on the network.

`retro_hunter.py`'s nightly run additionally rescans the **past 14 days** of history
against this store — catching "device B also touched this IOC three days ago, but wasn't
over its own detection threshold at the time" using intel the network only just learned.

**Real example:**

> 🌐 **Retroactive Local-Intel Cross-Reference: 1 match(es)**
> Devices that touched a since-confirmed-malicious IP/domain in the past 14d:
>
> • `192.168.1.28` → ip `157.240.223.61` _(Facebook, Inc.)_
>   Touched 2026-08-24 09:15 | confirmed 5x since 2026-08-22 (a hard-stop match against
>   known-bad intel); also confirmed by: ec840afaafa7
>   → Sensitivity tightened for this device (no block/isolation — informational + tuning
>   only)

Every match both re-confirms the shared store entry (so a *third* device later gets an
even faster hard-stop) and tightens sigma for the newly-implicated device — this is a
genuine autonomous action, not just a notification, even though nothing gets blocked as
a direct result of the historical match itself.

> **Correction (2026-08-29):** the real example above (`157.240.223.61`, Facebook's own
> CDN) turned out to illustrate a bug, not a genuine threat — a write guard meant to
> stop major cloud/CDN IPs from ever entering this store (`_is_ip_protected_from_
> confirmed_intel()`) had a keyword-list gap that let Apple and Facebook IPs through.
> Fixed, and a one-time cleanup removed 284 already-poisoned entries across essentially
> every major provider (AWS, Google, Microsoft, Cloudflare, Akamai, Alibaba, Apple,
> Facebook, Netflix, and others) — this exact example among them. See
> `DECISION_LOGIC_DEPENDENCY_MAP.md`'s "ASN/cloud-provider blind spot" row and
> `ALERT_CATEGORIZATION_CATALOG.md`'s audit-findings section for the full writeup. The
> network-effect mechanism described above is otherwise unchanged and still applies to
> genuine confirmed threats.

---

## 8. Ollama (Brain 3): LLM-validated closed loop

**File:** `src/scripts/ollama_soc.py` (every 4 hours — see [job list](#every-scheduled-job) below)

The third and most independent brain: a local LLM re-analyzes recent alerts from **raw
evidence only** — it's deliberately never shown this system's own risk score, signature
name, or prior verdict, so it has to reach its own conclusion rather than just ratifying
what already happened. A `DeterministicValidator` rejects any LLM response that
contradicts hard evidence (a circular-reasoning guard), and every alert is analyzed once
per *pattern* (device + target + signature), not once per individual occurrence — a
single noisy pattern firing 50 times in a day costs one LLM call, not 50.

A validated verdict feeds directly into the loops above:

- **Benign + suppress** → the same `mark_false_positive()` mechanism as a human's
  "Mark False Positive" tap: domain immunized into the trust cache, sigma widened, any
  existing Pi-hole block released.
- **Malicious** → the same `record_confirmed_threat()` mechanism as any other hard
  confirmation: local confirmed-intel updated (network-effect propagation), sigma
  tightened.
- **Withheld (multi-device guard):** if the *same signature* is independently firing on
  3+ distinct devices right now, autonomous suppression is deliberately withheld even on
  a confident benign verdict — a single per-alert LLM call has no visibility into a
  cross-device campaign, only the batch driver does. The withheld pattern is
  re-evaluated every run against then-current device spread, and the trend (which
  devices have joined since it was last withheld) is tracked across runs.

**Real example** (one full run digest, the new comprehensive format from v12.4.0):

> 🤖 **Ollama SOC run: 4 pattern(s) analyzed**
>
> 🛡️ immunized as false positive (sensitivity loosened): 1
> 🚨 confirmed malicious (sensitivity tightened): 1
> ⏸️ withheld (spreading across multiple devices, re-checking next run): 1
> ✅ 1 already actioned / no new action needed (see report for the full list)
>
> • `samsungsmartmonitor_fritz_box` → `firebaselogging-pa.googleapis.com` (NETWORK_INTRUSION)
>   LLM (confidence 0.93): "Standard Firebase Cloud Logging endpoint used by Android/
>   Google apps for telemetry; matches known benign vendor pattern, no evidence of data
>   exfiltration."
>   → domain immunized 14 days, sensitivity loosened for this device
>
> • `unknown` (192.168.1.26) → `187.40.44.143` _(PacketHub S.A., Brazil)_ (DATA_EXFILTRATION)
>   LLM (confidence 0.88): "Large outbound transfer over a non-standard port to a
>   residential-hosting-range IP with no legitimate service on record; pattern matches
>   known exfiltration behavior, not ordinary VPN traffic."
>   → local confirmed-intel updated (any other device touching this now hard-stops),
>   sensitivity tightened for this device
>
> • `family_pc_fritz_box` → `qwertyuiopasdfghjklzxcvbnm-*.ru` (DGA_BOTNET_C2)
>   withheld 4th time — spread 3→3→4→5 devices since 2026-08-24 09:1X (newly joined:
>   applewatch_fritz_box)

---

## Every scheduled job

`scripts/scheduler.py` polls `config.yaml`'s `scheduled_jobs` section every 60 seconds
and launches each enabled job as a subprocess on its own cron schedule. There are 5 jobs
total — nothing else runs on a schedule.

| Job | Cron | Script | What it does |
|---|---|---|---|
| `autotune` | `0 3 * * *` (3am daily) | `train_fp_classifier.py` | Retrains the LightGBM/ONNX false-positive classifier from full alert+correction history; calibrates global and per-device suppress thresholds (§3 above). Runs alongside an independent, roughly-weekly in-process retrain thread inside `fp_engine.py` itself. |
| `ollama_soc` | `30 */4 * * *` (every 4h) | `ollama_soc.py` | Brain 3 batch LLM triage (§8 above) — sends this run's digest whether or not anything new happened. |
| `retro_hunter` | `0 2 * * *` (2am daily) | `retro_hunter.py` | Two independent passes: rescans historical DNS traffic against freshly refreshed external threat-intel feeds (URLHaus/FeodoTracker/ThreatFox/OTX), and cross-references history against the local confirmed-intel store (§7 above). |
| `top_domains_report` | `0 6 * * *` (6am daily) | `top_domains_report.py` | Purely observational — a per-device "top domains contacted" digest. Never blocks or unblocks anything, no feedback loop. |
| `shadow_watcher` | `*/5 * * * *` (every 5 min) | `shadow_watcher.py` | **Temporary** — notifies the moment the shadow-mode evidence-taxonomy evaluation (see [`DECISION_LOGIC_DEPENDENCY_MAP.md`](DECISION_LOGIC_DEPENDENCY_MAP.md)) logs a new divergence. Gap 1 (below) flipped live 2026-08-29, so its divergence type no longer fires; still running for Gaps 2/3, which remain shadow-only. Removed once all three are flipped live or abandoned. |

**Real example** (shadow_watcher, an actual production alert — **historical**: this
specific divergence type is the one that got Gap 1 flipped live on 2026-08-29; live and
shadow now agree on this exact case, kept here as the concrete example of what the fix
addressed):

> 🔬 **Shadow-Mode: 1 new divergence(s)**
> Live verdict vs. the proposed evidence-taxonomy fix
> ([`DECISION_LOGIC_DEPENDENCY_MAP.md`](DECISION_LOGIC_DEPENDENCY_MAP.md)):
>
> • family_pc_fritz_box (192.168.1.12) — live: CRITICAL / Confirmed Malicious IOC →
>   shadow: SUSPICIOUS / Elevated Reputation Signal (Unconfirmed, Tier 5 Score)

This exact alert — recurring 3x in one night — is what triggered flipping Gap 1 from
shadow into the live decision path. See `ALERT_CATEGORIZATION_CATALOG.md` rows 5a/5b/5c
for the three-way outcome this produces now.

**Illustrative example** (top_domains_report — purely observational, no autonomous
action, shown for completeness rather than as a captured real message):

> 📊 **Top Domains — Last 24h**
> • family_pc_fritz_box: github.com (142), api.spotify.com (89), teams.microsoft.com (54)
> • amazon_echoshow_fritz_box: api.spotify.com (211), music-fa.scdn.co (176)

---

## How it all fits together — one false positive's lifecycle

1. A device triggers an alert. It's evaluated by CL-AFPE (Stage 1 hard-stop checks, then
   Stage 2 LightGBM, then Stage 3 FastEmbed if Stage 2 is inconclusive).
2. If it's autonomously suppressed as a false positive: the domain (or IP) is immunized
   into the [trust cache](#2-trust-cache--domain-immunization) (§2), the device's
   [sigma widens](#1-sigma-shift-per-device-sensitivity-tuning) (§1), and — if it's a
   *new* immunization — you get a `🔔 Auto-action: immunized` alert with a 24h Revoke
   window.
3. If instead the alert reaches Telegram and you tap "Mark False Positive" yourself, the
   exact same mechanism fires, tagged `source="operator"` instead of `"autonomous"` —
   distinguishable in the training data, but functionally identical.
4. Separately, every ~4 hours, [Ollama](#8-ollama-brain-3-llm-validated-closed-loop) (§8)
   independently re-analyzes recent patterns from raw evidence, feeding the same trust
   cache / sigma-shift loops from a completely different reasoning path (an LLM, not a
   classifier) — a second opinion that can catch what CL-AFPE's statistical approach
   missed, or vice versa.
5. Once a day, `train_fp_classifier.py` retrains the classifier itself and recalibrates
   [per-device thresholds](#3-per-device-learned-thresholds-autotune) (§3) from
   everything accumulated so far — corrections from CL-AFPE, human taps, and Ollama all
   feed the same training set.
6. If a genuine threat is later confirmed anywhere on this device (or on this same
   IP/domain from a *different* device, via [local confirmed-intel](#7-local-confirmed-intel-cross-device-network-effect)
   §7), sigma tightens immediately (twice as fast as it widened) and the network-wide
   protection propagates to every device, not just the one that found it first.

Nothing in this chain is a black box — every step above either produces a Telegram
notification with an undo button, or feeds a Grafana panel/Prometheus metric you can
inspect directly (see the [Autonomous Behavior dashboard](../grafana_dashboard/4_autonomous_behavior.json)
and [Device Deep Dive](../grafana_dashboard/3_device_deep_dive.json)'s per-device
self-learning section).
