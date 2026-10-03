# Home-IDS Pipeline Mathematics

The formulas behind every stage of the detection pipeline, with the constants the code uses. The
[Engineering Manual](ENGINEERING_MANUAL.md) explains what each stage does and in which order; this document explains
the arithmetic. Every formula is taken from the source file named in its section.

## Contents

1. [Per-device statistical baselines](#1-per-device-statistical-baselines)
2. [Evidence weight: confidence × freshness](#2-evidence-weight-confidence--freshness)
3. [Independent families: counting corroboration](#3-independent-families-counting-corroboration)
4. [Hypothesis scoring: the discrete ladder](#4-hypothesis-scoring-the-discrete-ladder)
5. [Reputation tiers](#5-reputation-tiers)
6. [Combining threat-intelligence sources](#6-combining-threat-intelligence-sources)
7. [The decision and the risk number](#7-the-decision-and-the-risk-number)
8. [DGA and domain entropy](#8-dga-and-domain-entropy)
9. [DNS tunnelling and covert channels](#9-dns-tunnelling-and-covert-channels)
10. [Peer-cohort deviation](#10-peer-cohort-deviation)
11. [The false-positive engine](#11-the-false-positive-engine)
12. [The AI advisor's validator](#12-the-ai-advisors-validator)
13. [Autotuning: the Wilson-bound safety gate](#13-autotuning-the-wilson-bound-safety-gate)
14. [The containment ladder and persistence](#14-the-containment-ladder-and-persistence)
15. [Notification grouping](#15-notification-grouping)
16. [Appendix: every numeric constant](#16-appendix-every-numeric-constant)

---

## 1. Per-device statistical baselines

Two baseline layers run side by side. A fast EWMA layer produces the z-scores carried in every alert's features. A
Bayesian layer produces typed evidence (`baseline_deviation`, `regime_change`, `markov_*`).

### 1a. EWMA z-scores

**File:** `src/core/state.py` (`EWMABaseline`), `src/core/pipeline.py` (`calc_z()`).

One exponentially weighted mean and variance per device and metric, in 24 hour-of-day buckets:

```python
def update(self, value, hour):
    if not self.init[hour]:
        self.mean[hour] = value; self.var[hour] = 0.0; self.init[hour] = True; self.n[hour] = 1
    else:
        diff = value - self.mean[hour]
        self.mean[hour] += self.alpha * diff                                  # alpha = 0.05
        self.var[hour] = (1 - self.alpha) * (self.var[hour] + self.alpha * diff ** 2)
        self.n[hour] += 1
```

With α = 0.05, each observation moves the mean 5% of the way towards itself (about a 20-cycle effective memory).
Neighbouring hours are interpolated by the current minute, so the baseline does not jump on the hour.

```python
def calc_z(val, baseline):
    mean, var, init, n = baseline.get_stats_interpolated(hour, minute)
    if not init or n < 10:
        return 0.0                                         # no confidence from a cold bucket
    return max(0.0, (val - mean) / math.sqrt(max(var, 1e-4)))
```

A one-sided z-score over counts from a 5-minute sliding window. Buckets with fewer than 10 samples return 0, and the
variance floor stops a constant metric from dividing by almost zero.

### 1b. Bayesian conjugate models

**Files:** `src/argus/baseline/bayesian.py` (mathematics), `src/argus/baseline/engine.py` (persistence and gating).
One model per `(device, metric, hour, regime)`.

**Gaussian** (query rate, entropy, unique domains, outbound bytes, risk): a Normal-Inverse-Gamma posterior.

```python
# prior: mu = 0.0, kappa = 0.05, alpha = 1.0, beta = 1.0
kappa_new = kappa + 1
mu_new    = (kappa * mu + x) / kappa_new
alpha_new = alpha + 0.5
beta_new  = beta + kappa * (x - mu) ** 2 / (2 * kappa_new)
```

The posterior predictive is Student-t with `loc = mu`, `scale² = beta (kappa + 1) / (alpha kappa)` and `2 alpha`
degrees of freedom. It is wide with few samples and narrows as they accumulate. Surprise is one-sided:
`max(0, (x − loc) / scale)`.

**Beta** (NXDOMAIN ratio, blocked ratio): a Beta-Binomial posterior with prior Beta(1, 1).

```python
a += successes
b += trials - successes
```

Surprise is two-sided: `|ratio − mean| / sqrt(variance)`.

**Poisson** (DGA hits, decoy touches): a Gamma-Poisson posterior with prior Gamma(1, 1).

```python
shape += count
rate  += 1
```

Surprise is one-sided: `(count − mean) / sqrt(shape / rate² + mean)`. The variance combines parameter uncertainty
with the Poisson variance, which approximates the negative-binomial predictive.

**Markov** (activity-state sequences): a Dirichlet-categorical transition model with Laplace smoothing.

```python
p = (count + pseudo_count) / (total + k * pseudo_count)      # pseudo_count = 0.5, k = number of states
surprise = -log(p)
```

It conditions on the last two states once that context has at least 20 samples, and on the last state otherwise.
Surprise is information-theoretic surprisal: zero for an expected transition, growing without bound for an
improbable one. It is learned per device, from the device's own history.

### 1c. Regime changes: Bayesian online change-point detection

**File:** `src/argus/baseline/bayesian.py` (`BOCPDTracker`). This follows Adams and MacKay (2007). Each run-length
hypothesis carries its own model and weight:

```python
for run_length, model, weight in hypotheses:
    grown.append((run_length + 1, model, weight * predictive_density(model, x) * (1 - hazard)))
grown.append((0, weaken(dominant_model), sum(weights) * hazard))   # "a change happened now"
normalise; update every surviving model with x
prune weights below 1e-4; keep at most 40 hypotheses
```

`hazard` defaults to 1/500 (an expected regime length of about 500 cycles) and is tuned automatically (section 13).
A change is confirmed in two stages, so a single spike cannot declare a new regime:

```
1. Candidate: change-point mass >= 0.5 -> freeze the pre-spike dominant model as an anchor
2. Over the next 3 observations, measure each one's surprise against that frozen anchor
3. Confirmed only if the average surprise >= 3.0 -> regime id increments, regime_change evidence
```

### 1d. Population priors for cold start

**File:** `src/argus/ops/population_prior_builder.py`. Each night, devices of the same type pool their learned
posteriors into a prior per `(device type, metric, hour)`. A contributor needs at least 20 real observations and
must be clean, meaning its latest decision is not SUSPICIOUS or worse. A pool needs at least 2 contributors.

| Model | How the pool is built | Strength |
|---|---|---|
| Gaussian | Mean of contributors' means; mean of implied variances (`beta / alpha`) | `kappa`, `alpha` pseudo-counts (default 5 and 10; tuned) |
| Beta | Mean ratio | Total pseudo-count (default 10; tuned) |
| Poisson | Mean rate | Pseudo-exposure (default 5; tuned) |
| Markov | Sum of transition counts, scaled down to a cap of 50 | Count cap |

A new device's model starts from the pool's hyperparameters. Its own data then outweighs the prior through the
normal conjugate update. The pseudo-count is the blending weight. A pool that falls below its contributor minimum is
deleted, not left stale.

### 1e. Learning pause

While a device's latest decision is SUSPICIOUS, HIGH or CRITICAL, and for 30 minutes after it returns to normal, no
baseline, regime or Markov update is made for that device.

---

## 2. Evidence weight: confidence × freshness

**Files:** `src/argus/evidence/model.py`, `src/argus/hypotheses/engine.py`.

```python
effective_weight = confidence * freshness
freshness = max(0, 1 - age / ttl)        # ttl = 600 s; 86,400 s for reputation evidence
                                         # evidence at or past its ttl is dropped entirely
```

Influence fades linearly. Five-minute-old behavioural evidence counts at half weight. Expired evidence is removed
before any hypothesis sees it, so it can never add even a token amount to a corroboration count.

---

## 3. Independent families: counting corroboration

**File:** `src/argus/hypotheses/independence.py`. Each evidence type belongs to exactly one family. Corroboration is
the size of a set:

```python
def count_independent_families(evidence_types) -> int:
    return len(frozenset(family_for(t) for t in evidence_types))
```

Five entropy items and one DGA burst are all `dns_behavior`, so they count as one. The families that never count are
excluded first: local context, novelty, peer-cohort deviation, ML anomaly, policy, baseline deviation, regime change
and sequence dynamics.

**Destination linkage** (`src/argus/decision/engine.py`): evidence that has a destination only counts towards a
hypothesis if that destination is among the hypothesis's own:

```python
attack_evidence = [e for e in attack_evidence
                   if e.destination_id == NO_DESTINATION or e.destination_id in hyp_destinations]
```

This filter can only remove corroboration, never add it.

---

## 4. Hypothesis scoring: the discrete ladder

**File:** `src/argus/hypotheses/engine.py`. Every hypothesis returns one of **0, 2, 3, 4**. Two counters drive it:

- `strong_score`, raised by conditions that strengthen the case (a second signal type, a high value, several distinct
  provenance tags);
- `contradicting_score`, raised when the hypothesis's own destination is in reputation tier 0, 1 or 2. Reputation
  acts as a veto or dampener, never as a bonus.

```python
# DNSTunnelingHypothesis, as an example
score = 2.0
if strong_score > 0 and contradicting_score == 0:
    score = 3.0
if strong_score > 0.5 and contradicting_score == 0 and effective_tier == 4:
    score = 4.0
```

`_effective_rep_tier()` uses the reputation of the hypothesis's own destination. If the device-level reputation
belongs to a different destination, the hypothesis is scored with a neutral tier 3.

**Combining hypotheses is winner-takes-all.** The attack score is the highest attack hypothesis's score, and the
benign score is the highest benign hypothesis's score. Nothing is summed or averaged.

**`hypothesis_weight`** is the mean confidence of evidence in the partial-support families (DNS behaviour, TLS,
network behaviour, data transfer, reputation, direct observation). It decides whether an alert is marked "evidence
verification required". It never chooses the decision state.

---

## 5. Reputation tiers

**File:** `src/intelligence/reputation/classifier.py`.

```python
tier = 3                                                    # unclassified
if destination is a private, link-local or loopback address:      tier = 0
elif destination ends with .box, .local or fritz.box:              tier = 0
elif destination is a major trusted vendor domain:                 tier = 1
elif destination is known CDN, cloud or ad infrastructure,
     or its network owner is a known-safe provider:                tier = 2
else:
    confirmed = vt_score > 2.0 or ti_score > 2.0 or abuse_score >= 4.0
    weak      = vt_score > 0   or ti_score > 0   or abuse_score > 0
    if confirmed:   tier = 5;  verified_ioc = ti_score > 2.0
    elif weak:      tier = 4
```

Tiers 0 to 2 are a floor: a reputation score cannot raise them. `verified_ioc` comes only from curated threat
intelligence, never from an abuse score alone. The two floors (2.0 and 4.0) are tuned automatically within bounds
(section 13).

---

## 6. Combining threat-intelligence sources

**Files:** `src/core/pipeline.py`, `src/intelligence/threat_intel.py`. Each source contributes a value in [0, 4]:

```python
ti_risk_et_open = confidence * 4.0       # ET Open index: C2 IPs 0.95, malware/C2 domains 0.90, JA3 0.90
ti_risk         = confidence * 4.0       # Feodo, SSLBL, local confirmed intel; keyed feeds when licensed
abuse_risk      = min(abuse_confidence / 100 * 6.0, 4.0)      # AbuseIPDB, when licensed; 4.0 on its blacklist
vt_risk         = 4.0 if destination is a decoy address
                  else min((malicious + 0.5 * suspicious) / engines * 6.0, 4.0)   # VirusTotal, when licensed

reputation_value = max(ti_risk_et_open, ti_risk, abuse_risk, vt_risk)
confidence       = 0.95 if reputation_value >= 4.0 else 0.8
```

One `reputation` evidence item is created, attributed to the destination that produced the maximum. The worst
single source wins, and the sources are never blended.

**Staleness** (`src/intelligence/ti_staleness.py`): indicators from the local index keep full weight for 14 days
after the last successful update check, then lose weight linearly, reaching zero at 60 days.

---

## 7. The decision and the risk number

**File:** `src/argus/decision/engine.py`. The decision state (BENIGN, ANOMALOUS, SUSPICIOUS, HIGH, CRITICAL) is
chosen by the branch of the decision tree that fires (see the Engineering Manual, section 8). Each branch sets a
fixed `threat_confidence`: 1.00, 0.99, 0.98, 0.95, 0.85, 0.75, 0.70, 0.45, 0.40, 0.10 or 0. The 0–10 risk number shown
to users is a linear rescale:

```python
risk = threat_confidence * 10.0
```

A risk of 8.5 therefore always means one specific branch: a corroborated HIGH, or a corroborated tier-5 reputation.
It is a deliberately coarse, discrete scale, not a calibrated probability.

**Hard-stop corroboration:**

```python
corroborating_sources = len(independence_families - rule.own_families)
if corroborating_sources >= 1 and attack_score > benign_score:
    state, confidence = CRITICAL, rule.confidence
else:
    state, confidence = HIGH, rule.uncorroborated_confidence     # 0.70 geofence, 0.75 exploit
```

A rule's own family is subtracted before counting, so a lone Suricata match cannot corroborate itself.

**The HIGH bar:** attack score ≥ 3.0 **and** at least 2 independent families **and** attack score > benign score.

---

## 8. DGA and domain entropy

**File:** `src/utils.py`.

```python
def entropy(text):                       # Shannon entropy in bits per character
    return -sum(p * log2(p) for p in character_frequencies(text))

def vowel_ratio(text):
    return count_vowels(text) / max(len(text), 1)
```

`entropy("dropbox")` is about 2.52 bits. A random string of the same length such as `xk4qz7p` is close to
`log2(7)` ≈ 2.81. Pronounceable words also have regularly spaced vowels.

**Per-domain test** (`suspicious_dga()`), applied to the first label after exempting `.arpa`, `.local`, `.lan` and
CDN or cloud domains:

```python
n = len(label)
if 6 <= n <= 11:
    return (vowel_ratio <= 0.12 and entropy > 2.6 and digit_ratio < 0.40) or \
           (digit_ratio >= 0.45 and entropy > 3.0)
if n >= 12:
    return entropy > 3.2 and vowel_ratio < 0.25 and digit_ratio < 0.75
return False
```

**Burst confidence** (`src/intelligence/detectors/threat_signals.py`), where `sd` is the count of suspicious domains
in the window:

```python
if sd >= 15:                                  confidence = min(1.0, 0.6 + sd / 50)
elif sd >= 5 and average_entropy > 3.5:       confidence = 0.6
elif not telemetry and dga_score > 0.40:      confidence = min(1.0, dga_score)   # optional classifier fallback
```

---

## 9. DNS tunnelling and covert channels

**Files:** `src/extractors/dns_features.py`, `src/intelligence/detectors/threat_signals.py`.

| Signal | Threshold | Confidence |
|---|---|---|
| Encoded or long label | First label longer than 28 characters with entropy > 3.6 (CDN and telemetry exempt) | `min(1, 0.5 + 0.15 × count)` |
| Subdomain fan-out | At least 8 distinct children of one registrable domain in the window | Base value + `min(0.3, max(0, avg_entropy − 3.0) × 0.2)` |
| TXT / NULL / ANY share | More than 15% of queries | `min(1, ratio × 2)` |
| Suspicious TLD share | More than 15% of queries to `.top`, `.xyz`, `.biz`, `.cc`, `.cfd`, `.buzz`, `.gq`, `.tk`, `.work`, `.rest`, `.country`, `.stream`, `.icu`, `.click`, `.live` | `min(1, ratio × 2)` |

The covert-tunnelling hypothesis needs at least two **different** signals to reach 3. It needs confidence of at least
0.85 and reputation tier 3 or 4 to reach 4. Each signal alone has a plausible benign explanation.

---

## 10. Peer-cohort deviation

**File:** `src/argus/ops/live_engine.py`.

```python
window     = 7 days
min_peers  = 3            # other devices with the same, known device type
multiplier = 3.0          # tuned automatically, 1.5 to 10
min_count  = 5            # tuned automatically, 2 to 20

my_count = distinct destinations this device contacted in the window
if my_count >= min_count:
    peer_avg = mean(distinct destinations of each peer)
    if peer_avg > 0 and my_count >= multiplier * peer_avg:
        emit Evidence("peer_deviation", confidence=0.6, value=my_count)
```

The cohort is every other device with the same device-type label; unknown types are never pooled. The hypothesis is
capped at 3, and its family never counts as a witness. It scores only when the same device also has attack-shaped
evidence (DGA, tunnelling, lateral scan, malicious fingerprint, exfiltration, beaconing, connection abuse, ARP sweep,
DNS evasion, a medium-or-stronger Zeek notice); on its own it is context and creates no alert. On the reference
network that removed about 96% of its alerts (2,812 a day to 115).

---

## 11. The false-positive engine

**Files:** `src/argus/cl_afpe/engine.py`, `ml_scoring.py`, `composite_trust.py`.

### 11a. Trust cache and composite trust

A destination enters a per-target trust cache when it is confirmed safe. The default TTL is 14 days, tuned between
1 and 30. Using the cache also needs the composite trust gate. Trust is kept per six-part key
`(device, behaviour fingerprint, destination class, hypothesis, evidence family, regime)`:

```python
decayed   = max(0.0, trust - 0.05 * days_since_last_update)
new_trust = min(1.0, decayed + 0.15)                     # per corroborating observation

def permits_suppression(key):
    return len({family for family, trust in trusts(key) if trust >= 0.6}) >= 2
```

A single repeated signal can never build enough trust alone: two distinct families must each pass 0.6. If the gate
does not agree, or fails, the full evaluation below runs.

The console's Autonomy tab shows each `(device, hypothesis, destination class, family)` row's progress as

```python
progress = min(1.0, trust / 0.6)         # 100% = this family qualifies as a witness
```

computed from the trust value stored at its last update. About five confirmations in quick succession reach 100%
(4 × 0.15 = 0.6 exactly, less the decay between them, falls just short); spread out, each day of silence costs 0.05.

A destination that is itself a known device on the network, with exactly zero threat-intelligence and abuse scores,
builds composite trust in the same way and is suppressed only once the gate passes.

### 11b. Stage 1: hard stops

Any one of these is a CONFIRMED_THREAT:

```
(0) the decision engine already said CRITICAL      (4) decoy contact
(1) ti_risk > 2.0                                  (5) abuse_risk >= 4.0
(2) lateral movement across >= 2 distinct targets  (6) outbound_bytes_z > 5.0 and outbound bytes > 2,500,000
(3) malicious JA3/JA4 fingerprint                      (known telemetry and CDN destinations exempt)
                                                   (7) a local confirmed-intel match
```

### 11c. Stages 2 and 3

```python
def combine_scores(lgbm_prob, embed_sim, embed_threshold=0.82):
    if embed_sim is None:
        return lgbm_prob if lgbm_prob is not None else 0.50
    if lgbm_prob is None:
        lgbm_prob = 0.50                                    # neutral: no classifier signal
    if lgbm_prob == 0.50 and embed_sim >= embed_threshold:
        return embed_sim
    return 0.45 * lgbm_prob + 0.55 * embed_sim
```

```
combined >= suppress threshold (0.80)            -> FALSE_POSITIVE, suppressed
uncertain threshold (0.55) <= combined < 0.80    -> UNCERTAIN, published with a low-confidence flag
combined < 0.55                                  -> CONFIRMED_THREAT, sensitivity shift tightened (recorded only, see 11d)
```

Both thresholds are read on every alert, in layers: the configured value (`fp_combined_suppress_threshold`,
`fp_combined_uncertain_threshold`), then for the suppress threshold the device's own value raised by corrections,
then a value promoted by the autotuner (device, device type, global). If the engine raises an error the verdict is
UNCERTAIN with `suppress = false`.

### 11d. Sensitivity shift

Each device has its own sensitivity shift:

```python
on CONFIRMED_THREAT: shift = max(shift - 0.50, -1.5)        # tighten fast
on FALSE_POSITIVE:   shift = min(shift + 0.25,  2.0)        # relax slowly
```

Tightening is twice as fast as relaxing. The shift is recorded per device and shown on the dashboards, but no
detector reads it yet, so it does not change detection; wiring it into the baseline thresholds is an open decision.

Verdict thresholds are fixed values that the autotuner adjusts. No calibrated probability is used to make the
decision.

---

### 11e. Classifier training

Input vector (11 values; `f` = the alert's `features`):

```
x0  = 1 − rank/1,000,000 if rank > 0 else 0      # rank: Tranco when tranco_enabled, else local popularity
x1  = min(entropy(first label) / 5, 1)
x2  = min(max_label_length / 60, 1)
x3  = min(max(outbound_bytes_z, 0) / 10, 1)
x4  = device-type weight (laptop/desktop 0.5, phone/tablet 0.4, TV/console 0.3, printer/NAS 0.2, IoT/camera 0.1, unknown 0.3)
x5  = 0                                           # retired "already trusted" flag (it reproduced the label)
x6  = min(zeek_lateral_moves / 10, 1)
x7  = min(zeek_s0_rej_count / 50, 1)
x8  = clamp(zeek_app_protocol_weight, 0, 1)       # 0.2 when absent
x9  = min(zeek_arp_sweep_count / 20, 1)
x10 = clamp(zeek_dns_evasion_ratio, 0, 1)
```

Training:

```
weight(row)    = n / (2 · n_class(row))
model          = StandardScaler → GradientBoosting(n_estimators=50, max_depth=3, learning_rate=0.1)
split          = 75/25 stratified, seed 42 (needs ≥ 40 held-out rows and both classes)
install if       balanced_accuracy(held-out) ≥ 0.65
             and max over inputs j of balanced_accuracy(best threshold on x_j alone) < 0.98
```

On the reference network the first gated model (2026-10-03) reached a held-out balanced accuracy of 0.97, with the
best single input at 0.84 (rejected connections). Replayed over the previous 24 hours of alerts, it would have
suppressed 1.4 %.

## 12. The AI advisor's validator

**File:** `src/argus/llm_review/validator.py`. A "benign" opinion from the local model is rejected if:

- reputation evidence has value ≥ 4.0;
- the model claims "telemetry" while reputation evidence is ≥ 3.0;
- the decision path was a hard stop, a confirmed or corroborated tier-5 reputation, or a corroborated HIGH;
- attack-shaped evidence types are present;
- the destination is neither trusted nor familiar to the device (familiarity below the tuned trust bar, default
  0.6);
- candidate hypotheses go unaddressed;
- its supporting evidence is empty or contradicts itself;
- it cites the risk number back (circular reasoning).

A "malicious" opinion that cites a risk score the model was never shown is rejected as well. The advisor's output is
advisory only.

---

## 13. Autotuning: the Wilson-bound safety gate

**Files:** `src/argus/autotune/engine.py`, `src/argus/ops/backtest_job.py`.

Loosening a device- or category-level parameter (making detection less sensitive) affects few devices, so there is
little real traffic to validate it. A rule like "N trials, all passed" is weak, because 3 out of 3 says little. The
Wilson score interval gives a conservative lower bound on the true rate and discounts small samples:

```python
def wilson_lower_bound(hits, n, z=1.959963984540054):
    if n <= 0:
        return 0.0
    p = hits / n
    denom  = 1 + z * z / n
    center = p + z * z / (2 * n)
    margin = z * sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (center - margin) / denom)
```

```
               p̂ + z²/2n − z·√(p̂(1−p̂)/n + z²/4n²)
Wilson_lower = ───────────────────────────────────
                          1 + z²/n
```

| n, all detected | Wilson lower bound |
|---|---|
| 15 | 0.7961 |
| 18 | 0.8241 |
| 20 | 0.8389 |
| **22** | **0.8513** |
| 25 | 0.8668 |
| 29 | 0.8830 |

A perfect record needs **22** trials to clear the 0.85 floor. The 20-trial minimum is only a cheap pre-filter.

**The gate in both directions:**

```python
if worst_detection_rate < 0.70:
    tighten now                         # no sample minimum: thin evidence errs towards scrutiny
elif loosening allowed:
    if any attack class has < 20 trials:            do nothing
    elif worst_detection_rate < 1.0:                do nothing   # one miss anywhere blocks loosening
    elif min(wilson_lower_bound(h, n) for each class) >= 0.85 and no drift:
        loosen
```

**Trust radius.** A scope may not drift looser than its parent by more than two maximum steps:

```
divergence = (new_value - parent_value) * direction
reject if divergence > 2.0 * max_step
```

**Retroactive circuit breaker.** Over the last 7 days, the breaker looks for a real Suricata match whose confidence
fell between a loosened scope's value and its parent's value. If that device then had a confirmed threat within the
hard-stop window, the scoped value is rolled back immediately, with no canary or approval.

**Lifecycle constants:** a 1-hour cooldown per parameter and scope, a 6-hour canary, and promotion only with a passing
backtest.

---

## 14. The containment ladder and persistence

**File:** `src/mitigation/ips.py` (`mitigate()`).

| Action | Gate |
|---|---|
| DNS block (Pi-hole) | Decision HIGH or CRITICAL |
| Router isolation | Router integration on, and risk ≥ 8.5 **or** a lateral threat (lateral movement across ≥ 2 targets, or decoy contact) |
| Layer-2 tarpit (ARP and NDP) | Risk ≥ 9.0 **or** a lateral threat; also armed alongside router isolation, because the router blocks IPv4 only |

Unless the threat is lateral, router isolation and the tarpit need approval when approval mode is on, or when the
device is a critical type. A device the user released is not contained again automatically unless the threat is
lateral.

**Persistence** (`src/core/pipeline.py`): a SUSPICIOUS verdict with the same signature for 600 seconds is displayed as
HIGH with `threat_confidence` raised to at least 0.55. For containment and notifications it still counts as
SUSPICIOUS:

```python
containment_state = decision["state"]
if decision.get("escalated_via_persistence"):
    containment_state = SUSPICIOUS      # persistence of one weak signal is not a second witness
```

---

## 15. Notification grouping

**File:** `src/core/incident_tracker.py`.

```python
send = (not fp_verdict.suppress) and containment_state in (HIGH, CRITICAL) and tracker.should_notify(key, state, now)
```

An incident is identified by device + target + signature.

```python
if no record, or the last occurrence was more than 1800 s ago:
    new incident -> notify
else:
    occurrences += 1
    notify = severity_rank > rank_at_last_notification or now - last_notified >= 900
```

So a message is sent for a new incident, for a real escalation past what was last sent, or as a "still ongoing"
update every 15 minutes. Alerts are recorded and fed to the false-positive engine regardless of this gate.

---

## 16. Appendix: every numeric constant

| Constant | Value | Where |
|---|---|---|
| EWMA α | 0.05 | `core/state.py` |
| EWMA minimum samples / variance floor | 10 / 1e-4 | `core/pipeline.py` |
| DNS feature window | 300 s | `extractors/dns_features.py` |
| Gaussian prior (μ, κ, α, β) | 0, 0.05, 1, 1 | `argus/baseline/bayesian.py` |
| Beta prior, Gamma prior | (1, 1), (1, 1) | `argus/baseline/bayesian.py` |
| Markov pseudo-count / order-2 minimum | 0.5 / 20 | `argus/baseline/bayesian.py` |
| BOCPD hazard (default, tuned range) | 1/500 (1/2000 to 1/100) | `argus/baseline/engine.py` |
| BOCPD pruning | weight < 1e-4, at most 40 hypotheses | `argus/baseline/bayesian.py` |
| Regime confirmation: mass / samples / mean surprise | ≥ 0.5 / 3 / ≥ 3.0 | `argus/baseline/engine.py` |
| Learning pause after an incident | 30 min | `argus/baseline/engine.py` |
| Population prior: minimum n / contributors | 20 / 2 | `argus/ops/population_prior_builder.py` |
| Population prior pseudo-counts (default) | Gaussian κ 5, α 10; Beta 10; Poisson 5; Markov cap 50 | `argus/ops/population_prior_builder.py` |
| Evidence TTL / reputation TTL | 600 s / 86,400 s | `argus/hypotheses/engine.py` |
| Hard-stop freshness | 120 s | `argus/decision/engine.py` |
| Attack score floor / HIGH bar | 2.0 / ≥ 3.0 with ≥ 2 families | `argus/decision/engine.py` |
| Tier-5 CRITICAL without verified IOC | ≥ 2 families | `argus/decision/engine.py` |
| Hard-stop corroboration | ≥ 1 family besides its own | `argus/decision/engine.py` |
| Tier-4 SUSPICIOUS bar | max source ≥ 1.5 | `argus/decision/engine.py` |
| ML-only ANOMALOUS bar | > 0.90 | `argus/decision/engine.py` |
| Confirmed reputation floors | TI/VT > 2.0, abuse ≥ 4.0 (tuned) | `intelligence/reputation/classifier.py` |
| Familiarity trust bar | 0.6 (tuned 0.3 to 0.9) | `argus/hypotheses/engine.py` |
| Risk scale | `threat_confidence × 10` | `core/pipeline.py` |
| Threat-intelligence staleness | full weight 14 days, zero at 60 days | `intelligence/ti_staleness.py` |
| DGA burst: strong / moderate | ≥ 15 / ≥ 5 with entropy > 3.5 | `intelligence/detectors/threat_signals.py` |
| DNS tunnelling thresholds | label > 28 chars with entropy > 3.6; fan-out ≥ 8; TXT/NULL > 15%; suspicious TLD > 15% | `extractors/dns_features.py` |
| Peer deviation: window / peers / multiplier / minimum | 7 days / 3 / 3.0 / 5 | `argus/ops/live_engine.py` |
| Trust cache TTL | 14 days (tuned 1 to 30) | `argus/cl_afpe/engine.py` |
| Composite trust: step / decay / floor / families | +0.15 / −0.05 per day / 0.6 / 2 | `argus/cl_afpe/composite_trust.py` |
| Stage 2 and 3 weights / embedding bar | 0.45, 0.55 / 0.82 | `argus/cl_afpe/ml_scoring.py` |
| Suppress / uncertain thresholds | 0.80 / 0.55 (tuned) | `argus/cl_afpe/engine.py` |
| Exfiltration hard stop | z > 5.0 and > 2,500,000 bytes | `argus/cl_afpe/engine.py` |
| Sensitivity shift | −0.50 (floor −1.5) / +0.25 (cap 2.0) | `argus/cl_afpe/engine.py` |
| Autotune cooldown / canary | 1 h / 6 h | `argus/autotune/engine.py` |
| Loosening: trials / Wilson floor; tightening floor | 20 / 0.85; 0.70 | `argus/autotune/engine.py`, `backtest_job.py` |
| Trust radius | 2 × max step | `argus/autotune/engine.py` |
| Circuit-breaker look-back | 7 days | `argus/ops/backtest_job.py` |
| Router isolation / tarpit | risk ≥ 8.5 / ≥ 9.0, or a lateral threat | `mitigation/ips.py` |
| Persistence window / confidence floor | 600 s / 0.55 | `core/pipeline.py` |
| Incident grouping / update interval | 1800 s / 900 s | `core/incident_tracker.py` |
| Shared threat memory TTL | 30 days | `intelligence/local_intel.py` |
