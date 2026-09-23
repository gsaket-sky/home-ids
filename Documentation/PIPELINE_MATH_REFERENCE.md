# Argus — Pipeline Math Reference

> **Companion to `ARGUS_ARCHITECTURE.md`.** That document is the authoritative map of
> *what runs, in what order, and why* — call chains, sequence diagrams, the full
> hard-stop/decision-tree table. This document exists to answer a narrower question for
> each stage: **what is the actual formula, and how was that number derived?** Where a
> formula is already fully spelled out in `ARGUS_ARCHITECTURE.md` (the decision-tree
> table, the hypothesis score table), this doc cross-references it rather than repeating
> it, and instead explains the arithmetic underneath.
>
> Every formula below is copied verbatim (or line-for-line reproduced) from the real
> source file at the line numbers cited, checked against the live code on
> 2026-09-16 — not reconstructed from memory or a design doc. Where a mechanism exists
> in code but is **not actually running on `.94`** (the live host this project targets),
> that is called out explicitly and prominently, matching this project's own standing
> "verify, don't assume" discipline (see `ARGUS_DECISIONS.md`'s Standing Rules).
>
> **Naming**: this document uses "Argus" for the live v13-successor pipeline throughout,
> per `ARGUS_ARCHITECTURE.md`'s own naming note — "v13" only appears here where it's a
> literal, permanent identifier (a file path, a config value, a provenance string), never
> as a name for the live system.

## Table of contents

1. [Statistical baseline models](#1-statistical-baseline-models-gaussianbetapoissonmarkov) — Gaussian/Beta/Poisson/Markov
2. [Evidence weighting: confidence × freshness](#2-evidence-weighting-confidence--freshness-decay)
3. [Independence families: the corroboration-counting rule](#3-independence-families-the-corroboration-counting-rule)
4. [Hypothesis scoring: the discrete ladder](#4-hypothesis-scoring-the-discrete-ladder)
5. [Reputation tiering](#5-reputation-tiering)
6. [Threat-intel combination (VT / AbuseIPDB / TI)](#6-threat-intel-combination-vt--abuseipdb--ti)
7. [Decision engine: risk number, hard-stops, hypothesis_weight](#7-decision-engine-risk-number-hard-stops-hypothesis_weight)
8. [DGA & domain-entropy detection](#8-dga--domain-entropy-detection)
9. [DNS tunneling / covert-channel detection](#9-dns-tunneling--covert-channel-detection)
10. [Peer-cohort deviation](#10-peer-cohort-deviation)
11. [CL-AFPE: Stage 1 hard-stops, Stage 2/3 ML combination, composite trust](#11-cl-afpe-stage-1-hard-stops-stage-23-ml-combination-composite-trust)
12. [Confidence calibration — collected, not yet load-bearing](#12-confidence-calibration--collected-not-yet-load-bearing)
13. [Autotune engine: the Wilson-bound safety gate](#13-autotune-engine-the-wilson-bound-safety-gate)
14. [IPS containment ladder & persistence escalation](#14-ips-containment-ladder--persistence-escalation)
15. [Telegram gating: IncidentTracker](#15-telegram-gating-incidenttracker)
16. [Appendix: every literal numeric threshold in one table](#16-appendix-every-literal-numeric-threshold-in-one-table)

---

## 1. Statistical baseline models (Gaussian/Beta/Poisson/Markov)

**Two genuinely separate baseline mechanisms exist in this codebase, at different
maturity and deployment stages — do not conflate them.** `ARGUS_ARCHITECTURE.md` §5
already flags this distinction for the Bayesian subsystem; this section carries the
same live/not-live check through the math itself, since the two mechanisms produce
similarly-named-sounding numbers (both are "baselines," both produce "surprise"/"z"
signals) that are easy to mix up in an incident writeup.

### 1a. The EWMA z-scores — live on `.94` today, feeds real evidence

**File:** `src/core/state.py` (`class EWMABaseline`, lines 53-108), consumed by
`src/core/pipeline.py`'s `calc_z()` (lines 1277-1289). **This is the mechanism actually
producing the `query_rate_z`/`entropy_z`/`nxdomain_ratio_z`/`outbound_bytes_z`/etc.
values seen in every real `.94` alert's `features` dict** — confirmed both by direct
code read and by the fact these exact keys appear with nonzero values in `.94`'s live
`alerts.json`.

One exponentially-weighted mean/variance tracker per (device, metric), bucketed into 24
hour-of-day slots:

```python
class EWMABaseline:
    def __init__(self, alpha=0.05):   # alpha configurable via config.yaml's baseline_alpha
        self.mean = [0.0] * 24; self.var = [0.0] * 24
        self.init = [False] * 24; self.n = [0] * 24

    def update(self, value, hour):
        if not self.init[hour]:
            self.mean[hour] = value; self.var[hour] = 0.0; self.init[hour] = True; self.n[hour] = 1
        else:
            diff = value - self.mean[hour]
            self.mean[hour] += self.alpha * diff
            self.var[hour] = (1 - self.alpha) * (self.var[hour] + self.alpha * (diff ** 2))
            self.n[hour] += 1
```

The standard online EWMA mean/variance recursion: `mean += α·(x−mean)`,
`var = (1−α)·(var + α·(x−mean)²)`, with `α = 0.05` by default (a new observation moves
the running mean 5% of the way toward itself each cycle — roughly a 20-cycle effective
memory window). Adjacent-hour values are linearly interpolated by the current minute
(`get_stats_interpolated()`) so the diurnal baseline doesn't step-jump at each hour
boundary.

**The z-score itself** (`calc_z()`, `core/pipeline.py:1277-1280`):

```python
def calc_z(val, baseline_obj):
    mean, var, init, n = baseline_obj.get_stats_interpolated(current_hour, current_minute)
    if not init or n < 10:
        return 0.0
    return max(0.0, (val - mean) / math.sqrt(max(var, 1e-4)))
```

A plain one-sided `(x - mean) / stddev` — **not** Welford's algorithm, not a robust
MAD-based z-score, not the Bayesian `surprise()` form below. Two hard gates: an
hour-of-day bucket with fewer than **10** samples always returns `0.0` (no false
confidence from a cold-start bucket), and variance is floored at `1e-4` before the
square root (a metric that's been perfectly constant so far never produces a
division-by-near-zero blowup). This is computed fresh every pipeline cycle from raw
counts over a **5-minute (300s)** sliding window (`window_seconds` config, enforced in
`extractors/dns_features.py`'s `FeatureExtractor.compute()`).

### 1b. The Bayesian conjugate-model subsystem — live on `.94` as of 2026-09-16

**File:** `src/argus/baseline/bayesian.py` (pure math), `src/argus/baseline/engine.py`
(orchestration/persistence, `device_baselines`/`population_priors` tables). **UPDATE
(2026-09-16, user request: "implement Bayesian Gaussian/Beta/Poisson/Markov + BOCPD
changepoint-detection subsystem in `.94`, ignore `.19`"): superseding this section's
own earlier "not running on `.94`" framing (accurate the day this doc was first
written, one day prior).** `BaselineEngine` was previously only ever instantiated by
`src/argus/ingest/daemon.py` (the separate `.19` shadow host); `argus/ops/live_engine.py`'s
`evaluate()` now constructs one too and scores every device with real traffic, every
cycle, via a new `_inject_baseline_evidence()` function that ports `daemon.py`'s own
`_score_baselines()` call sequence. Config-gated (`baseline_scoring_enabled`, default
`true`) — see `ARGUS_ARCHITECTURE.md` §5 for the full wiring writeup. Every formula
below is now a real, live explanation for `baseline_deviation`/`regime_change`/
`markov_*` evidence in a genuine `.94` alert, not just `.19`/future-cutover behavior.

Four conjugate-prior model families, one row per `(device_id, metric, hour, regime_id)`
in `device_baselines`:

**Gaussian** (`query_rate`, `entropy`, `unique_domains`, `outbound_bytes`, `risk`) — a
Normal-Inverse-Gamma conjugate posterior over (mean, variance):

```python
# prior: mu=0.0, kappa=0.05 (weak pseudo-count), alpha=1.0, beta=1.0
def update(self, x):
    kappa_new = self.kappa + 1.0
    mu_new = (self.kappa * self.mu + x) / kappa_new
    alpha_new = self.alpha + 0.5
    beta_new = self.beta + (self.kappa * (x - self.mu) ** 2) / (2.0 * kappa_new)
    self.mu, self.kappa, self.alpha, self.beta = mu_new, kappa_new, alpha_new, beta_new
```

The posterior-predictive distribution is Student-t (`loc=mu`,
`scale² = beta·(kappa+1)/(alpha·kappa)`, `dof=2·alpha`) — naturally wide with few
samples, narrowing as more accumulate, unlike a fixed-window EWMA. Its own "surprise"
score is one-sided: `max(0, (x - loc) / scale)`.

**Beta** (`nxdomain_ratio`, `blocked_ratio`) — Beta-Binomial conjugate over a rate:

```python
# prior: a=1.0, b=1.0 (uniform Beta(1,1))
def update(self, successes, trials):
    self.a += max(0.0, successes)
    self.b += max(0.0, trials - successes)
```

Surprise: `|observed_ratio - mean| / sqrt(Beta_variance)` — two-sided, unlike the
Gaussian/Poisson forms.

**Poisson** (`dga_hits`, `honeypot_touches`) — Gamma-Poisson conjugate over a rate:

```python
# prior: shape=1.0, rate=1.0  (Gamma(1,1) = Exponential(1))
def update(self, count):
    self.shape += max(0.0, count)
    self.rate += 1.0
```

Surprise: `(observed_count - mean) / sqrt(variance)`, one-sided, where variance is
approximated as `shape/rate² + mean` (posterior-parameter uncertainty plus the
Poisson's own variance=mean, an approximation to the true Negative-Binomial predictive
variance, per the code's own comment).

**Markov** (kill-chain-phase transition modeling) — Dirichlet-Categorical conjugate
transition probabilities, order-2 with an order-1 fallback for thin contexts
(`_MIN_ORDER2_SAMPLES = 20`):

```python
# add-alpha (Laplace) smoothed conditional probability, pseudo_count=0.5 by default
p = (count + pseudo_count) / (total + k * pseudo_count)   # k = number of possible states
```

Surprise is genuine information-theoretic surprisal, not a z-score:
`surprise = -log(p)` — zero for a fully-expected transition, growing unboundedly for an
improbable one. This *replaces* an older, purely cosmetic Markov mechanism still present
in `extractors/dns_features.py` (`_MARKOV_TRANSITIONS`, a hand-authored lookup table of
kill-chain-phase transition probabilities, feeding a `markov_anomaly` feature that,
per that file's own comment, "nothing in `decision_engine.py` or `hypotheses/engine.py`
ever reads" — display/Grafana-only, not a real detection input).

### 1c. Regime-change detection: Bayesian Online Changepoint Detection (BOCPD)

**File:** `src/argus/baseline/bayesian.py`, `class BOCPDTracker` (same "live on `.94`
as of 2026-09-16" status as §1b — runs wherever `BaselineEngine` runs, now including
`.94`'s own live per-cycle path).

Standard BOCPD (Adams & MacKay 2007): maintains a set of hypotheses, each pairing a
"run length" (cycles since the hypothesized last changepoint) with its own model
instance and a weight. Each cycle:

```python
for run_length, model, weight in hypotheses:
    fit = predictive_density(model, observation)             # how well this hypothesis explains x
    grown_weight = weight * fit * (1.0 - hazard_rate)         # "no changepoint" term
    grown.append((run_length + 1, model, grown_weight))

cp_weight = sum(all hypothesis weights) * hazard_rate         # "changepoint now" term
fresh_model = weaken(dominant_model)                          # anchored at current mean, less certain
grown.append((0, fresh_model, cp_weight))

normalize weights to sum to 1.0
update every surviving hypothesis's model with the new observation
prune hypotheses below weight 1e-4, cap at 40 by weight (bounds memory/CPU)
```

`hazard_rate` (default `1/500` — an expected ~500-cycle regime length) is one of the
four live-tunable autotune parameters (`bocpd_hazard_rate`, §13). **UPDATE
(2026-09-16): now has a real live consumer on `.94`** (`BaselineEngine._load_tracker()`
reads it via `get_active_value()` on every tracker construction) — the "motion with no
live effect" framing this section carried until now is stale. `backtest_job.py`'s real
proposer (§13) still doesn't trigger it, but for a different, still-accurate reason:
the nightly synthetic attack sweep has no signal shaped for this parameter (it's a
regime-sensitivity knob, not a detection-sensitivity one) — not because nothing would
read a promoted value.

**Regime-change confirmation is two-stage, not a single-cycle trigger** — the code's
own docstring documents two real false-positive modes this closed (a single 4-sigma
spike alone hitting `cp_mass=0.94`; a consecutive-cp_mass-streak check that also failed
because `cp_mass` structurally decays after one cycle regardless of a genuine regime
shift):

```
1. Candidate trigger: cp_mass (changepoint-hypothesis weight) >= 0.5 in one cycle
   -> freeze the PRE-SPIKE dominant model as a fixed anchor (never updated further)
2. Confirmation: over the NEXT 3 observations, compute each one's surprise() against
   that frozen anchor
3. Confirmed only if the AVERAGE of those 3 surprises >= 3.0
   -> regime_id increments; a regime_change Evidence item is emitted
```

This is the formal version of the "3+ promotions, no regime_change evidence" drift
check §13 references — a real regime shift (firmware update, new device behavior
pattern) is the one legitimate explanation the autotuner's drift-flag logic checks for
before treating a trending series of promotions as suspicious.

### 1d. `population_priors`: cold-start fallback — writer built 2026-09-16

**File:** `src/argus/graph/schema.sql` (`population_priors` table, keyed by
`device_type` not `device_id`). Intent, per the schema's own comment: a device with
too little history of its own seeds from a pooled prior built from *other* devices of
the same type — but only from devices with "a currently-clean backtest history"
(`contributed_by_json` records which device_ids fed the pool, so a later-found-
compromised contributor's influence can be identified and the pool rebuilt without it).

**Fallback is a hard replace, not a weighted blend**: `_seeded_model()`
(`baseline/engine.py:300-311`) looks up a `population_priors` row for
`(device_type, metric, hour)`; if one exists, the device's brand-new posterior
hyperparameters are initialized directly from that row's own saved hyperparameters
(e.g. `mu=200.0, kappa=5.0, alpha=10.0, beta=40.0, n=200`) rather than the model's weak
default prior. There's no separate interpolation formula on top of this — once real
per-device observations start arriving, the ordinary sequential conjugate update (§1b)
does the actual blending, since `kappa`/`alpha` accumulate additively: a population
prior seeded with `kappa=5` (5 pseudo-observations) is outweighed by real data quickly;
one seeded with `kappa=200` would take much longer to override. The pseudo-count the
pool was built with *is* the blending mechanism — not a separate weight parameter.

**UPDATE (2026-09-16, same day, user request: "implement it"): the writer now
exists.** `src/argus/ops/population_prior_builder.py` — a new scheduled job (daily,
03:45, `config.yaml`'s `scheduled_jobs.scheduler.population_prior_builder`) — pools
real per-device `device_baselines` posteriors into `population_priors` rows. Eligible
contributors: a device's own (metric, hour, model_kind) posterior must have
`n >= 20` real observations (same "is this enough real data" bar as the autotune
Wilson gate's `_MIN_TRIALS_FOR_LOOSENING`), and the device must be **currently
clean** — its most recent real decision must not be SUSPICIOUS/HIGH/CRITICAL, the
exact same check `BaselineEngine.is_learning_paused()` already used for a different
purpose, reused rather than re-invented. At least 2 eligible contributors are
required per group (matching `live_engine.py`'s own `_PEER_DEVIATION_MIN_PEERS`
precedent) — a lone device isn't a "population."

**Pooling math, per model kind** (honest first-pass, not yet empirically tuned):
Gaussian pools contributors' own `mu` (arithmetic mean) and implied variance
(`beta/alpha`, mean of implied variances — a documented simplification that
understates true between-device variance), rebuilt at a **fixed, modest**
pseudo-count (`kappa=5.0, alpha=10.0`, matching this codebase's own one existing
reference data point) so the pool stays a genuinely weak prior a new device's real
data quickly outweighs. Beta pools the mean ratio, rebuilt at a fixed total
pseudo-count of 10. Poisson pools the mean rate, rebuilt at a fixed pseudo-exposure
of 5. Markov (the one case where summing is the mathematically natural operation,
since the prior IS a Dirichlet count table) sums contributors' real transition
counts directly, then uniformly scales down if the total exceeds a cap (50), so a
device-type with many long-lived contributors doesn't end up with an oversized,
hard-to-override prior.

**A group that drops below the contributor minimum on rebuild has its stale row
DELETED, not left behind** — this module's own test suite caught the naive version
(silently skip, leave the old row) as a real bug before it ever shipped: the schema's
own "rebuilt without them" promise means removed, not just excluded from future
updates.

**Not built** (documented, not silently omitted): the two-tier "rare/attack-shaped
states pool GLOBALLY instead of per-device-type" design `baseline/engine.py`'s own
unused `_GLOBAL_POOL_STATES`/`_GLOBAL_POOL_DEVICE_TYPE` constants sketch — re-reading
that comment while building this writer, the actual per-state blending mechanics were
never fully specified, and inventing that design silently would be a real,
undocumented judgment call rather than an implementation of an existing spec.
Single-tier (per-device-type only, matching what `_load_population_prior()` already
reads) is what's actually built. See `tests/test_argus_population_prior_builder.py`
for the full test coverage (27 checks, including a closed-loop test confirming a
brand-new device actually inherits a freshly-built pool through the pre-existing
`_seeded_model()` read path, not just independently-correct writer/reader halves).

---

## 2. Evidence weighting: confidence × freshness decay

**File:** `src/argus/evidence/model.py`. Every `Evidence` object carries a `confidence`
field (`0.0 <= confidence <= 1.0`, validated at construction) and a fixed `timestamp`.
Its usable weight in any downstream calculation is never the raw confidence — it's
confidence multiplied by a **freshness** factor computed at read time:

```python
def effective_weight(self, freshness: float = 1.0) -> float:
    return self.confidence * freshness
```

Freshness is a **linear decay from 1.0 to 0.0 across a TTL window**, computed in
`src/argus/hypotheses/engine.py`:

```python
_DEFAULT_TTL_SECONDS = 600        # 10 minutes, most evidence types
_REPUTATION_TTL_SECONDS = 86400   # 24 hours, reputation-family evidence only

def compute_freshness(ev, now):
    age = now - ev.timestamp
    ttl = _REPUTATION_TTL_SECONDS if ev.independence_family == "reputation" else _DEFAULT_TTL_SECONDS
    if age >= ttl:
        return None            # dropped entirely -- too old to matter at all
    return max(0.0, 1.0 - (age / ttl))
```

Plain English: a piece of evidence's influence fades linearly over its TTL window, not
a step function — a signal 5 minutes old (half the default 10-minute TTL) contributes
at half its raw confidence, not its full confidence. `reputation`-family evidence gets
a 144x longer TTL (24h vs 10min) because a threat-intel verdict about a domain doesn't
go stale the way a live traffic-rate anomaly does. Anything past its TTL is filtered
out before any hypothesis ever sees it (`score_evidence()`), not merely down-weighted
to near-zero — a design choice that keeps stale evidence from ever contributing even a
token nonzero amount to a corroboration count.

---

## 3. Independence families: the corroboration-counting rule

Full family-membership table already lives in `ARGUS_ARCHITECTURE.md` §8 ("Layer 1 —
independence families") — this section is the arithmetic underneath that table.

**File:** `src/argus/hypotheses/independence.py`. The registry
(`INDEPENDENCE_FAMILY_MAP: Dict[str, str]`) maps every evidence type to exactly one
family string. Counting corroboration is **not** a weighted sum, an average, or a
Bayesian combination — it's the cardinality of a set:

```python
def count_independent_families(evidence_types) -> int:
    families = frozenset(family_for(t) for t in evidence_types)
    return len(families)
```

5 `dns_entropy` items and 1 `dns_dga_burst` item are all `"dns_behavior"` and count as
**exactly 1** independent source — volume within a family buys nothing. This is the
mechanism that makes the decision engine's "≥2 independent families" bar (§7 below)
mean what it says: two genuinely different *kinds* of evidence, not two observations of
the same kind.

`NON_ATTACK_FAMILIES` (`local_context`, `novelty_context`, `peer_cohort_deviation`,
`ml_anomaly`, `policy`, `baseline_deviation`, `regime_change`, `sequence_dynamics`) are
excluded from this count entirely before it runs — each can produce its own hypothesis
verdict, but none can ever supply one of the two required independent sources for
HIGH/CRITICAL. `sequence_dynamics` (the Markov surprise evidence types) is the one
family explicitly documented as a **permanent** exclusion, by design — it's meant to
act as a severity multiplier on an already-corroborated verdict, never a corroborating
source in its own right.

**Destination-linkage stripping** (`src/argus/decision/engine.py:280-324`, the
"Gap-64 fix"): before the family count runs, evidence carrying a real destination is
only kept if that destination matches one of the *winning hypothesis's own* relevant
destinations:

```python
attack_evidence = [e for e in attack_evidence
    if e.destination_id == NO_DESTINATION or e.destination_id in hyp_destinations]
```

Evidence with no destination at all (`NO_DESTINATION` sentinel) always survives this
filter — the check only ever *removes* candidate corroboration, never adds it. This is
what stops an unrelated domain's evidence item from padding out the independent-source
count for a hypothesis about a completely different destination.

---

## 4. Hypothesis scoring: the discrete ladder

Full per-hypothesis requirement table (what evidence each one needs, exact literal
thresholds for 3.0/4.0) already lives in `ARGUS_ARCHITECTURE.md` §8 — this section is
the shared mechanics every hypothesis in that table is built from.

**There is no continuous score and no numeric fusion formula.** Every attack
hypothesis's `evaluate()` (`src/argus/hypotheses/engine.py`) is a small rule-based state
machine that returns exactly one of **four fixed values**: `0.0` (its required evidence
is entirely absent — hard gate), `2.0` (bar just cleared), `3.0` (a genuinely strong
signal is present), `4.0` (strong signal plus a second confirming condition, usually
reputation-tier or a second corroborating evidence type). The base class accumulates two
running counters while scanning matched evidence:

- `strong_score` — incremented (usually `+= 1.0`, sometimes a fractional bump) for each
  condition that makes the hypothesis *more* confident (a second signal type present, a
  higher raw value, more distinct provenance subtags).
- `contradicting_score` — incremented (almost universally `+= 1.0`) whenever
  `rep_vector.tier` (or the hypothesis's own `_effective_rep_tier()`) lands in `{0,1,2}`
  (local/trusted/known-infrastructure) — reputation acts as a **veto/dampener** on the
  ladder, never a bonus multiplier.

A representative example, `DNSTunnelingHypothesis.evaluate()`:

```python
score = 2.0
if self.strong_score > 0 and self.contradicting_score == 0:
    score = 3.0
if self.strong_score > 0.5 and self.contradicting_score == 0 and eff_tier == 4:
    score = 4.0
```

Every other attack hypothesis (`NETWORK_INTRUSION`, `DGA_BOTNET_C2`,
`DATA_EXFILTRATION`, `C2_BEACONING`, `DNS_COVERT_TUNNELING`, `COORDINATED_TARGETING`,
`CONNECTION_ABUSE`, `DNS_POLICY_BYPASS`/`DNS_EVASION`/`DNS_ATTRIBUTION_GAP`,
`SIGNATURE_MATCHED_THREAT`, `PEER_COHORT_DEVIATION`) follows this same
required→strong/contradicting→ladder shape, differing only in which literal evidence
values gate `strong_score` (see `ARGUS_ARCHITECTURE.md` §8's table for the per-hypothesis
specifics).

**`_effective_rep_tier()`** (`hypotheses/engine.py:118-168`): `pipeline.py` computes only
*one* `ReputationVector` per device per cycle, for whichever destination scored highest
that cycle — structurally unrelated to any individual hypothesis's own evidence. Every
hypothesis therefore compares `rep_vector.domain` against its *own* evidence's real
destination; if both sides carry a destination and provably differ, the tier used for
that hypothesis's own scoring is forced to a neutral 3 ("unclassified") regardless of
what the device-level `rep_vector.tier` actually was.

**Multi-hypothesis combination — winner-take-all, not a sum:**

```python
for h in self.attack_hypotheses:
    score = h.evaluate(...)
    if score > best_attack_score:
        best_attack_score = score
        best_attack = h
```

(`HypothesisEngine.evaluate_all()`, `hypotheses/engine.py:854-895`.) The device's
"attack score" for the cycle is the single highest-scoring attack hypothesis — a max,
never a sum, average, or Bayesian posterior — and the same max-take-all runs
independently over the benign hypotheses to produce "benign score." The decision engine
(§7) then compares these two maxima against each other.

**`hypothesis_weight` — the one place a real average exists**
(`decision/engine.py:263-271`), and it is *not* the hypothesis ladder score:

```python
_PARTIAL_SUPPORT_FAMILIES = frozenset({
    "dns_behavior", "tls_fingerprint", "network_behavior",
    "data_transfer_pattern", "reputation", "direct_observation",
})
partial_support = [e for e in ev_store if family_for(e.evidence_type) in _PARTIAL_SUPPORT_FAMILIES]
hypothesis_weight = sum(_safe_confidence(e.confidence) for e in partial_support) / max(1, len(partial_support))
```

This is the arithmetic mean of `confidence` across every partial-support-family
evidence item in the cycle, independent of which hypothesis won — used only to compute
`evidence_verification_required` (line 271, gates whether Layer 3's LLM review is asked
to double-check this alert), never to pick the decision state itself.

---

## 5. Reputation tiering

**File:** `src/intelligence/reputation/classifier.py`, `ReputationClassifier.classify()`.
Six tiers, in order of trust (full narrative table already in
`ARGUS_ARCHITECTURE.md` §8's decision-tree section — this is the exact classification
rule that assigns one):

```python
tier = 3   # default: unclassified, neutral

# Tier 0a -- raw private/link-local/loopback IP (added 2026-09-15, closing a real gap:
# the tier-0 docstring "promises RFC1918 coverage" but the OLD rule only matched domain
# SUFFIXES -- a bare private IP like "192.168.1.41" fell through to tier 3 before this)
if ip_address(domain) is private/link_local/loopback:
    tier = 0

# Tier 0b -- domain suffix match (.box, .local, fritz.box), boundary-safe (not .endswith())
elif domain ends with one of {".box", ".local", "fritz.box"}:
    tier = 0

# Tier 1 -- hardcoded trusted-vendor allowlist
elif domain in {"apple.com","microsoft.com","google.com","icloud.com","windowsupdate.com"}:
    tier = 1

# Tier 2 -- hardcoded CDN/cloud allowlist, or a "known-safe" ASN owner
elif domain in {"doubleclick.net","cloudflare.com","amazonaws.com","azure.com",
                 "akamaiedge.net","googlesyndication.com"}:
    tier = 2
elif is_known_safe_asn_owner(asn_owner):   # ASN org name contains "telegram"/"verisign",
    tier = 2                               # or utils.is_cloud_cdn_provider_org()

# Tier 4/5 -- reputation-signal promotion, ONLY if still 3 (0/1/2 are a floor, never
# re-escalated by a reputation hit once assigned)
else:
    confirmed_ioc = vt_score > 2.0 or ti_score > 2.0 or abuse_score >= 4.0
    weak_signal = vt_score > 0.0 or ti_score > 0.0 or abuse_score > 0.0
    if confirmed_ioc:
        tier = 5
        verified_ioc = ti_score > 2.0   # verified_ioc is ONLY ever true via the TI path
    elif weak_signal:
        tier = 4
```

`confirmed_vt_ti_floor` (2.0) and `confirmed_abuse_floor` (4.0) are themselves two of
the four live-tunable autotune parameters (`reputation_tier_suspicious_floor`/
`reputation_tier_high_floor` — see §13). Note the asymmetry in what counts as
"confirmed": VT/TI need to *exceed* 2.0, AbuseIPDB needs to *reach* 4.0 — and AbuseIPDB
alone can never set `verified_ioc=True`, only the curated threat-intel feed path can.
`source_confidence` is set to `"high"` for tiers `{0,1,5}` and `"medium"` otherwise
(a display-only field, not consumed by any scoring formula).

---

## 6. Threat-intel combination (VT / AbuseIPDB / TI)

**File:** `src/core/pipeline.py` (computation), `src/intelligence/threat_intel.py`
(per-source scoring). Three independent sources, each producing a risk contribution
capped to **[0, 4.0]**:

```python
# AbuseIPDBClient.get_live_risk() -- threat_intel.py
abuse_risk = min((abuseConfidenceScore / 100.0) * 6.0, 4.0)
# flat 4.0 if the IP matches the cached blacklist snapshot or a configured honeypot IP

# VirusTotalClient.risk_contribution() -- threat_intel.py
vt_risk = min(((malicious_count + suspicious_count * 0.5) / total_engines) * 6.0, 4.0)
# flat 4.0 if the destination IP is a configured honeypot; takes max(ip_risk, domain_risk)

# ti_risk -- pipeline.py, curated feed match (Feodo/ThreatFox/OTX)
ti_risk = confidence * 4.0   # confidence field from the matching feed entry, default 0.8
```

**Combined into one number by a plain max, not a weighted sum:**

```python
reputation_value = max(ti_risk, abuse_risk, vt_risk)
confidence = 0.95 if reputation_value >= 4.0 else 0.8
```

A single `Evidence(type="reputation", value=reputation_value, confidence=confidence)`
item is created, attributed to whichever specific domain/IP actually produced the max
(tracked as a running max across all three source checks) — the three sources are
never blended into a composite score; the worst single signal wins outright and the
other two are discarded once the max is taken.

**Caching/staleness** (all in `threat_intel.py`): AbuseIPDB and VirusTotal per-IOC
results cache for **86400s (24h)** on a real hit, **3600s (1h)** on a failed/empty
lookup (a negative cache, so a transient API outage doesn't get treated as "confirmed
clean" for a full day). Curated static feeds (Feodo/ThreatFox/OTX) cache **3600s**
each. Pi-hole's gravity-domain cache is **21600s (6h)**. VirusTotal's worker is rate-
limited to one call per **16s** with a **950/day** cap; a transient VT error itself
caches for only **60s** so an outage doesn't get treated as a long-lived negative
result.

---

## 7. Decision engine: risk number, hard-stops, hypothesis_weight

Full hard-stop table and the full decision-tree flowchart (with every literal
confidence value) already live in `ARGUS_ARCHITECTURE.md` §8 — this section covers the
one piece of arithmetic that table doesn't spell out: **how a decision's category
(BENIGN/ANOMALOUS/SUSPICIOUS/HIGH/CRITICAL) becomes the 0–10 "risk" number shown in the
console and alerts.json.**

There is no numeric fused risk score computed inside the decision engine itself
(`src/argus/decision/engine.py`) — `DecisionState` is a plain enum
(`BENIGN`/`ANOMALOUS`/`SUSPICIOUS`/`HIGH`/`CRITICAL`), chosen by which branch of the
decision tree fires, not by comparing a continuous score against cutoffs. Each branch
also sets a **hardcoded literal** `threat_confidence` (0.99, 0.95, 0.85, 0.75, 0.70,
0.45, 0.40, 0.10, or 0.0 — see `ARGUS_ARCHITECTURE.md`'s decision-tree diagram for which
branch sets which value). The familiar 0–10 "risk" number is a pure linear rescale of
that literal, computed downstream in `core/pipeline.py`:

```python
risk = decision["threat_confidence"] * 10.0   # "Map to old 0-10 scale temporarily for metrics"
```

So a `risk` of 8.5 in a real alert always traces back to one specific hardcoded branch
confidence (0.85 — the `hypothesis_high`/`tier5_corroborated` branch), not to any
continuous statistical computation. **This is a deliberately coarse, discrete scale, not
a calibrated probability** — see §12 for the actual (separate, not-yet-load-bearing)
calibration machinery. `core/pipeline.py` floors a persistence-escalated alert's
`threat_confidence` at 0.55 specifically so it stays visibly distinguishable from every
genuine-HIGH branch's own literal (0.75-0.99), never accidentally reading as more
serious than a real corroborated hit (see §14).

**Hard-stop corroboration arithmetic** (`decision/engine.py:363-370`), the exact rule
`ARGUS_ARCHITECTURE.md`'s table summarizes as ">=1 independent family (excluding X)":

```python
corroborating_sources = len(independence_families - rule.own_families)
if corroborating_sources >= 1 and attack_score > benign_score:
    # -> full corroborated CRITICAL confidence
else:
    # -> demoted to HIGH, the rule's own "uncorroborated" confidence value
```

`own_families` (e.g. `{"signature_match"}` for the `confirmed_exploit` rule) is
subtracted from the independence-family set *before* counting — a 2026-09-12 bugfix
closing a real bug where a lone Suricata match satisfied its own corroboration
requirement by counting itself as the "second" source.

---

## 8. DGA & domain-entropy detection

**File:** `src/utils.py`. Two primitives, both plain information-theoretic measures —
no dictionary lookup, no n-gram language model, no trained classifier at this layer:

```python
def entropy(text):
    """Shannon entropy, in bits, of the character distribution."""
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    ent = 0
    for v in freq.values():
        p = v / len(text)
        ent -= p * math.log2(p)
    return ent

def vowel_ratio(text):
    vowels = sum(1 for c in text if c in "aeiou")
    return vowels / max(len(text), 1)
```

**Worked example** — compare a real word to a DGA-shaped string of the same length:
`entropy("dropbox")` ≈ 2.52 bits (7 letters, several repeats, low uncertainty per
character); a random-looking same-length string like `"xk4qz7p"` scores close to
`log2(7)` ≈ 2.81 bits (every character close to equally likely) — DGA detection
leans on exactly this gap, combined with vowel scarcity (a pronounceable word has
vowels roughly evenly spaced; a DGA string usually doesn't).

**`suspicious_dga(domain)`** (`utils.py:626-660`) — the actual per-domain classifier,
length-bucketed (short domains and long domains use different thresholds, since entropy
is a noisier signal on very short strings):

```python
if domain ends with .arpa/.local/.lan or is a CDN/cloud domain:
    return False   # exempt up front, never scored

left = first_label(domain)
n = len(left)

if 6 <= n <= 11:
    vr = vowel_ratio(left); ent = entropy(left)
    digit_ratio = digit_count(left) / n
    return (vr <= 0.12 and ent > 2.6 and digit_ratio < 0.40) or \
           (digit_ratio >= 0.45 and ent > 3.0)

if n < 12:
    return False   # too short below 6 chars, or between 6-11 already handled above

# n >= 12
ent = entropy(left); vr = vowel_ratio(left); dr = digit_count(left) / n
return ent > 3.2 and vr < 0.25 and dr < 0.75
```

**Burst-level scoring** (feeds the `DGA_BOTNET_C2` hypothesis via `dns_dga_burst`
evidence, `src/intelligence/detectors/threat_signals.py:140-152`):

```python
sd = suspicious_domain_count_this_window
if sd >= 15:
    confidence = min(1.0, 0.6 + sd / 50.0)          # strong burst
elif sd >= 5 and entropy_avg > 3.5:
    confidence = 0.6                                 # moderate burst, flat confidence
elif not is_telemetry and dga_score > 0.40:
    confidence = min(1.0, dga_score)                 # ML-classifier-only path
```

`dga_score` here is an optional ML classifier output, used only as a fallback when the
domain-count/entropy heuristics above don't already trigger — the primary path is the
deterministic entropy+ratio rule, not a model.

---

## 9. DNS tunneling / covert-channel detection

**File:** `src/extractors/dns_features.py` (feature computation),
`src/intelligence/detectors/threat_signals.py` (evidence emission).

Four independent signals, each with its own literal threshold, any one of which can
raise `dns_tunnel_v2` evidence:

| Signal | Formula / threshold |
|---|---|
| **Encoded/long label** | subdomain first-label length `> 28` chars AND `entropy(label) > 3.6`, minus CDN/telemetry exemptions |
| **Subdomain fanout** | `>= 8` distinct subdomains sharing one eTLD+1 parent within the window; confidence gets a small bonus (`min(0.3, max(0, avg_label_entropy - 3.0) * 0.2)`) for genuinely high-entropy fanout children, not just high fanout count |
| **TXT/NULL/ANY query-type ratio** | `txt_null_count / total_queries > 0.15` |
| **Suspicious TLD ratio** | queries to `{.top, .xyz, .biz, .cc, .cfd, .buzz, .gq, .tk, .work, .rest, .country, .stream, .icu, .click, .live}` `/ total > 0.15` |

Each signal's confidence is its own literal formula, e.g. the encoded-label path:
`min(1.0, 0.5 + tunnel_domain_count * 0.15)`; the ratio-based ones are simply
`min(1.0, ratio * 2.0)` — a ratio crossing 0.5 alone already saturates confidence to 1.0.

**Hypothesis scoring** (`DNSTunnelingV2Hypothesis`) requires **2+ distinct** of these
four signal categories (tracked via each evidence item's own provenance subtag, not
raw hit count) to reach its 3.0 rung, and a 0.85+ confidence on top of that plus
reputation tier 3/4 to reach 4.0 — deliberately requires a *combination* of tunneling
signatures, not one strong hit alone, since any single one of the four (an unusually
long subdomain, a TXT-heavy resolver, one suspicious-TLD lookup) has a plausible benign
explanation on its own.

---

## 10. Peer-cohort deviation

**File:** `src/argus/ops/live_engine.py`, `_inject_peer_deviation_evidence()`. This is
the newest, most explicitly-flagged-as-unvalidated heuristic in the pipeline (see its
score cap below) — **not** a z-score or percentile-rank comparison, a simple
ratio-to-cohort-mean test:

```python
_PEER_DEVIATION_WINDOW_SECONDS = 7 * 86400      # trailing 7 days
_PEER_DEVIATION_MIN_PEERS = 2                   # need >=2 OTHER same-device_type devices
_PEER_DEVIATION_MULTIPLIER = 3.0                # this device's own count must be >=3x cohort avg
_PEER_DEVIATION_MIN_ABSOLUTE_COUNT = 5          # ignore trivial small-number swings (1->4 is "4x" but meaningless)

peers = every OTHER device sharing the exact same device_type string
        (excludes empty/"unknown" device_type entirely -- a documented fix after 13
         genuinely-unidentified devices got pooled into one fake cohort)

my_count = distinct destinations this device contacted in the trailing 7 days
if my_count < 5:
    return []   # too small a sample to mean anything, don't even compare

peer_avg = mean(distinct-destination counts across all peers)
if peer_avg > 0 and my_count >= peer_avg * 3.0:
    fire Evidence(type="peer_deviation", confidence=0.6, value=my_count)
```

Plain English: "this device talked to at least 3x as many distinct destinations as the
average device of its own type over the last week, and at least 5 in absolute terms."
Cohort membership is a bare string match on `device_type` (e.g. `"smart_plug"`), not a
behavioral clustering algorithm — two devices with the same type label but genuinely
different real-world usage patterns are treated as the same cohort.

**Deliberately capped at 3.0 (SUSPICIOUS), never reaches HIGH alone**
(`PeerDeviationHypothesis`, `hypotheses/engine.py:795-832`) — the module's own docstring
explains why: unlike `coordinated_targeting`/`fingerprint_campaign`/`dga_seed_campaign`
(which reuse "well-established, low-false-positive correlation concepts"), this is "a
genuinely NEW, unvalidated anomaly heuristic" with no real-world tuning history yet.
Its evidence family (`peer_cohort_deviation`) is also one of the `NON_ATTACK_FAMILIES`
(§3) — it can never itself supply one of the two independent sources another hypothesis
needs to reach HIGH, so the 3.0 cap is enforced twice over: once by the hypothesis's own
ladder logic, once structurally by the independence-family exclusion.

---

## 11. CL-AFPE: Stage 1 hard-stops, Stage 2/3 ML combination, composite trust

**File:** `src/argus/cl_afpe/engine.py` (`ClAfpeEngine`) — the live false-positive
suppression layer (`Layer 2` in `ARGUS_ARCHITECTURE.md` §8; confirmed live on `.94` via
`cl_afpe_engine: argus` in its real `config.yaml`, checked 2026-09-16). Runs on every
alert independently of Layer 1's own verdict.

### 11a. Trust-cache fast path + composite-trust hard gate

A destination first has to be in a plain TTL-based trust cache (14 days,
`TRUST_CACHE_TTL_SECONDS`). As of 2026-09-15, clearing that cache alone is no longer
sufficient — `composite_trust.permits_suppression()` must *also* return True, or the
fast path is abandoned and the full Stage 1/2/3 evaluation below runs instead
(fail-open on any exception in the composite-trust check itself).

### 11b. Stage 1 — 8 hard-stop checks, first match wins

Any one match sets the verdict to `CONFIRMED_THREAT` outright — no scoring, no
combination, a pure OR gate:

```
(0) Layer 1 already said CRITICAL
(1) ti_risk > 2.0
(2) lateral movement across >= 2 distinct targets
(3) malicious JA3/JA4 fingerprint hit
(4) honeypot hit
(5) abuseipdb_risk >= 4.0
(6) outbound_bytes_z > 5.0  AND  outbound_bytes > 2,500,000   (exempting known telemetry/CDN domains)
(7) a local confirmed-intel store match (a prior CONFIRMED_THREAT for this exact target)
```

### 11c. Stage 2 (LightGBM) + Stage 3 (FastEmbed) combination

**File:** `src/argus/cl_afpe/ml_scoring.py`. The two model scores are combined by a
fixed weighted blend, with two special-cased fallback paths:

```python
LGBM_WEIGHT = 0.45
EMBED_WEIGHT = 0.55
NEUTRAL_LGBM_SCORE = 0.50   # "no real Stage 2 signal" sentinel

def combine_scores(lgbm_prob, embed_sim, embed_similarity_threshold):
    if embed_sim is None:
        return lgbm_prob if lgbm_prob is not None else NEUTRAL_LGBM_SCORE
    if lgbm_prob is None:
        lgbm_prob = NEUTRAL_LGBM_SCORE
    if lgbm_prob == NEUTRAL_LGBM_SCORE and embed_sim >= embed_similarity_threshold:
        return embed_sim
    return lgbm_prob * 0.45 + embed_sim * 0.55
```

Three-way branch, not a single formula: embed unavailable → LightGBM alone; LightGBM
genuinely has nothing (sitting at its neutral 0.50 sentinel) *and* embed clears its own
0.82 similarity bar → embed alone; otherwise the weighted blend, with embedding
similarity weighted slightly higher (0.55 vs 0.45).

**Final verdict thresholds** (`DEFAULT_COMBINED_SUPPRESS_THRESHOLD = 0.80`,
`DEFAULT_COMBINED_UNCERTAIN_THRESHOLD = 0.55`, `DEFAULT_EMBED_SIMILARITY_THRESHOLD =
0.82`, all overridable per-device):

```
combined >= 0.80              -> attempt mark_false_positive() -> FALSE_POSITIVE
0.55 <= combined < 0.80        -> UNCERTAIN (published normally, flagged low-confidence)
combined < 0.55                -> CONFIRMED_THREAT, sigma tune-up (tighten sensitivity)
```

The legacy engine (`src/intelligence/fp_engine.py`) implements the exact same weights
and thresholds independently (`_DEFAULT_LGBM_FP_THRESHOLD`/`_DEFAULT_COMBINED_*`,
`fp_engine.py:131-140`) — a deliberately mirrored, not shared, implementation (see
`ARGUS_ARCHITECTURE.md` §8's Layer 2 description for why the two engines don't share
code).

### 11d. Composite trust — a decayed bounded-increment counter, not a Bayesian posterior

**File:** `src/argus/cl_afpe/composite_trust.py`. A six-dimensional key (`device x
behavior_fingerprint x destination_class x hypothesis x evidence_family x regime`).
Despite the name, this is **not** a moving average or a Beta-distribution posterior —
it's a flat step increment with linear time-decay:

```python
_TRUST_INCREMENT = 0.15          # bounded step per confirming observation
_TRUST_DECAY_PER_DAY = 0.05      # erodes if not reinforced
_SUPPRESSION_TRUST_FLOOR = 0.6   # minimum per-family trust to count as "corroborating"
_MIN_DISTINCT_FAMILIES_TO_BUILD_TRUST = 2

# on each new corroborating observation for an existing tuple:
days_elapsed = max(0.0, (now - last_updated) / 86400.0)
decayed = max(0.0, trust_value - _TRUST_DECAY_PER_DAY * days_elapsed)
new_trust = min(1.0, decayed + _TRUST_INCREMENT)
```

Plain English: `trust_new = min(1.0, max(0.0, trust_old − 0.05 × days_since_last_seen) +
0.15)`. Every corroborating observation bumps trust by a flat +0.15 (capped at 1.0), but
first erodes whatever time has passed since the last observation at 0.05/day — a device/
destination/hypothesis combination seen once and never again slowly forgets that single
observation rather than remembering it forever.

**Suppression gate — a counting rule, not a combined score:**

```python
def permits_suppression(...):
    trusts = per-family decayed trust values for this exact 6-dimensional tuple
    qualifying_families = {family for family, trust in trusts if trust >= 0.6}
    return len(qualifying_families) >= 2
```

Suppression is only permitted once **at least 2 distinct evidence families** have each
*independently* decayed-trust past 0.6 for the exact same tuple — structurally the same
"count distinct families, don't sum them" pattern as the independence-family gate in
§3, applied here to trust-building instead of hypothesis corroboration. This is what
prevents one repeatedly-tripped weak signal from ever building enough trust alone,
regardless of how many times it fires.

**Stage 1b — local-origin auto-corroboration** (`engine.py:894-960`, 2026-09-15):
triggers only when the destination is itself one of the network's own already-
registered devices AND both `ti_risk == 0.0` and `abuseipdb_risk == 0.0` (exact zero,
not merely low) — never auto-resolves on first sighting, accumulates composite-trust
corroboration per cycle via the same +0.15/decay mechanism above and only resolves
`FALSE_POSITIVE` once `permits_suppression()` actually clears.

**Sigma-shift widening/tightening** — a separate, simpler mechanism from composite
trust, adjusting a device's own detection sensitivity directly:

```python
# CONFIRMED_THREAT (tighten):  new = max(current - 0.50, -1.5)
# FALSE_POSITIVE (widen/correct): new = min(current + 0.25, 2.0)
```

Deliberately asymmetric: a confirmed threat tightens twice as fast per step (−0.50) as
a correction widens (+0.25) — sharpening sensitivity is cheap, relaxing it is
deliberately slower.

---

## 12. Confidence calibration — collected, not yet load-bearing

**File:** `src/intelligence/confidence_calibration.py` /
`src/intelligence/fp_engine.py`'s `_apply_calibration()`. An online per-confidence-
bucket Beta-Binomial posterior (separate benign/malicious tracks) has been collecting
real outcome data since 2026-09-04, and `fp_engine.py` loads a piecewise-linear
isotonic-regression calibration curve from `fp_calibration.json` if one exists. **This
number is explicitly not used for any branching decision** — `fp_engine.py`'s own
comment: *"Deliberately NOT used for the suppress/uncertain/threat branching above...
purely additive to the audit trail."* `calibrated_confidence` is written into every
alert's `fp_verdict` for future analysis, and the CL-AFPE (Argus) port doesn't even
carry the field forward — it's always `None` there. The only place real veto logic
lives on top of a proposed verdict today is the rule-based `DeterministicValidator`
(§ below), which is a checklist gate, not a calibrated probability model.

**`DeterministicValidator.validate()`** (`src/argus/llm_review/validator.py:81-165`) —
gates the Layer 3 LLM's proposed "benign" reclassification (see
`ARGUS_ARCHITECTURE.md` §8, Layer 3). Rejects "benign" outright, regardless of the
model's own stated reasoning, if any of: a `reputation` evidence item with `value >=
4.0` exists (a real IOC); the reasoning cites "telemetry" while `reputation` evidence
still shows `value >= 3.0`; the persisted `hee_decision_path` was already one of
`{hard_stop, tier5_confirmed, tier5_corroborated, hypothesis_high}` (§7's strongest
branches); attack-shaped evidence types are present in `hee_evidence_types`; the
destination isn't trusted/familiar (reputation tier untrusted AND
`baseline_familiarity < 0.6`); real candidate hypotheses went unaddressed; supporting
evidence is empty; or the model's reasoning cites the exact original risk number back
verbatim (circular reasoning, not independent judgment).

---

## 13. Autotune engine: the Wilson-bound safety gate

Full lifecycle sequence diagram (propose → canary → backtest → promote/rollback) and
the 3-tier device/category/global resolution already live in `ARGUS_ARCHITECTURE.md`
§5. This section derives the one piece of real statistics in the whole pipeline: **why
20 trials isn't enough to loosen a threshold, but ~22 is.**

**The problem this solves**: a scoped (device- or category-level) proposal to *loosen*
a detection parameter (make it less sensitive) is inherently riskier than a global
change — it affects fewer devices, so there's less real traffic to validate it against.
A naive "N trials, all passed" rule is a bad safety gate on its own: 3-for-3 (100%) is
weak evidence; 18-for-20 (90%) might genuinely be better evidence than 3-for-3 despite
the lower raw rate. The Wilson score interval is the standard statistical tool for
exactly this — it answers "given `hits` successes out of `n` trials, what's a
conservative (95%-confidence) *lower bound* on the true success rate?", automatically
discounting small samples more heavily than large ones.

**File:** `src/argus/autotune/engine.py:115-130`:

```python
_WILSON_Z_95 = 1.959963984540054   # standard normal quantile for a 95% two-sided CI

def wilson_lower_bound(hits: int, n: int, z: float = _WILSON_Z_95) -> float:
    if n <= 0:
        return 0.0
    phat = hits / n
    denom = 1.0 + z * z / n
    center = phat + z * z / (2 * n)
    margin = z * ((phat * (1 - phat) / n + z * z / (4 * n * n)) ** 0.5)
    return max(0.0, (center - margin) / denom)
```

This is the textbook Wilson score interval lower bound:

```
                p̂ + z²/2n − z·√(p̂(1−p̂)/n + z²/4n²)
Wilson_lower = ────────────────────────────────────────
                          1 + z²/n
```

where `p̂ = hits/n` is the raw observed rate and `z ≈ 1.96` is the 95%-confidence
quantile. Unlike a naive `p̂ - margin` (a normal/Wald interval), the Wilson interval
doesn't require re-centering by hand for small `n` and never produces a bound outside
`[0, 1]` even at extreme observed rates.

**Worked example — a perfect record at increasing sample sizes** (computed directly,
not estimated):

| n (all hits) | `wilson_lower_bound(n, n)` |
|---|---|
| 15 | 0.7961 |
| 18 | 0.8241 |
| 20 | 0.8389 |
| **22** | **0.8513** |
| 25 | 0.8668 |
| 29 | 0.8830 |

A perfect 100% raw record needs **22 trials**, not 20, before its Wilson lower bound
actually clears the 0.85 floor the autotuner requires (`_TUNE_LOOSEN_WILSON_FLOOR =
0.85`). This is exactly the effect the gate is designed to produce: a 20-trial perfect
record (0.8389) still reads as "probably good, not yet certain enough" — the coarse
`_MIN_TRIALS_FOR_LOOSENING = 20` pre-filter is a cheap early exit, not itself the real
bar; the Wilson bound is the actual statistical gate applied on top of it.

**The full gate, both directions** (`backtest_job.py:263-282`):

```python
if worst_rate < 0.70:                                    # _TUNE_TIGHTEN_FLOOR
    tighten immediately -- no sample-size minimum at all,
    a single miss below 70% raw detection rate is enough
elif allow_loosen:
    if any class has < 20 trials:
        do nothing -- not even evaluated for loosening yet
    elif worst_rate < 1.0:
        do nothing -- must be a literal 100% raw rate across every attack class
    elif min(wilson_lower_bound(hits, n) for every class) >= 0.85 and no drift detected:
        loosen
```

The asymmetry is deliberate and load-bearing: **tightening has no statistical gate at
all** (fail-safe toward more scrutiny on thin evidence), while **loosening requires
both a perfect raw record and a real statistical floor on top of it** — a single miss
anywhere, at any sample size, blocks loosening outright; passing everything still isn't
enough until the Wilson bound itself clears 0.85.

**Trust-radius cap** (`_TRUST_RADIUS_MAX_STEPS = 2.0`) — a second, independent failsafe
layered on top of the Wilson gate, not a replacement for it: even a statistically-
justified loosening is rejected if it would move a scope more than 2 `max_step`s
looser than its own parent tier (device looser than category/global, or category
looser than global):

```
divergence = (new_value - parent_value) * direction   # direction: +1 or -1, per-parameter
reject if divergence > 2.0 * max_step
```

Only enforced in the less-sensitive direction — tightening past the parent tier is
never capped, matching the same fail-safe asymmetry as the Wilson gate itself.

**Retroactive circuit-breaker** (`check_retroactive_misses_and_rollback()`,
`backtest_job.py:501-593`) — the failsafe that runs *between* backtest cycles, not at
proposal time: scans the last 7 days of real `suricata_signature_match` evidence for
any hit whose confidence falls in the band between a loosened scope's own value and its
parent's stricter value (i.e. a real signature match that *would* have cleared the
parent's bar but not this scope's own, looser one). Any such near-miss cross-referenced
against a real `CONFIRMED_THREAT` decision within the hard-stop freshness window
triggers an immediate, unconditional rollback — no canary, no confirming backtest, no
operator approval. This is the one mechanism that can undo a promoted change purely
because real subsequent evidence proved it wrong, independent of whether the original
statistical justification was sound at promotion time.

---

## 14. IPS containment ladder & persistence escalation

**File:** `src/mitigation/ips.py`, `mitigate()`. Three escalating actions, each with its
own independent gate — not a single risk-score ladder, a mix of categorical and numeric
gates:

| Action | Gate |
|---|---|
| `dns_block` (Pi-hole) | `decision_state in (HIGH, CRITICAL)` — categorical, no numeric risk floor |
| `router_isolate` | `risk_score >= 8.5` **OR** `lateral_threat` (lateral movement across `>=2` distinct targets, or a honeypot hit) |
| `tarpit` (Layer-2 ARP/NDP) | `risk_score >= 9.0` **OR** `lateral_threat` — a stricter, separately-gated numeric floor than router isolation, one full risk point higher |

Since `risk = threat_confidence * 10.0` (§7), `risk_score >= 8.5` means
`threat_confidence >= 0.85` — exactly the `hypothesis_high`/`tier5_corroborated`
branch's own literal confidence, so in practice router isolation's numeric gate and
Layer 1's own "genuinely corroborated HIGH" bar are the same threshold expressed in two
different units.

**IPv6 dual-stack coverage**: once router isolation fires (the 8.5 gate), the tarpit is
armed automatically alongside it *regardless* of the tarpit's own stricter 9.0 gate —
Fritz!Box's `DisallowWANAccessByIP` only blocks IPv4, so without this, a router-isolated
device below the tarpit's own 9.0 floor would sit isolated on IPv4 with zero IPv6
containment.

**Persistence escalation** (`core/pipeline.py:1964-2022`) — a SUSPICIOUS decision whose
`primary_sig` stays identical across cycles for `>= suspicious_escalation_seconds`
(default **600s / 10 min**) gets promoted to HIGH:

```python
if persisted_for >= 600:
    decision["state"] = HIGH
    decision["escalated_via_persistence"] = True
    decision["threat_confidence"] = max(decision["threat_confidence"], 0.55)
```

**But this promoted state is downgraded again before it can authorize containment or a
Telegram send** (`core/pipeline.py:2719-2721`):

```python
containment_decision_state = decision["state"]
if decision.get("escalated_via_persistence"):
    containment_decision_state = SUSPICIOUS   # downgrade, for authorization purposes only
```

The device's alert still *displays* as HIGH (with an explanation suffix showing how
long it persisted), but the separate `containment_decision_state` used for the whole
IPS ladder above and for Telegram gating (§15) is quietly SUSPICIOUS — a persistence-
escalated alert can be seen but cannot trigger a Pi-hole block, router isolation, or a
page. The rationale, verbatim from the code's own comment: *"persistence of one weak
signal is not the same as a second independent one."*

---

## 15. Telegram gating: IncidentTracker

**File:** `src/core/incident_tracker.py`. The final gate before a real Telegram send,
after every decision/CL-AFPE/containment computation above has already run:

```python
telegram_worthy = containment_decision_state in (HIGH, CRITICAL)   # note: the
    # DOWNGRADED state from §14 -- a persistence-escalated HIGH never counts here
send_gate = not fp_verdict["suppress"] and telegram_worthy and incident_notify.should_notify
```

`IncidentTracker.should_notify(key, severity_state, now)` — `key` is a device+target+
signature composite (so the same device tripping two different signatures are tracked
as two separate incidents). Config: `incident_grouping_window_seconds` (default **1800s
/ 30 min**), `incident_update_min_interval_seconds` (default **900s / 15 min**).

```python
_SEVERITY_RANK = {"SUSPICIOUS": 0, "ANOMALOUS": 0, "BENIGN": 0, "HIGH": 1, "CRITICAL": 2}

if no existing incident record, or last occurrence was > 1800s ago:
    -> NEW incident, occurrence_count reset to 1, notify=True   # "first occurrence"

else:
    occurrence_count += 1
    escalated = current_severity_rank > rank_at_last_actual_notification
    due_for_update = (now - last_notified_at) >= 900

    notify = escalated or due_for_update
```

Three, and only three, conditions ever produce a real Telegram send for an ongoing
incident: it's genuinely new (or the previous sighting was long enough ago to treat as
new); its severity rank has *increased past the rank that was actually notified on
last time* (not merely higher than the previous cycle — re-escalating from HIGH back to
HIGH after a dip doesn't re-notify); or at least 15 minutes have passed since the last
notification for this same still-open incident (a periodic "still ongoing" update).
Every call still records the occurrence (`occurrence_count`, `last_seen`) regardless of
whether it returns `should_notify=True` — only the Telegram *send* is gated by this;
`alerts.json` and CL-AFPE training both happen earlier and unconditionally, independent
of this tracker entirely. State is deliberately in-memory only — a process restart
resets all incident grouping, so the "first occurrence" bonus effectively re-fires for
every still-ongoing incident after a `soc.service` restart.

---

## 16. Appendix: every literal numeric threshold in one table

| Constant | Value | Where |
|---|---|---|
| EWMA z-score decay (`alpha`) | 0.05 | `core/state.py` (live on `.94`) |
| EWMA z-score: min samples / variance floor | n>=10 / 1e-4 | `core/pipeline.py`'s `calc_z()` (live on `.94`) |
| DNS feature sliding window | 300s (5 min) | `argus/ingest/daemon.py` / `dns_features.py` |
| Bayesian baseline models (Gaussian/Beta/Poisson/Markov), BOCPD | **live on `.94`** since 2026-09-16 (was `.19`-only before) | `argus/baseline/`, wired via `argus/ops/live_engine.py` |
| BOCPD hazard rate (expected regime length) | 1/500 cycles | `argus/baseline/engine.py` |
| BOCPD changepoint: candidate mass / confirm samples / confirm avg surprise | >=0.5 / 3 / >=3.0 | `argus/baseline/engine.py` |
| `baseline_scoring_enabled` rollback switch | default `true` | `config.yaml`'s `detection_engine:` section |
| `population_priors` writer: min n / min contributors | 20 / 2 | `argus/ops/population_prior_builder.py` |
| `population_priors` writer: Gaussian pseudo-count (kappa/alpha) | 5.0 / 10.0 | `argus/ops/population_prior_builder.py` |
| `population_priors` writer: Beta/Poisson pseudo-count | 10.0 total / 5.0 exposure | `argus/ops/population_prior_builder.py` |
| `population_priors` writer: Markov pooled-count cap | 50.0 | `argus/ops/population_prior_builder.py` |
| `population_priors` writer schedule | daily, 03:45 | `config.yaml`'s `scheduled_jobs.scheduler.population_prior_builder` |
| Default evidence TTL | 600s | `hypotheses/engine.py` |
| Reputation-family evidence TTL | 86400s | `hypotheses/engine.py` |
| Hard-stop freshness window | 120s | `decision/engine.py` |
| Attack-hypothesis score floor to matter at all | 2.0 | `decision/engine.py` |
| HIGH bar: attack_score / independent families | >=3.0 / >=2 | `decision/engine.py` |
| tier5 CRITICAL corroboration bar | >=2 independent sources | `decision/engine.py` |
| hard-stop corroboration bar (geofence/exploit) | >=1 (excluding own family) | `decision/engine.py` |
| tier4 elevated-signal bar | max(vt,ti,abuse) >= 1.5 | `decision/engine.py` |
| ml_anomaly-only bar | value > 0.90 | `decision/engine.py` |
| confirmed_ioc floor (VT/TI) | > 2.0 | `reputation/classifier.py` |
| confirmed_ioc floor (AbuseIPDB) | >= 4.0 | `reputation/classifier.py` |
| DeviceProfileBenignHypothesis familiarity trust bar | >= 0.6 | `hypotheses/engine.py` |
| risk = threat_confidence x 10.0 | — | `core/pipeline.py` |
| DGA burst: strong / moderate | sd>=15 / sd>=5 & entropy>3.5 | `threat_signals.py` |
| DGA per-domain entropy gate (6-11 char labels) | vowel<=0.12 & entropy>2.6, or digit>=0.45 & entropy>3.0 | `utils.py` |
| DGA per-domain entropy gate (12+ char labels) | entropy>3.2 & vowel<0.25 & digit<0.75 | `utils.py` |
| DNS tunneling: encoded label | length>28 & entropy>3.6 | `dns_features.py` |
| DNS tunneling: subdomain fanout | >=8 distinct children | `dns_features.py` |
| DNS tunneling: TXT/NULL ratio | >0.15 | `dns_features.py` |
| DNS tunneling: suspicious-TLD ratio | >0.15 | `dns_features.py` |
| Peer-deviation: window / min peers / multiplier / min count | 7d / 2 / 3.0x / 5 | `live_engine.py` |
| CL-AFPE Stage 1 hard-stops | 8 checks, first match wins | `cl_afpe/engine.py` |
| CL-AFPE Stage 2/3 weights | LGBM 0.45 / Embed 0.55 | `cl_afpe/ml_scoring.py` |
| CL-AFPE suppress / uncertain thresholds | 0.80 / 0.55 | `cl_afpe/engine.py` |
| Composite trust: increment / decay / floor / min families | +0.15 / -0.05/day / 0.6 / 2 | `composite_trust.py` |
| Sigma-shift: tighten / widen step | -0.50 (floor -1.5) / +0.25 (cap +2.0) | `cl_afpe/engine.py` |
| Autotune: cooldown / canary duration | 3600s / 21600s (6h) | `autotune/engine.py` |
| Autotune: min trials for loosening / Wilson floor / tighten floor | 20 / 0.85 / 0.70 raw rate | `autotune/engine.py`, `backtest_job.py` |
| Autotune: trust-radius cap | 2.0 x max_step | `autotune/engine.py` |
| Retroactive circuit-breaker lookback | 7 days | `backtest_job.py` |
| IPS: router isolate / tarpit risk floor | >=8.5 / >=9.0 | `mitigation/ips.py` |
| Persistence escalation window | 600s (10 min) | `core/pipeline.py` |
| Persistence-escalated confidence floor | 0.55 | `core/pipeline.py` |
| Incident grouping window / re-notify interval | 1800s (30min) / 900s (15min) | `core/incident_tracker.py` |
| TI/VT/AbuseIPDB cache TTL (hit / miss) | 86400s / 3600s | `intelligence/threat_intel.py` |
