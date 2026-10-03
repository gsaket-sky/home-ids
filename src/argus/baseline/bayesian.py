"""
argus/baseline/bayesian.py -- Release 15 closed-loop autotuning architecture,
Sheet 00: per-device Bayesian baseline models.

Pure math only -- no GraphStore/SQLite/IO in this module (matches this codebase's
own "pure logic vs thin runnable wrapper" split, e.g. ingest/sources.py vs
ingest/daemon.py). engine.py (this same package) is the orchestration layer that
persists this module's state to device_baselines/population_priors and turns its
output into Evidence rows.

Four conjugate families with a real posterior (mean + uncertainty) -- unlike the pipeline's
point-estimate EWMABaseline (core/state.py), which keeps only a mean/variance pair:

  GaussianBaseline  -- Normal-Inverse-Gamma, for continuous metrics (query_rate,
                       entropy, unique_domains, outbound_bytes, risk).
  BetaBaseline      -- Beta-Binomial, for ratio metrics (nxdomain_ratio, blocked_ratio).
  PoissonBaseline   -- Gamma-Poisson, for rare-event counts (DGA hits, honeypot touches).
  MarkovBaseline    -- Dirichlet-Categorical, for discrete state sequences (the
                       extended kill-chain activity-state, destination-tier
                       sequences, beaconing-interval buckets).

Each exposes a posterior-predictive surprise score that replaces calc_z()'s point
z-score (core/pipeline.py:1089-1101, hard n>=10 cutoff) with a calibrated,
uncertainty-aware one -- naturally wide/uncertain with few samples, narrowing as
evidence accumulates.

BOCPD (Bayesian Online Changepoint Detection, Adams & MacKay 2007) wraps any of
these four in a run-length posterior over "cycles since the last regime change" --
see BOCPDTracker below. Resource-bounded: prunes hypotheses whose weight drops
below _MIN_HYPOTHESIS_WEIGHT each cycle, sized against the Pi 8GB budget so this
stays O(a handful of live hypotheses) per device/metric, not O(cycles since start).
"""
import math
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# GaussianBaseline -- Normal-Inverse-Gamma conjugate
# ---------------------------------------------------------------------------

@dataclass
class GaussianBaseline:
    """Normal-Inverse-Gamma conjugate posterior over (mean, variance) of a
    continuous metric. Posterior predictive is Student-t -- naturally wide with
    few samples, narrowing as n grows.

    Hyperparameters (mu, kappa, alpha, beta) start as a weak, barely-informative
    prior by default. For a device seeded from a population prior (cold-start
    hierarchical shrinkage -- engine.py's seed_from_population()), construct via
    from_dict() with that prior's own posterior params instead of the defaults.
    """
    mu: float = 0.0
    kappa: float = 0.05    # pseudo-count of the prior -- small = weak prior
    alpha: float = 1.0
    beta: float = 1.0
    n: int = 0

    def update(self, x: float) -> None:
        """Standard sequential Normal-Inverse-Gamma conjugate update."""
        kappa_new = self.kappa + 1.0
        mu_new = (self.kappa * self.mu + x) / kappa_new
        alpha_new = self.alpha + 0.5
        beta_new = self.beta + (self.kappa * (x - self.mu) ** 2) / (2.0 * kappa_new)
        self.mu, self.kappa, self.alpha, self.beta = mu_new, kappa_new, alpha_new, beta_new
        self.n += 1

    def posterior_predictive_params(self) -> Tuple[float, float, float]:
        """Returns (loc, scale, dof) of the Student-t posterior predictive
        distribution for the next observation."""
        dof = max(2.0 * self.alpha, 1e-6)
        scale_sq = self.beta * (self.kappa + 1.0) / max(self.alpha * self.kappa, 1e-9)
        return self.mu, math.sqrt(max(scale_sq, 0.0)), dof

    def predictive_density(self, x: float) -> float:
        """Student-t predictive PDF at x -- used as BOCPDTracker's fit signal."""
        loc, scale, dof = self.posterior_predictive_params()
        if scale <= 0:
            return 1.0 if abs(x - loc) < 1e-9 else 1e-9
        t = (x - loc) / scale
        # Student-t pdf, unnormalized-safe form (we only need relative magnitude
        # across hypotheses sharing the same dof range, not a calibrated density).
        coeff = math.exp(math.lgamma((dof + 1) / 2) - math.lgamma(dof / 2)) / math.sqrt(dof * math.pi)
        density = (coeff / scale) * (1.0 + (t * t) / dof) ** (-(dof + 1) / 2)
        return max(density, 1e-12)

    def surprise(self, x: float) -> float:
        """Posterior-predictive surprise: |x - loc| / scale using the Student-t
        posterior predictive -- naturally larger tolerance with few samples
        (small alpha widens scale), replacing calc_z()'s Normal z-score."""
        loc, scale, _dof = self.posterior_predictive_params()
        if scale <= 0:
            return 0.0
        return max(0.0, (x - loc) / scale)

    def to_dict(self) -> dict:
        return {"mu": self.mu, "kappa": self.kappa, "alpha": self.alpha, "beta": self.beta, "n": self.n}

    @classmethod
    def from_dict(cls, data: dict) -> "GaussianBaseline":
        return cls(mu=data.get("mu", 0.0), kappa=data.get("kappa", 0.05),
                    alpha=data.get("alpha", 1.0), beta=data.get("beta", 1.0), n=data.get("n", 0))


def weaken_gaussian(model: "GaussianBaseline", retain_fraction: float = 0.1) -> "GaussianBaseline":
    """Returns a new GaussianBaseline anchored at `model`'s CURRENT mean but
    with much lower confidence (kappa/alpha scaled down) -- used to seed a
    BOCPD changepoint hypothesis from "what we currently believe, but far
    less sure of," not a flat, uninformed prior.

    Fixes a real instability found via this module's own integration test:
    a flat mu=0 changepoint hypothesis's Student-t density at a merely
    4-sigma point can exceed a well-established (large-n, tightly-fit)
    hypothesis's own density there by 50-100x, simply because a wide/
    uninformed distribution spreads probability mass generously across
    values a narrow, correctly-fit one assigns very little to -- letting
    ordinary statistical noise masquerade as a regime change. Anchoring the
    reset at the current estimate is also more realistic: a firmware update
    shifts a device's behavior, it doesn't erase all prior knowledge of its
    rough operating range. Keeps genuine sustained shifts detectable within
    a handful of confirming cycles (the weakened hypothesis is still free to
    drift its own mean as new data arrives) without losing to a single
    moderately-surprising point."""
    kappa = max(model.kappa * retain_fraction, 0.05)
    alpha = max(model.alpha * retain_fraction, 1.0)
    implied_var = model.beta / max(model.alpha, 1e-9)  # beta/alpha ~ the model's own current variance estimate
    beta = max(implied_var * alpha, 1e-6)
    return GaussianBaseline(mu=model.mu, kappa=kappa, alpha=alpha, beta=beta, n=0)


# ---------------------------------------------------------------------------
# BetaBaseline -- Beta-Binomial conjugate
# ---------------------------------------------------------------------------

@dataclass
class BetaBaseline:
    """Beta-Binomial conjugate posterior over a ratio metric's success
    probability (e.g. nxdomain_ratio, blocked_ratio). Each observation is
    (successes, trials) for one cycle's window, not a single 0/1 event."""
    a: float = 1.0   # weak uniform prior by default
    b: float = 1.0
    n: int = 0

    def update(self, successes: float, trials: float) -> None:
        if trials <= 0:
            return
        self.a += max(0.0, successes)
        self.b += max(0.0, trials - successes)
        self.n += 1

    def mean(self) -> float:
        total = self.a + self.b
        return self.a / total if total > 0 else 0.5

    def predictive_density(self, observed_ratio: float, trials: float = 1.0) -> float:
        """Approximate fit signal for BOCPDTracker: a Normal approximation to
        the Beta posterior's own density at observed_ratio (exact Beta-Binomial
        density needs (successes, trials), which BOCPDTracker's generic
        observe() doesn't have visibility into per-hypothesis; this
        approximation is enough for relative weighting across hypotheses)."""
        mean = self.mean()
        var = max(self._variance(), 1e-6)
        std = math.sqrt(var)
        z = (observed_ratio - mean) / std
        return max(math.exp(-0.5 * z * z) / (std * math.sqrt(2 * math.pi)), 1e-12)

    def _variance(self) -> float:
        total = self.a + self.b
        if total <= 0:
            return 1.0
        return (self.a * self.b) / (total ** 2 * (total + 1.0))

    def surprise(self, observed_ratio: float) -> float:
        """Posterior-predictive surprise: how many posterior standard
        deviations away observed_ratio is from the Beta posterior's own mean --
        wide (low surprise for a given deviation) with a weak posterior,
        narrowing as a+b grows."""
        std = math.sqrt(max(self._variance(), 1e-9))
        return max(0.0, abs(observed_ratio - self.mean()) / std)

    def to_dict(self) -> dict:
        return {"a": self.a, "b": self.b, "n": self.n}

    @classmethod
    def from_dict(cls, data: dict) -> "BetaBaseline":
        return cls(a=data.get("a", 1.0), b=data.get("b", 1.0), n=data.get("n", 0))


def weaken_beta(model: "BetaBaseline", retain_fraction: float = 0.1) -> "BetaBaseline":
    """Same reset-at-current-estimate fix as weaken_gaussian, for the Beta-
    Binomial family -- anchors at the current mean ratio with a much smaller
    effective pseudo-count, instead of a flat uniform prior."""
    total = max(model.a + model.b, 1e-9)
    mean = model.a / total
    weakened_total = max(total * retain_fraction, 2.0)
    return BetaBaseline(a=max(mean * weakened_total, 0.5), b=max((1.0 - mean) * weakened_total, 0.5), n=0)


# ---------------------------------------------------------------------------
# PoissonBaseline -- Gamma-Poisson conjugate
# ---------------------------------------------------------------------------

@dataclass
class PoissonBaseline:
    """Gamma-Poisson conjugate posterior over a rare-event count's rate (e.g.
    DGA hits, honeypot touches per cycle window). Assumes unit exposure per
    update() call (one cycle = one unit) -- fine for this codebase's fixed
    poll-interval cadence; a variable-exposure caller should pass a
    pre-normalized rate instead of a raw count."""
    shape: float = 1.0   # weak prior: Gamma(1, 1) = Exponential(1)
    rate: float = 1.0
    n: int = 0

    def update(self, count: float) -> None:
        self.shape += max(0.0, count)
        self.rate += 1.0
        self.n += 1

    def mean(self) -> float:
        return self.shape / self.rate if self.rate > 0 else 0.0

    def predictive_density(self, observed_count: float) -> float:
        mean = self.mean()
        var = max(self._variance(), 1e-6)
        std = math.sqrt(var)
        z = (observed_count - mean) / std
        return max(math.exp(-0.5 * z * z) / (std * math.sqrt(2 * math.pi)), 1e-12)

    def _variance(self) -> float:
        mean = self.mean()
        # Posterior parameter uncertainty (shape/rate^2) plus the Poisson's own
        # variance=mean -- an approximation to the true Gamma-Poisson (Negative
        # Binomial) predictive variance, adequate for a surprise score.
        return self.shape / (self.rate ** 2) + mean if self.rate > 0 else 1.0

    def surprise(self, observed_count: float) -> float:
        std = math.sqrt(max(self._variance(), 1e-9))
        return max(0.0, (observed_count - self.mean()) / std)

    def to_dict(self) -> dict:
        return {"shape": self.shape, "rate": self.rate, "n": self.n}

    @classmethod
    def from_dict(cls, data: dict) -> "PoissonBaseline":
        return cls(shape=data.get("shape", 1.0), rate=data.get("rate", 1.0), n=data.get("n", 0))


def weaken_poisson(model: "PoissonBaseline", retain_fraction: float = 0.1) -> "PoissonBaseline":
    """Same reset-at-current-estimate fix as weaken_gaussian, for the
    Gamma-Poisson family -- anchors at the current rate estimate with a much
    smaller effective exposure count, instead of a flat Exponential(1) prior."""
    mean = model.mean()
    weakened_rate = max(model.rate * retain_fraction, 1.0)
    return PoissonBaseline(shape=max(mean * weakened_rate, 1.0), rate=weakened_rate, n=0)


# ---------------------------------------------------------------------------
# MarkovBaseline -- Dirichlet-Categorical conjugate transition model
# ---------------------------------------------------------------------------

class MarkovBaseline:
    """Dirichlet-Categorical conjugate transition matrix over a discrete state
    space (e.g. the extended kill-chain activity states: NORMAL, RECON,
    THREAT_INTEL_HIT, DNS_ANOMALY, C2_BEACON, LATERAL_MOVEMENT, EXFIL,
    POLICY_VIOLATION). Order-1 by default; order-2 (conditioning on the last
    TWO states) is used automatically once a given (prev2, prev) context has
    accumulated _MIN_ORDER2_SAMPLES -- below that, falls back to order-1 for
    that specific context, never a hard global switch.

    Replaces the static, hand-authored _MARKOV_TRANSITIONS table
    (extractors/dns_features.py:227-252, `_compute_markov_anomaly`) with a
    per-device learned matrix.
    """

    _MIN_ORDER2_SAMPLES = 20

    def __init__(self, states: List[str], pseudo_count: float = 0.5):
        self.states = list(states)
        self.pseudo_count = pseudo_count
        self.counts1: Dict[str, Dict[str, float]] = {}
        self.counts2: Dict[Tuple[str, str], Dict[str, float]] = {}

    def update(self, prev_state: Optional[str], next_state: str, prev2_state: Optional[str] = None) -> None:
        if prev_state is not None:
            bucket = self.counts1.setdefault(prev_state, {})
            bucket[next_state] = bucket.get(next_state, 0.0) + 1.0
            if prev2_state is not None:
                key = (prev2_state, prev_state)
                bucket2 = self.counts2.setdefault(key, {})
                bucket2[next_state] = bucket2.get(next_state, 0.0) + 1.0

    def _order2_context_count(self, prev2_state: str, prev_state: str) -> float:
        return sum(self.counts2.get((prev2_state, prev_state), {}).values())

    def predictive_probability(self, prev_state: Optional[str], next_state: str,
                                 prev2_state: Optional[str] = None) -> float:
        """Dirichlet-Categorical predictive: (count + pseudo_count) /
        (total + K*pseudo_count). Uses order-2 automatically once that
        specific context has enough samples, otherwise order-1, otherwise
        (no history at all) a uniform prior over the state space."""
        k = len(self.states) or 1
        if prev_state is not None and prev2_state is not None and \
                self._order2_context_count(prev2_state, prev_state) >= self._MIN_ORDER2_SAMPLES:
            bucket = self.counts2.get((prev2_state, prev_state), {})
            total = sum(bucket.values())
            count = bucket.get(next_state, 0.0)
            return (count + self.pseudo_count) / (total + k * self.pseudo_count)
        if prev_state is not None:
            bucket = self.counts1.get(prev_state, {})
            total = sum(bucket.values())
            count = bucket.get(next_state, 0.0)
            return (count + self.pseudo_count) / (total + k * self.pseudo_count)
        return 1.0 / k

    def surprise(self, prev_state: Optional[str], next_state: str,
                  prev2_state: Optional[str] = None) -> float:
        """Surprise = -log(predictive probability) -- 0 for an expected
        transition, growing unboundedly for an improbable one."""
        p = max(self.predictive_probability(prev_state, next_state, prev2_state), 1e-9)
        return -math.log(p)

    def to_dict(self) -> dict:
        return {
            "states": self.states,
            "pseudo_count": self.pseudo_count,
            "counts1": self.counts1,
            "counts2": {f"{a}\x1f{b}": v for (a, b), v in self.counts2.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "MarkovBaseline":
        obj = cls(states=data.get("states", []), pseudo_count=data.get("pseudo_count", 0.5))
        obj.counts1 = dict(data.get("counts1", {}))
        obj.counts2 = {}
        for key, v in data.get("counts2", {}).items():
            a, _, b = key.partition("\x1f")
            obj.counts2[(a, b)] = v
        return obj


# ---------------------------------------------------------------------------
# BOCPD -- Bayesian Online Changepoint Detection wrapper
# ---------------------------------------------------------------------------

_MIN_HYPOTHESIS_WEIGHT = 1e-4  # resource bound: prune run-length hypotheses below this


class BOCPDTracker:
    """Wraps a sequence of per-metric model instances (one per hypothesized run
    length) in a run-length posterior, per Adams & MacKay (2007). At each
    observation: every existing run-length hypothesis is extended by one step,
    weighted by how well the new value fits THAT hypothesis's own current
    posterior; a fresh run-length-zero hypothesis is added, weighted by the
    hazard rate; the distribution is renormalized; every surviving
    hypothesis's model is then updated with the new observation.

    HONEST SIMPLIFICATION (this codebase's own established "first-pass
    judgment call, not yet empirically validated" framing -- see
    INDEPENDENCE_FAMILY_MAP's docstring for the precedent): the textbook BOCPD
    recursion weights the run-length-0 (changepoint) term by each existing
    hypothesis's own predictive fit, not a flat hazard-rate-only mass. This
    implementation uses the simpler flat-mass form for the changepoint term
    (`prior_mass * hazard_rate`) -- it still detects real changepoints
    correctly over a handful of cycles (old hypotheses decay from repeated
    poor fit; a fresh hypothesis that happens to match the new regime grows on
    its OWN subsequent cycles' fit terms), just without the textbook's exact
    joint-probability weighting on the very first post-changepoint cycle.
    Revisit if real deployment data shows detection lag at the changepoint
    boundary itself.

    `model_factory` builds the INITIAL (cycle-zero) model instance -- if
    hierarchical shrinkage applies (Sheet 00's cold-start priors), the
    CALLER's closure should seed it from the current population prior, not a
    flat default.
    `predictive_prob_fn(model, *observation_args) -> float` scores a model's
    fit to the new observation (e.g. `lambda m, x: m.predictive_density(x)`).
    `weaken_fn(dominant_model) -> object`, if given, seeds every SUBSEQUENT
    changepoint hypothesis (spawned during `observe()`, not the initial one)
    by anchoring at the CURRENT dominant model's own estimate with reduced
    confidence, instead of calling `model_factory()` fresh each time -- see
    bayesian.py's own `weaken_gaussian`/`weaken_beta`/`weaken_poisson` for
    why: a flat, uninformed fresh hypothesis's wide density can otherwise
    out-compete a well-established, tightly-fit one on nothing more than
    ordinary statistical noise (confirmed via this module's own integration
    test). Omit only for a model kind with no such helper.
    """

    def __init__(self, model_factory: Callable[[], object],
                  predictive_prob_fn: Callable[..., float],
                  hazard_rate: float = 1.0 / 250.0,
                  max_hypotheses: int = 40,
                  weaken_fn: Optional[Callable[[object], object]] = None):
        self._model_factory = model_factory
        self._predictive_prob_fn = predictive_prob_fn
        self.hazard_rate = hazard_rate
        self._weaken_fn = weaken_fn
        # BUGFIX (found via this module's own unit test): the weight-threshold
        # prune alone (_MIN_HYPOTHESIS_WEIGHT) does not bound hypothesis count
        # during a long STABLE regime -- every surviving hypothesis's model gets
        # updated with the same real data every cycle, so old and new
        # hypotheses alike keep a comparably good `fit` and decay only via the
        # slow geometric (1-hazard_rate)^cycles factor (150 cycles at
        # hazard_rate=0.01 leaves weight at 0.99^150=0.22, nowhere near the
        # 1e-4 threshold) -- confirmed live: 150 stable cycles left 151 live
        # hypotheses, unbounded growth. An explicit top-K-by-weight cap after
        # every cycle (the standard practical BOCPD variant -- particle/
        # hypothesis pruning, not relying on weight decay alone) is what
        # actually guarantees the O(a handful) resource bound this class
        # promises, sized against the Pi 8GB budget.
        self.max_hypotheses = max_hypotheses
        self._hypotheses: List[Tuple[int, object, float]] = [(0, model_factory(), 1.0)]

    def observe(self, *observation_args) -> float:
        """Feeds one new observation through every live hypothesis, adds a
        fresh run-length-zero hypothesis, renormalizes, prunes low-weight
        hypotheses, and returns the probability mass now at run-length 0 --
        the changepoint signal for this cycle."""
        grown: List[Tuple[int, object, float]] = []
        total_growth_weight = 0.0
        for run_length, model, weight in self._hypotheses:
            fit = self._predictive_prob_fn(model, *observation_args)
            grown_weight = weight * fit * (1.0 - self.hazard_rate)
            grown.append((run_length + 1, model, grown_weight))
            total_growth_weight += grown_weight

        prior_mass = sum(w for _, _, w in self._hypotheses)
        cp_weight = prior_mass * self.hazard_rate
        fresh_model = self._weaken_fn(self.dominant_model()) if self._weaken_fn is not None else self._model_factory()
        grown.append((0, fresh_model, cp_weight))

        total = total_growth_weight + cp_weight
        if total <= 0:
            total = 1.0
        normalized = [(rl, m, w / total) for rl, m, w in grown]

        for _rl, model, _w in normalized:
            model.update(*observation_args)

        normalized = [h for h in normalized if h[2] >= _MIN_HYPOTHESIS_WEIGHT]
        if len(normalized) > self.max_hypotheses:
            # Keep the top-K by weight, then renormalize so the survivors still
            # sum to (approximately) 1 -- the pruned tail's mass was already
            # negligible relative to what's kept, by construction (sorted).
            normalized.sort(key=lambda h: h[2], reverse=True)
            normalized = normalized[: self.max_hypotheses]
            kept_total = sum(w for _, _, w in normalized) or 1.0
            normalized = [(rl, m, w / kept_total) for rl, m, w in normalized]
        if not normalized:
            normalized = [(0, self._model_factory(), 1.0)]
        self._hypotheses = normalized

        return next((w for rl, _m, w in self._hypotheses if rl == 0), 0.0)

    def map_run_length(self) -> int:
        """The single most-likely run length -- 'cycles since the last
        regime change' under the current posterior."""
        return max(self._hypotheses, key=lambda h: h[2])[0]

    def dominant_model(self) -> object:
        """The model instance backing the highest-weight (MAP) hypothesis --
        the posterior a caller should read/query for day-to-day scoring."""
        return max(self._hypotheses, key=lambda h: h[2])[1]

    def num_live_hypotheses(self) -> int:
        return len(self._hypotheses)
