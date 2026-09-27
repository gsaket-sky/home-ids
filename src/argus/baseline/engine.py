"""
v13/baseline/engine.py -- Release 15 Sheet 00 orchestration layer: wires
baseline/bayesian.py's pure conjugate/BOCPD models to GraphStore persistence,
derives the cross-detector "activity state" for MarkovBaseline, and turns
model output into Evidence rows -- all subject to the no-learning-during-an-
-incident gate (Design Invariant 06) and hierarchical population-prior
shrinkage for cold start.

Structurally a thin orchestration wrapper around the pure math in bayesian.py
(same "pure logic vs. thin runnable wrapper" split this codebase already uses
elsewhere, e.g. ingest/sources.py vs ingest/daemon.py) -- this module is where
GraphStore reads/writes, JSON (de)serialization, and the incident/probation
gating logic live; bayesian.py stays free of any of that.
"""
import json
import logging
import time
from typing import Dict, Iterable, List, Optional, Tuple

from argus.autotune.engine import AutotuneEngine

LOGGER = logging.getLogger("argus.baseline.engine")
from argus.baseline.bayesian import (
    BetaBaseline, BOCPDTracker, GaussianBaseline, MarkovBaseline, PoissonBaseline,
    weaken_beta, weaken_gaussian, weaken_poisson,
)
from argus.evidence.model import Evidence, NO_DESTINATION
from argus.graph.store import GraphStore
from argus.hypotheses.independence import family_for

# --- metric registry ---------------------------------------------------------

GAUSSIAN_METRICS = ("query_rate", "entropy", "unique_domains", "outbound_bytes", "risk")
BETA_METRICS = ("nxdomain_ratio", "blocked_ratio")
POISSON_METRICS = ("dga_hits", "honeypot_touches")

_INCIDENT_STATES = frozenset({"SUSPICIOUS", "HIGH", "CRITICAL"})
# 30 minutes after a device returns to a non-incident state before its own
# baseline/regime/Markov learning resumes -- see is_learning_paused()'s own
# docstring for why a plain elapsed-time check against the LATEST decision
# row is correct here, not a row-count.
_INCIDENT_COOLDOWN_SECONDS = 1800.0

# BOCPD: cp_mass (probability mass at run-length 0) crossing this bar is the
# CANDIDATE trigger -- confirmation is a separate, second stage (see
# _CHANGEPOINT_CONFIRM_* below and _evaluate_changepoint_candidate()). A
# first-pass, not-yet-empirically-tuned constant (this codebase's own
# established honesty framing for exactly this kind of judgment call -- see
# INDEPENDENCE_FAMILY_MAP's docstring).
_CHANGEPOINT_MASS_THRESHOLD = 0.5

# CONFIRMATION, not just the candidate trigger above -- two real bugs found
# via this module's own integration test before landing on this design:
#
# 1. A single-cycle cp_mass spike alone is not reliable: even after
#    weaken_gaussian/weaken_beta/weaken_poisson anchor a fresh hypothesis at
#    the current estimate (not a flat prior), a POOL of hypotheses at
#    various intermediate maturities can collectively assign more density to
#    an ordinary tail point (a ~4-sigma value, expected occasionally by
#    chance) than the single fully-mature dominant hypothesis does --
#    confirmed live: cp_mass reached 0.94 from ONE moderately-surprising
#    point after 60 stable cycles.
#
# 2. Requiring cp_mass ITSELF to stay high for several consecutive cycles
#    (the first fix attempted) does not work either, and for a more
#    fundamental reason: cp_mass measures mass at run-length EXACTLY 0, which
#    structurally decays after a single cycle regardless of whether a real
#    changepoint occurred -- the new-regime hypothesis becomes run-length 1,
#    then 2, then 3, the same way for both a genuine sustained shift AND a
#    single noisy outlier (confirmed live: map_run_length resets to 0 and
#    climbs steadily afterward in BOTH cases -- a fresh hypothesis that
#    happens to explain ongoing NORMAL data adequately never gets
#    "corrected back," since per-point density comparison has no way to
#    prefer the long-established hypothesis's larger effective evidence
#    the way a proper Bayes-factor/Occam's-razor comparison would).
#
# The fix that actually works: snapshot the OLD (pre-spike) dominant model
# as a FIXED reference the moment a candidate spike is seen, then require
# _CHANGEPOINT_CONFIRM_SAMPLES subsequent raw observations to average at
# least _CHANGEPOINT_CONFIRM_AVG_SURPRISE surprise AGAINST THAT FIXED,
# NEVER-UPDATED ANCHOR. A single outlier's own surprise against the anchor
# is real but isolated -- the next few observations (drawn from the
# still-unchanged true regime) show low surprise against the same anchor,
# pulling the average back down. A genuine sustained shift keeps EVERY
# subsequent observation surprising against the old anchor (which never
# updates to chase the new regime), keeping the average high. Verified
# directly against both failure modes above before adopting this design.
_CHANGEPOINT_CONFIRM_SAMPLES = 3
_CHANGEPOINT_CONFIRM_AVG_SURPRISE = 3.0

_DEFAULT_HAZARD_RATE = 1.0 / 500.0  # ~500-cycle expected regime length by default

# 2026-09-27 (Phase 5 of the autonomy-completion effort): how often a warm
# tracker's hazard_rate is re-checked against the currently-promoted value.
# First-pass, not-yet-empirically-tuned constant, same honesty framing as this
# module's other first-pass constants -- cheap enough (one indexed SELECT) to
# run fairly often without real cost, but not so often it re-queries SQLite on
# literally every observation.
_HAZARD_RATE_RECHECK_SECONDS = 60.0

# --- activity-state taxonomy (Markov axis 1) ---------------------------------

ACTIVITY_STATES = [
    "NORMAL", "RECON", "THREAT_INTEL_HIT", "DNS_ANOMALY", "C2_BEACON",
    "LATERAL_MOVEMENT", "EXFIL", "POLICY_VIOLATION",
]

# Which real, already-registered evidence_types (hypotheses/independence.py's
# own INDEPENDENCE_FAMILY_MAP) trigger each activity state. Replaces
# _determine_killchain_phase()'s first-match-wins threshold cascade
# (extractors/dns_features.py:227-243), which never looks at reputation/IOC,
# honeypot, ARP-spoof, or geofence evidence at all.
_ACTIVITY_STATE_TRIGGERS: Dict[str, Tuple[str, ...]] = {
    "POLICY_VIOLATION": ("honeypot_access", "arp_spoofing", "geofencing_violation"),
    "THREAT_INTEL_HIT": ("reputation", "suricata_signature_match"),
    "EXFIL": ("zeek_exfiltration",),
    "C2_BEACON": ("zeek_beaconing",),
    "LATERAL_MOVEMENT": ("peer_deviation", "coordinated_targeting", "zeek_lateral_scan"),
    "RECON": ("arp_sweep",),
    "DNS_ANOMALY": ("dns_tunnel_v2", "dns_dga_burst", "dns_evasion_anomaly"),
}
# Priority order when more than one state's triggers are present in the same
# cycle -- picks the single label fed into the Markov transition model. This
# does NOT discard the co-occurrence: every triggering evidence item is still
# its own separate row in the graph, scored on its own merits by the decision
# engine: this priority order only decides what MarkovBaseline's OWN sequence
# sees as "the state this cycle."
_ACTIVITY_STATE_PRIORITY = [
    "POLICY_VIOLATION", "THREAT_INTEL_HIT", "EXFIL", "C2_BEACON",
    "LATERAL_MOVEMENT", "RECON", "DNS_ANOMALY", "NORMAL",
]

# Two-tier pooling for cold start (Phase 0 design): common states shrink to a
# device-type prior; rare/attack-shaped states shrink to a GLOBAL prior
# instead, since even device-type-level sample counts for these will usually
# be too sparse on a home network.
_GLOBAL_POOL_STATES = frozenset({"RECON", "LATERAL_MOVEMENT", "EXFIL", "THREAT_INTEL_HIT"})
_GLOBAL_POOL_DEVICE_TYPE = "__global__"  # population_priors' own device_type key for these


def derive_activity_state(evidence_types_this_cycle: Iterable[str]) -> str:
    """The dominant cross-detector activity state for one device-cycle."""
    present = set(evidence_types_this_cycle)
    for state in _ACTIVITY_STATE_PRIORITY:
        if present.intersection(_ACTIVITY_STATE_TRIGGERS.get(state, ())):
            return state
    return "NORMAL"


_MODEL_CLASSES = {"gaussian": GaussianBaseline, "beta": BetaBaseline, "poisson": PoissonBaseline}
_WEAKEN_FNS = {"gaussian": weaken_gaussian, "beta": weaken_beta, "poisson": weaken_poisson}


def _fit_fn_for(model_kind: str):
    if model_kind == "gaussian":
        return lambda model, x: model.predictive_density(x)
    if model_kind == "beta":
        # BUGFIX (found while wiring real per-cycle trial counts, Release 15
        # follow-up): observation_args for beta is (successes, trials) --
        # BetaBaseline.update()'s own tested contract (test_argus_bayesian_
        # baseline.py) -- not (ratio,). The old 1-arg lambda here crashed
        # with a TypeError on every single beta-metric cycle (confirmed live:
        # `model.predictive_density(ratio)` called via `fit_fn(model,
        # *observation_args)` with a 2-element observation_args always raised
        # "takes 2 positional arguments but 3 were given"), silently
        # swallowed by daemon.py's per-device try/except -- which discarded
        # not just the beta evidence but the WHOLE cycle's already-computed
        # gaussian/poisson/markov evidence for that device too, every cycle
        # nxdomain_ratio/blocked_ratio had data. predictive_density() itself
        # is on the RATIO scale (compares against the posterior mean, a
        # probability) -- convert here rather than changing that already-
        # tested method's signature.
        return lambda model, successes, trials: model.predictive_density(successes / max(trials, 1e-9), trials)
    if model_kind == "poisson":
        return lambda model, count: model.predictive_density(count)
    raise ValueError(f"unknown model_kind: {model_kind}")


def _surprise_args_for(model_kind: str, observation_args: Tuple) -> Tuple:
    """Same ratio-scale conversion as _fit_fn_for's beta branch, for the two
    call sites below that invoke a model's own .surprise() generically
    against observation_args -- BetaBaseline.surprise() takes a ratio (its
    own tested contract), while this engine's beta observation_args carries
    (successes, trials) for update()'s sake. Gaussian/Poisson pass through
    unchanged (their surprise() already takes the same single scalar
    observation_args already carries)."""
    if model_kind == "beta":
        successes, trials = observation_args
        return (successes / max(trials, 1e-9),)
    return observation_args


class BaselineEngine:
    """Orchestrates Sheet 00's Bayesian/BOCPD/Markov models against a
    GraphStore. One instance per ingest daemon process (matches
    IngestDaemon's own one-GraphStore-per-process pattern)."""

    def __init__(self, store: GraphStore):
        self.store = store
        # Release 15 Sheet 03a live wiring (closes that module's own former
        # honest gap: "not yet wired to make v13/decision/engine.py actually
        # READ these promoted values"): bocpd_hazard_rate is the one
        # TUNABLE_PARAMETERS entry this engine itself owns the meaning of.
        # get_active_value() falls back to _DEFAULT_HAZARD_RATE (this
        # module's own prior constant, unchanged) until an autotuner
        # proposal for this parameter is actually canary-confirmed and
        # promoted -- inert by construction until that happens, never a
        # behavior change on its own.
        self.autotune = AutotuneEngine(store)
        # 2026-09-27 (Phase 5 of the autonomy-completion effort): closes
        # _load_tracker()'s own "HONEST LIMITATION" below. Registered for
        # defense-in-depth (a FUTURE caller that promotes bocpd_hazard_rate
        # in-process, in the same process this BaselineEngine runs in, would
        # reach this immediately) -- but confirmed via direct investigation
        # this is NOT the mechanism that actually matters for the real
        # deployed topology: bocpd_hazard_rate's own promoter
        # (backtest_job.py's run_backtest(), via _propose_bocpd_hazard_changes())
        # runs as its own separate scheduled OS subprocess (scripts/scheduler.py),
        # never in-process with the live soc.service pipeline this BaselineEngine
        # actually runs inside of -- an in-process callback can never fire across
        # that process boundary. The REAL fix is the periodic re-check inside
        # _load_tracker()'s own cache-HIT path below, which re-reads the
        # promoted value from the shared SQLite threshold_history table (the
        # actual cross-process channel) instead of relying on a same-process
        # notification.
        self.autotune.set_notify(self._on_autotune_notify)
        # (device_id, metric, hour) -> (hazard_rate tracker was last confirmed
        # to be using, wall-clock of that last confirmation) -- throttles the
        # re-check to _HAZARD_RATE_RECHECK_SECONDS instead of every single
        # cache-hit call, same "periodic, not per-call" precedent already
        # established elsewhere in this codebase (fritzbox_capture.py's own
        # disk-budget check).
        self._tracker_hazard_state: Dict[Tuple[str, str, int], Tuple[float, float]] = {}
        # In-memory cache of live BOCPDTracker objects, keyed by
        # (device_id, metric, hour) -- avoids reconstructing the whole
        # hypothesis list from JSON every cycle for a device active every
        # poll. A cold key is loaded from device_baselines on first touch.
        # Deliberately NOT the "fresh per-cycle snapshot" model
        # DecisionEngine/HypothesisEngine follow (schema.sql's own design
        # note) -- that discipline governs DECISION-time reads specifically
        # (Design Invariant 02); this is upstream LEARNING state, which is
        # expected to persist and accumulate, same distinction that
        # invariant itself draws.
        self._trackers: Dict[Tuple[str, str, int], BOCPDTracker] = {}
        self._markov: Dict[Tuple[str, str], MarkovBaseline] = {}  # (device_id, axis) -> tracker
        self._last_state: Dict[Tuple[str, str], Tuple[Optional[str], Optional[str]]] = {}  # (device, axis) -> (prev, prev2)
        self._last_observed_at: Dict[str, float] = {}  # device_id -> wall-clock of its last real update
        # (device, metric, hour) -> {"anchor": <frozen pre-spike model>, "surprises": [...]}
        # -- an active reference-check for a candidate changepoint. See
        # _CHANGEPOINT_CONFIRM_* above for why this two-stage design replaced
        # both a single-cycle check and a consecutive-cp_mass-streak check.
        self._changepoint_pending: Dict[Tuple[str, str, int], dict] = {}

    # ---------------------------------------------------------- incident gate

    def is_learning_paused(self, device_id: str, now: Optional[float] = None) -> bool:
        """Design Invariant 06: no baseline/regime/Markov update while a
        device sits at SUSPICIOUS/HIGH/CRITICAL, and not immediately on
        return to BENIGN either. `compute_decision()` only persists a new
        decisions row when the verdict CHANGES (v13/ingest/sources.py's
        only_persist_if_changed_from) -- so the latest row's own timestamp
        already IS "when this device most recently left/avoided an incident
        state," and a plain elapsed-time check against it is the correct
        cooldown, with no extra row-counting needed.

        BUGFIX (2026-09-20, identity-merge handover follow-up): resolves
        device_id to its live canonical id first -- get_latest_decision_for_device()
        already does this internally too, but score_metric()/
        score_activity_transition() below need the SAME resolution for their
        OWN device_baselines reads/writes, so this is resolved once, up front,
        for consistency rather than relying on it happening to also be safe
        here specifically."""
        device_id = self.store.resolve_canonical_device_id(device_id)
        latest = self.store.get_latest_decision_for_device(device_id)
        if latest is None:
            return False
        if latest.get("state") in _INCIDENT_STATES:
            return True
        now = now if now is not None else time.time()
        return (now - float(latest.get("timestamp", 0) or 0)) < _INCIDENT_COOLDOWN_SECONDS

    # ---------------------------------------------------------- persistence

    def _load_tracker(self, device_id: str, metric: str, model_kind: str, hour: int,
                        now: Optional[float] = None) -> Tuple[BOCPDTracker, int]:
        """Loads the live BOCPDTracker for (device, metric, hour), or builds
        a fresh one seeded from the population prior (hierarchical shrinkage
        for cold start) if none exists yet. Returns (tracker, regime_id) --
        regime_id is tracked alongside, not inside BOCPDTracker itself, since
        it's this engine's own concept (which REGIME's row to read/write),
        distinct from BOCPD's internal run-length hypotheses.

        FIXED (2026-09-27, Phase 5 of the autonomy-completion effort -- closes
        this method's own former "HONEST LIMITATION"): a cache-HIT no longer
        just returns the warm tracker unconditionally. At most once per
        _HAZARD_RATE_RECHECK_SECONDS, it re-reads the currently-promoted
        bocpd_hazard_rate and, if it has changed since this tracker was built
        (or last confirmed), updates `tracker.hazard_rate` IN PLACE --
        BOCPDTracker.observe() reads `self.hazard_rate` fresh every call
        (bayesian.py:349's own class, not baked into any per-hypothesis
        closure), so this is a safe, lossless in-place update: no hypothesis
        list eviction, no reload from device_baselines, no posterior state
        lost or reconstructed. This is real, effective cache invalidation
        precisely BECAUSE it re-reads the shared SQLite threshold_history
        table (the actual cross-process channel bocpd_hazard_rate's own
        promoter uses -- see this class's own __init__ comment on why an
        in-process notify callback alone can't reach this)."""
        now = now if now is not None else time.time()
        key = (device_id, metric, hour)
        if key in self._trackers:
            tracker = self._trackers[key]
            last_hazard, last_checked = self._tracker_hazard_state.get(key, (tracker.hazard_rate, 0.0))
            if now - last_checked >= _HAZARD_RATE_RECHECK_SECONDS:
                current_hazard = self.autotune.get_active_value(
                    "bocpd_hazard_rate", device_id, default=_DEFAULT_HAZARD_RATE)
                if current_hazard != tracker.hazard_rate:
                    LOGGER.info(
                        "bocpd_hazard_rate promotion/rollback reached warm tracker (device=%r, "
                        "metric=%r, hour=%r): %.6f -> %.6f, updated in place, hypotheses preserved",
                        device_id, metric, hour, tracker.hazard_rate, current_hazard,
                    )
                    tracker.hazard_rate = current_hazard
                self._tracker_hazard_state[key] = (current_hazard, now)
            return tracker, self._regime_for(device_id, metric, hour)

        row = self.store._conn.execute(
            "SELECT * FROM device_baselines WHERE device_id=? AND metric=? AND hour=? "
            "ORDER BY regime_id DESC LIMIT 1",
            (device_id, metric, hour),
        ).fetchone()

        model_cls = _MODEL_CLASSES[model_kind]
        fit_fn = _fit_fn_for(model_kind)
        hazard_rate = self.autotune.get_active_value(
            "bocpd_hazard_rate", device_id, default=_DEFAULT_HAZARD_RATE)
        self._tracker_hazard_state[key] = (hazard_rate, now)

        if row is not None:
            regime_id = int(row["regime_id"])
            run_length_state = json.loads(row["run_length_json"] or "[]")
            if run_length_state:
                tracker = BOCPDTracker(
                    model_factory=lambda: self._seeded_model(device_id, metric, model_kind, hour, model_cls),
                    predictive_prob_fn=fit_fn, hazard_rate=hazard_rate,
                    weaken_fn=_WEAKEN_FNS.get(model_kind),
                )
                tracker._hypotheses = [
                    (h["run_length"], model_cls.from_dict(h["model"]), h["weight"])
                    for h in run_length_state
                ]
                self._trackers[key] = tracker
                return tracker, regime_id

        # No saved state (or a saved-but-empty hypothesis list) -- fresh
        # tracker; the constructor's own model_factory() call already seeds
        # hypothesis 0 from the population prior (hierarchical shrinkage),
        # no separate override needed here.
        tracker = BOCPDTracker(
            model_factory=lambda: self._seeded_model(device_id, metric, model_kind, hour, model_cls),
            predictive_prob_fn=fit_fn, hazard_rate=hazard_rate,
            weaken_fn=_WEAKEN_FNS.get(model_kind),
        )
        self._trackers[key] = tracker
        regime_id = int(row["regime_id"]) if row is not None else 0
        return tracker, regime_id

    def _on_autotune_notify(self, parameter: str, device_id: Optional[str],
                              device_type: Optional[str], event: str) -> None:
        """AutotuneEngine.set_notify() subscriber -- see __init__'s own comment
        on why this is defense-in-depth (a same-process promoter), not the
        mechanism that handles the real, cross-process deployment topology
        (that's _load_tracker()'s own periodic re-check). Forces the NEXT
        _load_tracker() call for every potentially-affected warm tracker to
        immediately re-check and update in place, by resetting this key's
        recheck timestamp to 0, rather than duplicating the update logic here.
        Scoped correctly: a device-scoped promotion only forces that one
        device's own keys; category/global forces every warm key (this cache
        has no device_type index, so a category-scoped promotion can't cheaply
        narrow further -- correctness over a small, one-time-per-promotion
        optimization)."""
        if parameter != "bocpd_hazard_rate":
            return
        for key in list(self._tracker_hazard_state.keys()):
            key_device_id, _metric, _hour = key
            if device_id is not None and key_device_id != device_id:
                continue
            hazard, _checked_at = self._tracker_hazard_state[key]
            self._tracker_hazard_state[key] = (hazard, 0.0)

    def _seeded_model(self, device_id: str, metric: str, model_kind: str, hour: int, model_cls):
        """Hierarchical shrinkage: a brand-new run-length-zero hypothesis (or
        a brand-new device's very first model) starts from the device-type
        population prior instead of a flat, uninformative default -- the
        concrete mechanism that makes adding a new device to a plug-and-
        forget deployment safe from cycle one.

        PHASE 8 (behavioral cohorts, autonomy-completion effort): when no
        device_type prior exists at all (the common case in production --
        device_type is user-set/self-reported and NULL for most real devices,
        see population_prior_builder.py's own _device_type_map() docstring),
        falls back to this device's own BEHAVIORAL cohort prior instead --
        still real, still device-type-independent, purely additive coverage
        for devices that otherwise get zero cold-start benefit. Never
        overrides a working device_type prior when one exists."""
        device_type = self.store.get_device_metadata(device_id).get("device_type") \
            or self._device_type_column(device_id)
        prior = self._load_population_prior(device_type, metric, hour)
        if prior is None:
            cohort_key = self._device_cohort_key(device_id)
            if cohort_key:
                prior = self._load_cohort_prior(cohort_key, metric, hour)
        if prior is not None:
            return model_cls.from_dict(prior)
        return model_cls()

    def _device_type_column(self, device_id: str) -> Optional[str]:
        row = self.store._conn.execute(
            "SELECT device_type FROM devices WHERE device_id=?", (device_id,),
        ).fetchone()
        return row["device_type"] if row is not None else None

    def _device_cohort_key(self, device_id: str) -> Optional[str]:
        return self.store.get_device_cohort_key(device_id)

    def _load_population_prior(self, device_type: Optional[str], metric: str, hour: int) -> Optional[dict]:
        pool_type = device_type or "__unknown__"
        row = self.store._conn.execute(
            "SELECT posterior_params_json FROM population_priors WHERE device_type=? AND metric=? AND hour=?",
            (pool_type, metric, hour),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["posterior_params_json"])

    def _load_cohort_prior(self, cohort_key: str, metric: str, hour: int) -> Optional[dict]:
        row = self.store._conn.execute(
            "SELECT posterior_params_json FROM cohort_priors WHERE cohort_key=? AND metric=? AND hour=?",
            (cohort_key, metric, hour),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["posterior_params_json"])

    def _regime_for(self, device_id: str, metric: str, hour: int) -> int:
        row = self.store._conn.execute(
            "SELECT MAX(regime_id) AS r FROM device_baselines WHERE device_id=? AND metric=? AND hour=?",
            (device_id, metric, hour),
        ).fetchone()
        return int(row["r"]) if row is not None and row["r"] is not None else 0

    def _save_tracker(self, device_id: str, metric: str, model_kind: str, hour: int,
                        tracker: BOCPDTracker, regime_id: int, now: float) -> None:
        run_length_state = [
            {"run_length": rl, "weight": w, "model": m.to_dict()}
            for rl, m, w in tracker._hypotheses  # noqa: SLF001 -- this engine owns the persistence contract
        ]
        dominant = tracker.dominant_model()
        self.store._conn.execute(
            "INSERT INTO device_baselines "
            "(device_id, metric, hour, regime_id, model_kind, posterior_params_json, run_length_json, n, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(device_id, metric, hour, regime_id) DO UPDATE SET "
            "posterior_params_json=excluded.posterior_params_json, "
            "run_length_json=excluded.run_length_json, n=excluded.n, updated_at=excluded.updated_at",
            (device_id, metric, hour, regime_id, model_kind,
             json.dumps(dominant.to_dict()), json.dumps(run_length_state), dominant.n, now),
        )
        self.store._maybe_commit()

    def _evaluate_changepoint_candidate(self, key: Tuple[str, str, int], cp_mass: float,
                                           pre_spike_dominant, model_cls, observation_args: Tuple,
                                           model_kind: str) -> bool:
        """Two-stage changepoint confirmation -- see _CHANGEPOINT_CONFIRM_*'s
        own comment for the two real failure modes this design replaced.
        Returns True only once, on the cycle a pending check actually
        confirms; every other cycle (no candidate, or still buffering)
        returns False."""
        pending = self._changepoint_pending.get(key)
        if pending is None:
            if cp_mass < _CHANGEPOINT_MASS_THRESHOLD:
                return False
            # New candidate: freeze a snapshot of the OLD model (a
            # serialization round-trip, not the live mutable object every
            # hypothesis in the tracker keeps updating) as the fixed
            # reference every subsequent buffered sample is scored against.
            pending = {"anchor": model_cls.from_dict(pre_spike_dominant.to_dict()), "surprises": []}
            self._changepoint_pending[key] = pending

        pending["surprises"].append(pending["anchor"].surprise(*_surprise_args_for(model_kind, observation_args)))
        if len(pending["surprises"]) < _CHANGEPOINT_CONFIRM_SAMPLES:
            return False

        avg_surprise = sum(pending["surprises"]) / len(pending["surprises"])
        del self._changepoint_pending[key]
        return avg_surprise >= _CHANGEPOINT_CONFIRM_AVG_SURPRISE

    # ---------------------------------------------------------- Gaussian/Beta/Poisson scoring

    def score_metric(self, device_id: str, metric: str, model_kind: str,
                       observation_args: Tuple, hour: int, now: Optional[float] = None) -> Optional[Evidence]:
        """Updates (device, metric, hour)'s BOCPD-wrapped posterior with one
        new observation and returns a `baseline_deviation` Evidence item (or
        a `regime_change` one if this cycle's observation triggered a
        changepoint) -- or None if learning is currently paused (Design
        Invariant 06) or the observation is a no-op.

        Uses NO_DESTINATION (v13/evidence/model.py) unconditionally: these
        are aggregate, per-device features, not single-connection evidence,
        and this is the DIRECT application of the red-team finding that new
        evidence emitters must never guess a "last known destination"
        fallback (the exact bug class behind CHANGELOG.md:569's 3,179-alert
        incident) -- no real destination exists for this evidence type, so
        the schema's own explicit sentinel is used, not a guess.
        """
        now = now if now is not None else time.time()
        # BUGFIX (2026-09-20, identity-merge handover follow-up): resolve BEFORE
        # anything else touches device_id -- device_baselines was found to be
        # the real root cause of the device_baselines 89-vs-13 device_id anomaly:
        # every device_baselines row (and this engine's own in-memory
        # _trackers/_markov/_last_state/_changepoint_pending caches) was keyed
        # by device_id LITERALLY, with no merge resolution anywhere in this
        # file. An orphan that merges away mid-lifetime (see
        # core/state_guard.py's merge_into_canonical()) would silently strand
        # its own brief baseline history under a dead id forever, while the
        # canonical identity cold-starts a completely fresh one -- exactly the
        # kind of stray row the 89-vs-13 anomaly investigation found. Resolving
        # here means a NEW orphan (now typically merged away within a cycle or
        # two, since the zombie-resurrection fix closed off the main source of
        # long-lived orphans) never gets its own device_baselines row in the
        # first place. Deliberately NOT also searching across every id that
        # ever merged into this canonical (unlike get_evidence_for_device()'s
        # own resolve_merges) -- per this session's explicit product decision,
        # a pre-merge orphan's own brief statistical history stays discarded,
        # not adopted, same reasoning as core/state_guard.py's baselines.
        device_id = self.store.resolve_canonical_device_id(device_id)
        if self.is_learning_paused(device_id, now):
            return None

        # BUGFIX (found via the real ingest daemon's own existing test suite,
        # not this module's own tests -- those always upserted the device
        # first): device_baselines.device_id is a foreign key against
        # devices(device_id). insert_evidence() upserts the device as a side
        # effect, but a device can go a whole cycle with ZERO raw detector
        # evidence (normal -- most cycles for most devices are quiet) while
        # still having valid features worth baseline-scoring. Upserting here
        # too makes this engine self-sufficient regardless of what the
        # caller already did this cycle, not dependent on ordering.
        self.store.upsert_device(device_id, timestamp=now)

        tracker, regime_id = self._load_tracker(device_id, metric, model_kind, hour, now=now)
        model_cls = _MODEL_CLASSES[model_kind]
        pre_spike_dominant = tracker.dominant_model()  # snapshot BEFORE this cycle's update -- the confirmation anchor

        cp_mass = tracker.observe(*observation_args)
        self._last_observed_at[device_id] = now

        changepoint_confirmed = self._evaluate_changepoint_candidate(
            (device_id, metric, hour), cp_mass, pre_spike_dominant, model_cls, observation_args, model_kind,
        )
        if changepoint_confirmed:
            regime_id += 1

        self._save_tracker(device_id, metric, model_kind, hour, tracker, regime_id, now)

        dominant = tracker.dominant_model()
        surprise = (dominant.surprise(*_surprise_args_for(model_kind, observation_args))
                     if hasattr(dominant, "surprise") else 0.0)

        if changepoint_confirmed:
            return Evidence(
                device_id=device_id, destination_id=NO_DESTINATION,
                evidence_type="regime_change", independence_family=family_for("regime_change"),
                timestamp=now, source="v13.baseline.engine",
                value=cp_mass, confidence=cp_mass,
                features={"metric": metric, "regime_id": regime_id, "cp_mass": cp_mass},
            )
        if surprise <= 0.0:
            return None
        # Confidence rises with surprise but never certainly -- this is
        # context (NON_ATTACK_FAMILIES), never proof; capped well short of 1.0.
        confidence = min(0.6, surprise / 10.0)
        return Evidence(
            device_id=device_id, destination_id=NO_DESTINATION,
            evidence_type="baseline_deviation", independence_family=family_for("baseline_deviation"),
            timestamp=now, source="v13.baseline.engine",
            value=surprise, confidence=confidence,
            features={"metric": metric, "regime_id": regime_id, "hour": hour},
        )

    # ---------------------------------------------------------- Markov / activity-state scoring

    def score_activity_transition(self, device_id: str, evidence_types_this_cycle: Iterable[str],
                                     axis: str = "activity_state", now: Optional[float] = None) -> Optional[Evidence]:
        """Derives this cycle's dominant activity state, updates the
        device's learned Markov transition model, and returns a
        `markov_activity_surprise` Evidence item scored against the
        transition's posterior-predictive probability. Order-2 (conditioning
        on the last TWO states) is used automatically once MarkovBaseline's
        own per-context sample threshold is crossed -- see bayesian.py.

        Gap fixed via direct verification against decision/engine.py before
        this was written (not assumed): independence_family is re-derived
        centrally from evidence_type via family_for() at decision time, never
        trusted from whatever is stored per-instance -- so "no self-
        corroboration through derivation" is enforced by markov_activity_
        surprise's PERMANENT hypotheses/independence.py NON_ATTACK_FAMILIES
        membership, not by a dynamic per-instance family override (which the
        real corroboration-counting code doesn't even read).
        """
        now = now if now is not None else time.time()
        # BUGFIX (2026-09-20, identity-merge handover follow-up): same
        # resolve-before-anything-else fix as score_metric() above -- see its
        # own comment for the full rationale.
        device_id = self.store.resolve_canonical_device_id(device_id)
        if self.is_learning_paused(device_id, now):
            return None
        self.store.upsert_device(device_id, timestamp=now)  # same FK fix as score_metric

        state = derive_activity_state(evidence_types_this_cycle)
        key = (device_id, axis)
        markov = self._markov.get(key) or self._load_markov(device_id, axis)
        prev_state, prev2_state = self._last_state.get(key, (None, None))

        surprise = markov.surprise(prev_state, state, prev2_state=prev2_state) if prev_state else 0.0
        markov.update(prev_state, state, prev2_state=prev2_state)
        self._last_state[key] = (state, prev_state)
        self._markov[key] = markov
        self._save_markov(device_id, axis, markov, now)

        if prev_state is None or surprise <= 0.0:
            return None
        confidence = min(0.5, surprise / 8.0)
        return Evidence(
            device_id=device_id, destination_id=NO_DESTINATION,
            evidence_type="markov_activity_surprise",
            independence_family=family_for("markov_activity_surprise"),
            timestamp=now, source="v13.baseline.engine",
            value=surprise, confidence=confidence,
            features={"axis": axis, "prev_state": prev_state, "state": state},
        )

    def _load_markov(self, device_id: str, axis: str) -> MarkovBaseline:
        row = self.store._conn.execute(
            "SELECT posterior_params_json FROM device_baselines "
            "WHERE device_id=? AND metric=? AND model_kind='markov' ORDER BY regime_id DESC LIMIT 1",
            (device_id, axis),
        ).fetchone()
        if row is not None:
            return MarkovBaseline.from_dict(json.loads(row["posterior_params_json"]))
        # BUGFIX (Phase 8, behavioral cohorts, found while extending this same
        # cold-start path): this used to read ONLY the raw devices.device_type SQL
        # column, skipping metadata_json -- the same class of footgun
        # population_prior_builder.py's _device_type_map() docstring already
        # documents (the column is NULL for every real device on `.94`; the live
        # pipeline only ever writes device_type into metadata_json). That silently
        # made the Markov axis's own device-type cold-start prior permanently
        # inert in production, unlike every other axis's _seeded_model() call,
        # which already checked metadata_json first.
        device_type = self.store.get_device_metadata(device_id).get("device_type") \
            or self._device_type_column(device_id)
        prior = self._load_population_prior(device_type, axis, hour=0)
        if prior is None:
            cohort_key = self._device_cohort_key(device_id)
            if cohort_key:
                prior = self._load_cohort_prior(cohort_key, axis, hour=0)
        if prior is not None:
            return MarkovBaseline.from_dict(prior)
        return MarkovBaseline(ACTIVITY_STATES if axis == "activity_state" else [])

    def _save_markov(self, device_id: str, axis: str, markov: MarkovBaseline, now: float) -> None:
        self.store._conn.execute(
            "INSERT INTO device_baselines "
            "(device_id, metric, hour, regime_id, model_kind, posterior_params_json, run_length_json, n, updated_at) "
            "VALUES (?, ?, 0, 0, 'markov', ?, '[]', ?, ?) "
            "ON CONFLICT(device_id, metric, hour, regime_id) DO UPDATE SET "
            "posterior_params_json=excluded.posterior_params_json, n=excluded.n, updated_at=excluded.updated_at",
            (device_id, axis, json.dumps(markov.to_dict()),
             sum(sum(b.values()) for b in markov.counts1.values()), now),
        )
        self.store._maybe_commit()

    # ---------------------------------------------------------- outage-gap correctness (BOCPD)

    def gap_since_last_observation(self, device_id: str, now: Optional[float] = None) -> float:
        """Wall-clock seconds since this device's last real update through
        this engine -- callers (the ingest daemon, on resume after a health-
        manager-reported outage) use this to discount a known downtime gap
        rather than letting BOCPD read 'no data for N minutes' as evidence
        the device's behavior itself changed. 0.0 for a device never seen
        before (nothing to discount)."""
        last = self._last_observed_at.get(device_id)
        if last is None:
            return 0.0
        return max(0.0, (now if now is not None else time.time()) - last)
