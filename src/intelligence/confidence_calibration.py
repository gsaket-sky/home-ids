"""
PHASE 60a (Gap 6 item 4, confidence conflation -- Documentation/
DECISION_LOGIC_DEPENDENCY_MAP.md): online Beta-Binomial calibration for Ollama's
self-reported `confidence`, fed by weak labels harvested from outcomes this codebase
already tracks. Data-collection scaffold only -- ConfidenceCalibrator.get_calibrated()
is not yet consulted by any decision logic (that's Phase 60b, deferred until buckets
have enough real samples to mean something). Nothing in this module changes pipeline
behavior; it only records and reads a small JSON file.

Why online Beta-Binomial instead of a batch-retrained model (e.g. reusing fp_engine's
own LightGBM setup): a home network's true-positive volume is too sparse to support a
periodic retrain cycle -- there's rarely enough of either class between retrains to
move the needle, and a batch model sitting stale between retrains is itself a form of
the exact staleness bug Phase 57 closed for the validator cache. A Beta(alpha, beta)
posterior per confidence bucket updates with a single conjugate increment per label,
no retrain step, and gets monotonically sharper (lower variance) as labels accumulate
-- it also degrades gracefully with a weakly-informative prior instead of crashing or
returning nonsense on a bucket with zero samples.

Two SEPARATE calibration tracks (benign vs malicious), not one shared curve -- a home
network accumulates benign-confirmed labels fast (most things really are benign) but
malicious-confirmed labels very slowly (that's the network being healthy, not a data
problem to paper over). Pooling them would let the abundant benign data silently
calibrate a malicious-confidence number that has no real support behind it. Priors are
asymmetric for the same reason: benign starts at Beta(2,2) (weak, easily moved);
malicious starts skewed conservative at Beta(1,3) (mean 0.25) so a handful of
early "malicious, confidence 0.9" labels can't produce a falsely-confident calibrated
number before the bucket has real volume -- see get_calibrated()'s min-sample gate.
"""
import json
import logging
import threading
from pathlib import Path
from typing import Optional

LOGGER = logging.getLogger("home_ids.confidence_calibration")

_NUM_BUCKETS = 10  # [0.0-0.1), [0.1-0.2), ..., [0.9-1.0]
_BENIGN_PRIOR = (2.0, 2.0)      # mean 0.5, weakly-informative, easily moved
_MALICIOUS_PRIOR = (1.0, 3.0)   # mean 0.25, deliberately conservative -- see module docstring

# PHASE 60a: a bucket's calibrated value is only meaningful once it has real volume
# behind it -- below this, get_calibrated() returns None (honest "not yet calibrated")
# rather than a confident-looking number computed from 2 samples. Chosen to match the
# same order of magnitude as fp_engine's own _BASELINE_FAMILIARITY_OBSERVATIONS (5)
# scaled up for a coarser, noisier signal (LLM confidence vs. a device's own repeated
# traffic pattern) -- not a rigorously derived statistical threshold, just a
# deliberately conservative floor that's easy to revisit once real data exists.
MIN_SAMPLES_FOR_CALIBRATION = 20


def _bucket_index(confidence: float) -> int:
    c = max(0.0, min(1.0, float(confidence)))
    idx = int(c * _NUM_BUCKETS)
    return min(idx, _NUM_BUCKETS - 1)  # confidence==1.0 lands in the last bucket, not a new 11th one


class ConfidenceCalibrator:
    """Persisted to state/confidence_calibration.json as
    {"benign": [[alpha, beta], ...10 buckets...], "malicious": [[alpha, beta], ...]}."""

    def __init__(self, state_path: str):
        self._path = Path(state_path)
        self._lock = threading.RLock()
        self._benign = [list(_BENIGN_PRIOR) for _ in range(_NUM_BUCKETS)]
        self._malicious = [list(_MALICIOUS_PRIOR) for _ in range(_NUM_BUCKETS)]
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            benign = raw.get("benign")
            malicious = raw.get("malicious")
            if isinstance(benign, list) and len(benign) == _NUM_BUCKETS:
                self._benign = [list(pair) for pair in benign]
            if isinstance(malicious, list) and len(malicious) == _NUM_BUCKETS:
                self._malicious = [list(pair) for pair in malicious]
        except Exception as e:
            LOGGER.warning(f"Could not read confidence_calibration.json ({e}) -- starting fresh, priors unchanged.")

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps({"benign": self._benign, "malicious": self._malicious}, indent=2),
                encoding="utf-8",
            )
        except Exception as e:
            LOGGER.error(f"Failed to save confidence_calibration.json: {e}")

    def record_outcome(self, classification: str, confidence: float, correct: bool) -> None:
        """Single conjugate Beta update -- no retrain, no batch step. `classification`
        is which track this label belongs to ("benign"|"malicious", matching
        ollama_soc.py's existing two-value enum -- see Phase 51's own comment on why
        that stayed a 2-way value). `correct` is whether the ORIGINAL verdict at that
        confidence turned out right (a weak or strong label harvested elsewhere --
        see ollama_soc.py's harvesting call sites for what currently feeds this)."""
        classification = (classification or "").lower()
        buckets = self._benign if classification == "benign" else (
            self._malicious if classification == "malicious" else None
        )
        if buckets is None:
            return
        idx = _bucket_index(confidence)
        with self._lock:
            if correct:
                buckets[idx][0] += 1.0
            else:
                buckets[idx][1] += 1.0
            self._save()

    def get_calibrated(self, classification: str, confidence: float) -> Optional[float]:
        """Posterior mean (alpha / (alpha + beta)) for this classification+confidence
        bucket, or None if the bucket hasn't accumulated MIN_SAMPLES_FOR_CALIBRATION
        real observations yet (the prior alone isn't "calibrated", it's a guess -- see
        module docstring). Not yet consulted by any decision logic (Phase 60b)."""
        classification = (classification or "").lower()
        buckets = self._benign if classification == "benign" else (
            self._malicious if classification == "malicious" else None
        )
        if buckets is None:
            return None
        idx = _bucket_index(confidence)
        with self._lock:
            alpha, beta = buckets[idx]
        prior_alpha, prior_beta = (_BENIGN_PRIOR if classification == "benign" else _MALICIOUS_PRIOR)
        real_observations = (alpha - prior_alpha) + (beta - prior_beta)
        if real_observations < MIN_SAMPLES_FOR_CALIBRATION:
            return None
        return alpha / (alpha + beta)

    def sample_counts(self) -> dict:
        """Real (non-prior) observation count per bucket, both tracks -- for a future
        dashboard/report line showing calibration maturity, same spirit as
        fp_engine.get_baseline_entry_count()."""
        with self._lock:
            benign_counts = [
                (a - _BENIGN_PRIOR[0]) + (b - _BENIGN_PRIOR[1]) for a, b in self._benign
            ]
            malicious_counts = [
                (a - _MALICIOUS_PRIOR[0]) + (b - _MALICIOUS_PRIOR[1]) for a, b in self._malicious
            ]
        return {"benign": benign_counts, "malicious": malicious_counts}
