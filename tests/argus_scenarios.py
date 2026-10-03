"""Helpers that let scenario tests written with detector-shaped Evidence (intelligence/hypotheses/evidence.py, what the
detectors emit) run against the argus engines that make the live decisions.

  DecisionEngine().evaluate(evidence, rep, device_type, baseline_familiarity, features=, is_safe=)
      -> argus/ops/live_engine.evaluate(), the exact call pipeline.py makes (no graph: no device_id)
  HypothesisEngine().evaluate_all(evidence, rep, device_type, baseline_familiarity)
      -> argus.hypotheses.engine.HypothesisEngine on the converted, freshness-scored evidence
  <Name>Hypothesis().evaluate(evidence, rep, ...)
      -> the argus hypothesis class of the same name, same conversion

Not a test file itself (no test_ prefix).
"""
import copy
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import argus.hypotheses.engine as _hyp  # noqa: E402
from argus.decision.engine import DecisionState  # noqa: E402,F401  (re-exported)
from argus.evidence.ingest import convert_list  # noqa: E402
from argus.hypotheses.independence import INDEPENDENCE_FAMILY_MAP  # noqa: E402
from argus.ops import live_engine as _live  # noqa: E402


def _to_v2(evidence, now=None):
    """Detector Evidence -> argus Evidence. Items never stamped (timestamp 0 -- the live EvidenceStore stamps them
    when added) count as observed now."""
    evidence = list(evidence or [])
    if evidence and not hasattr(evidence[0], "evidence_type"):
        now = now if now is not None else time.time()
        stamped = []
        for e in evidence:
            if not getattr(e, "timestamp", 0):
                e = copy.copy(e)
                e.timestamp = now
            stamped.append(e)
        return convert_list(stamped, INDEPENDENCE_FAMILY_MAP)
    return evidence


def to_scored(evidence, now=None):
    """Detector Evidence (or argus Evidence) -> the ScoredEvidence list argus hypotheses evaluate."""
    items = list(evidence or [])
    if items and isinstance(items[0], _hyp.ScoredEvidence):
        return items
    v2 = _to_v2(items, now)
    return _hyp.score_evidence(v2, now=now if now is not None else time.time())


class DecisionEngine:
    def evaluate(self, evidence, rep_vector, device_type="", baseline_familiarity=0.0, features=None, is_safe=False,
                 **_ignored):
        return _live.evaluate(list(evidence or []), rep_vector, device_type, baseline_familiarity,
                              features=features, is_safe=is_safe)


class HypothesisEngine(_hyp.HypothesisEngine):
    def __init__(self):
        super().__init__()
        # the same hypotheses, as the wrapped classes this module exports (so isinstance checks hold)
        self.attack_hypotheses = [globals()[type(h).__name__]() for h in self.attack_hypotheses]
        self.benign_hypotheses = [globals()[type(h).__name__]() for h in self.benign_hypotheses]

    def evaluate_all(self, evidence, rep_vector, device_type="", baseline_familiarity=0.0, *args, **kwargs):
        return super().evaluate_all(_to_v2(evidence), rep_vector, device_type, baseline_familiarity, *args, **kwargs)


def _wrap(cls):
    class Wrapped(cls):
        def evaluate(self, ev_store, rep_vector, *args, **kwargs):
            return super().evaluate(to_scored(ev_store), rep_vector, *args, **kwargs)
    Wrapped.__name__ = cls.__name__
    return Wrapped


for _name in dir(_hyp):
    _obj = getattr(_hyp, _name)
    if isinstance(_obj, type) and issubclass(_obj, _hyp.Hypothesis) and _obj is not _hyp.Hypothesis:
        globals()[_name] = _wrap(_obj)

HYPOTHESIS_RELEVANT_EVIDENCE_TYPES = getattr(_hyp, "HYPOTHESIS_RELEVANT_EVIDENCE_TYPES", {})
ATTACK_SHAPED_EVIDENCE_TYPES = getattr(_hyp, "ATTACK_SHAPED_EVIDENCE_TYPES", set())
