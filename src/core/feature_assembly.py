"""
Typed assembly of the per-device feature dict the pipeline hands to the decision engine, the detectors, CL-AFPE and the
ML scorer (DETECTION_CORE_REWORK P0; MASTER_TODO 0d register row U3).

Before: `features = {**dns_features, **zeek_features, **last_connection_meta}` followed by ~20 `features[k] = v`
assignments. Any two producers of one key silently replaced each other -- the window's outbound byte total was overwritten
by the last connection's bytes (U3), and the "last connection" keys had two producers that disagreed (the oldest of the
device's addresses, then the current address). One dict, no owners: a collision was invisible.

Now every key has exactly one named owner:
  add_source(source, mapping)  -- a source's values (dns, zeek, ...)
  derive(stage, key, value)    -- a value computed from the above (z-scores, reputation context)
  gate(stage, replace, remove) -- a DECLARED replacement/removal of owned keys (the learning-period gate): recorded as
                                  the stage's own action, never as a collision
A key a second writer tries to take keeps its first owner's value, and the attempt is recorded in `collisions`
(`FeatureCollision(key, owner, intruder)`). The pipeline reports collisions as a "features" engine error (health probe
`engine_errors`) and keeps running -- a code defect must not stop every device's cycle; tests and tools use
`strict=True`, which raises. Pure: no I/O, no module state.
"""
from typing import Any, Dict, Iterable, List, Mapping, NamedTuple, Optional


class FeatureCollision(NamedTuple):
    key: str
    owner: str       # the writer that had the key first (its value is kept)
    intruder: str    # the writer that tried to take it


class FeatureAssembly:
    def __init__(self, strict: bool = False):
        self.strict = strict
        self.features: Dict[str, Any] = {}
        self._owner: Dict[str, str] = {}
        self.collisions: List[FeatureCollision] = []

    def owner(self, key: str) -> Optional[str]:
        return self._owner.get(key)

    def _take(self, writer: str, key: str, value: Any) -> None:
        owner = self._owner.get(key)
        if owner is None:
            self.features[key] = value
            self._owner[key] = writer
            return
        collision = FeatureCollision(key, owner, writer)
        if self.strict:
            raise ValueError(f"feature {key!r} is produced by both {owner!r} and {writer!r}")
        self.collisions.append(collision)

    def add_source(self, source: str, values: Mapping[str, Any]) -> "FeatureAssembly":
        for key, value in values.items():
            self._take(source, key, value)
        return self

    def derive(self, stage: str, key: str, value: Any) -> "FeatureAssembly":
        self._take(stage, key, value)
        return self

    def gate(self, stage: str, replace: Mapping[str, Any], remove: Iterable[str] = ()) -> "FeatureAssembly":
        """The declared replacement of keys other writers own (a gate that blanks features): the gate becomes their owner."""
        for key, value in replace.items():
            self.features[key] = value
            self._owner[key] = stage
        for key in remove:
            self.features.pop(key, None)
            self._owner.pop(key, None)
        return self
