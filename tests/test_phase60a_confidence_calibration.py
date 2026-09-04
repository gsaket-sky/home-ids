"""
Standalone runtime test for Phase 60a (Gap 6 item 4, confidence conflation --
Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md): online Beta-Binomial calibration
scaffold for Ollama's self-reported `confidence`.

Pure data-collection phase -- ConfidenceCalibrator.get_calibrated() is built and
tested here but not yet consulted by any decision logic anywhere (that's Phase 60b,
deferred until buckets have real sample volume). This phase only wires HARVESTING:
_load_cache() records a weak-benign label for any cache entry that survives its whole
TTL having been action_taken (never contradicted, never re-escalated, never
fingerprint-invalidated -- see Phase 57), and main()'s confirmed-threat branch records
an immediate, stronger malicious label right where record_confirmed_threat() already
fires.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase60a_confidence_calibration.py`

Sections:
  A. ConfidenceCalibrator -- bucketing, asymmetric priors, conjugate updates,
     min-sample gate (None below MIN_SAMPLES_FOR_CALIBRATION), benign/malicious
     tracks stay independent, persistence round-trip
  B. Source-level wiring in ollama_soc.py -- _load_cache() gained an optional
     calibrator param (backward compatible, existing callers unaffected);
     main() instantiates one and threads it through; the confirmed-threat branch
     records an immediate label
"""
import sys
import tempfile
import os
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.confidence_calibration import (
    ConfidenceCalibrator, MIN_SAMPLES_FOR_CALIBRATION, _bucket_index,
)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: ConfidenceCalibrator
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: ConfidenceCalibrator ---")

check("_bucket_index buckets correctly (0.35 -> bucket 3)", _bucket_index(0.35) == 3)
check("_bucket_index clamps confidence==1.0 into the LAST bucket, not an 11th one",
      _bucket_index(1.0) == 9)
check("_bucket_index clamps out-of-range values (negative, >1.0) instead of crashing",
      _bucket_index(-0.5) == 0 and _bucket_index(5.0) == 9)

_tmpdir = tempfile.mkdtemp()
_calib_path = os.path.join(_tmpdir, "confidence_calibration.json")
calib = ConfidenceCalibrator(_calib_path)

check("a brand-new calibrator returns None (not calibrated) for every bucket -- "
      "the prior alone isn't a calibration",
      calib.get_calibrated("benign", 0.9) is None
      and calib.get_calibrated("malicious", 0.9) is None)

for _ in range(MIN_SAMPLES_FOR_CALIBRATION):
    calib.record_outcome("benign", 0.95, correct=True)

check(f"after {MIN_SAMPLES_FOR_CALIBRATION} consistent 'correct' labels in one bucket, "
      "that bucket IS calibrated (crosses MIN_SAMPLES_FOR_CALIBRATION)",
      calib.get_calibrated("benign", 0.95) is not None)

check("a calibrated bucket with all-correct labels returns a value close to 1.0 "
      "(high posterior mean)",
      calib.get_calibrated("benign", 0.95) > 0.9)

check("a DIFFERENT bucket (0.05, untouched) is still uncalibrated -- buckets don't "
      "leak sample credit into each other",
      calib.get_calibrated("benign", 0.05) is None)

check("the MALICIOUS track is completely independent -- pumping the benign track "
      "full of samples didn't calibrate malicious at all",
      calib.get_calibrated("malicious", 0.95) is None)

calib2 = ConfidenceCalibrator(_calib_path)
check("persistence round-trip: a freshly-loaded calibrator from the same path sees "
      "the same calibrated value (state actually saved to disk, not just in-memory)",
      calib2.get_calibrated("benign", 0.95) == calib.get_calibrated("benign", 0.95))

for _ in range(MIN_SAMPLES_FOR_CALIBRATION * 3):
    calib.record_outcome("malicious", 0.2, correct=False)  # low-confidence malicious calls, mostly wrong
check("a bucket with mostly-incorrect labels calibrates toward a LOW value, not just "
      "'is calibrated or not' -- the direction of the labels actually moves the mean",
      calib.get_calibrated("malicious", 0.2) < 0.3)

check("an unrecognized classification string (neither benign nor malicious) is "
      "silently ignored by record_outcome, not a crash",
      calib.record_outcome("unknown", 0.5, correct=True) is None)

check("get_calibrated() for an unrecognized classification returns None cleanly",
      calib.get_calibrated("unknown", 0.5) is None)

_counts = calib.sample_counts()
check("sample_counts() reports real (non-prior) observations per bucket, both tracks",
      isinstance(_counts, dict) and "benign" in _counts and "malicious" in _counts
      and len(_counts["benign"]) == 10 and _counts["benign"][9] >= MIN_SAMPLES_FOR_CALIBRATION)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: source-level wiring
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section B: source-level wiring in ollama_soc.py ---")

_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("_load_cache() gained an optional calibrator= param (backward compatible -- "
      "existing/test callers with no calibrator argument are unaffected)",
      "def _load_cache(cache_path: Path, ttl_seconds: float, calibrator=None) -> dict:" in _soc_src)

check("_load_cache() harvests a weak-benign label only for entries that were "
      "actually action_taken AND classified benign -- not every expiring entry",
      'calibrator.record_outcome("benign", float(v.get("confidence", 0.0)), correct=True)' in _soc_src
      and 'v.get("action_taken") and v.get("classification") == "benign"' in _soc_src)

check("main() instantiates a ConfidenceCalibrator and threads it into _load_cache()",
      "calibrator = ConfidenceCalibrator(" in _soc_src
      and "cache = _load_cache(cache_path, cache_ttl_seconds, calibrator=calibrator)" in _soc_src)

check("the confirmed-threat branch records an immediate malicious label right where "
      "record_confirmed_threat() already fires",
      'calibrator.record_outcome("malicious", float(response_json.get("confidence", 0.0)), correct=True)' in _soc_src)

check("ConfidenceCalibrator is imported from intelligence.confidence_calibration, "
      "not redefined locally",
      "from intelligence.confidence_calibration import ConfidenceCalibrator" in _soc_src)

# Backward-compat sanity: the existing (pre-Phase-60a) call shape -- no calibrator arg
# -- must still work exactly as before.
import importlib
_ollama_soc_mod = importlib.import_module("ollama_soc")
_tmp_cache_path = _PathForSysPath(_tmpdir) / "ollama_analysis_cache_empty.json"
check("_load_cache() with NO calibrator argument (old call shape) still works on a "
      "nonexistent cache file, returns {} -- doesn't require the new param",
      _ollama_soc_mod._load_cache(_tmp_cache_path, 3600.0) == {})

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 60a confidence-calibration checks PASSED.")
