"""
Standalone runtime test for Phase 67 (HEE_ROADMAP.md item 6, malicious-track
calibration wiring): `ConfidenceCalibrator`'s malicious track was already collecting
real observations (`record_outcome("malicious", ...)`, ollama_soc.py) but nothing ever
consumed it -- only the benign track was wired (Phase 63b, into immunization TTL).

The fix mirrors the benign wiring's exact shape, applied to a NEW target since a
malicious verdict has no TTL-shaped consumer the way benign immunization does:
`local_intel.py`'s confirmed-IOC TTL. `LocalConfirmedIntel.record()`/`check()`/
`all_confirmed()`/`prune_expired()` gained a per-entry `ttl_seconds` override (same
shape-agnostic pattern as fp_engine.py's own trust-cache `_trust_entry_ttl()`, Phase
52) -- `None` (every caller before this phase) means "use the instance-wide default".
`fp_engine.py`'s `record_confirmed_threat()` threads an optional `ttl_seconds` through
to both the domain and IP `local_intel.record()` calls. `ollama_soc.py`'s malicious-
verdict branch now calls `calibrator.get_calibrated("malicious", ...)` and feeds it
through the EXISTING `_apply_confidence_calibration()` helper (unchanged, already
self-gating) to compute the confirmed-intel TTL -- self-activating exactly like the
benign case: byte-identical to the fixed 30-day default until the malicious track
separately crosses `MIN_SAMPLES_FOR_CALIBRATION=20` real observations, then starts
modulating on its own, no further code change required.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase67_malicious_calibration_wiring.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))
import tempfile
import time

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.local_intel import LocalConfirmedIntel, DEFAULT_TTL_SECONDS
from intelligence.fp_engine import AutonomousFPEngine
from intelligence.confidence_calibration import ConfidenceCalibrator, MIN_SAMPLES_FOR_CALIBRATION
from ollama_soc import _apply_confidence_calibration


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: LocalConfirmedIntel per-entry TTL override
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    intel = LocalConfirmedIntel(tmpdir, ttl_seconds=3600.0)  # instance default: 1 hour
    intel.record("ip", "1.2.3.4", "devA", ttl_seconds=0.01)  # this entry: ~effectively already expired
    time.sleep(0.05)
    check("THE FIX: a per-entry ttl_seconds override is respected by check() -- this "
          "entry's own short TTL expired even though the instance default (1h) hasn't",
          intel.check("ip", "1.2.3.4") is None)

    intel.record("ip", "5.6.7.8", "devB")  # no override -- uses instance default (1h, not expired)
    check("REGRESSION GUARD: an entry with no ttl_seconds override still uses the "
          "instance-wide default and is NOT expired",
          intel.check("ip", "5.6.7.8") is not None)

    intel.record("domain", "evil.example.com", "devC", ttl_seconds=7200.0)
    entry = intel.check("domain", "evil.example.com")
    check("a real per-entry ttl_seconds is stored on the entry itself",
          entry is not None and entry.get("ttl_seconds") == 7200.0, f"got {entry}")

    check("REGRESSION GUARD: a manually-constructed LEGACY entry (no ttl_seconds key "
          "at all, exactly what every pre-Phase-67 entry looks like on disk) still "
          "reads correctly via the instance-wide fallback",
          intel._entry_ttl({"last_confirmed": time.time()}) == 3600.0)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: record_confirmed_threat() threads ttl_seconds through to BOTH branches
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)
    # NOTE: RFC 5737 documentation-range addresses (198.51.100.0/24 etc.) will NOT
    # work here -- Python's ipaddress module classifies them as is_private=True, which
    # _is_ip_protected_from_confirmed_intel() correctly refuses (by design, this store
    # can only record genuinely-external infrastructure). 45.33.32.156 is a real,
    # ordinary public IP with no asn_owner passed here, so the cloud/CDN-provider ASN
    # check (which only runs `if asn_owner`) can't fire regardless of who really owns it.
    fp.record_confirmed_threat(
        "dev_x", "confirmed-malicious-domain.example", "45.33.32.156",
        reason="TEST", ttl_seconds=999.0,
    )
    domain_entry = fp.local_intel.check("domain", "confirmed-malicious-domain.example")
    ip_entry = fp.local_intel.check("ip", "45.33.32.156")
    check("record_confirmed_threat() threads ttl_seconds through to the DOMAIN branch",
          domain_entry is not None and domain_entry.get("ttl_seconds") == 999.0, f"got {domain_entry}")
    check("record_confirmed_threat() threads ttl_seconds through to the IP branch",
          ip_entry is not None and ip_entry.get("ttl_seconds") == 999.0, f"got {ip_entry}")

    fp.record_confirmed_threat("dev_y", "another-domain.example", "45.33.32.157", reason="TEST")
    default_entry = fp.local_intel.check("domain", "another-domain.example")
    check("REGRESSION GUARD: omitting ttl_seconds (every existing caller, e.g. "
          "fp_engine's own internal Stage-1 hard-stop path) still works exactly as "
          "before -- falls back to the instance default",
          default_entry is not None and default_entry.get("ttl_seconds") == DEFAULT_TTL_SECONDS,
          f"got {default_entry}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: end-to-end self-activation -- byte-identical until real volume exists,
# then modulates automatically, matching the benign wiring's own proven behavior
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    calibrator = ConfidenceCalibrator(tmpdir + "/confidence_calibration.json")

    # Before any real observations: get_calibrated() returns None (self-gated), so
    # _apply_confidence_calibration() must return the raw default TTL UNCHANGED.
    raw_conf = 0.9
    calibrated_before = calibrator.get_calibrated("malicious", raw_conf)
    ttl_before = _apply_confidence_calibration(DEFAULT_TTL_SECONDS, raw_conf, calibrated_before)
    check("BEFORE enough samples: get_calibrated() returns None (self-gated)",
          calibrated_before is None)
    check("BEFORE enough samples: confirmed-intel TTL is BYTE-IDENTICAL to the fixed "
          "default -- no behavior change until real volume exists",
          ttl_before == DEFAULT_TTL_SECONDS, f"got {ttl_before}")

    # Feed exactly MIN_SAMPLES_FOR_CALIBRATION real "confidence=0.9, correct" labels
    # into the 0.9 bucket -- no code change needed for this to start mattering, only
    # data arriving, which is the whole point of this phase.
    for _ in range(MIN_SAMPLES_FOR_CALIBRATION):
        calibrator.record_outcome("malicious", raw_conf, correct=True)

    calibrated_after = calibrator.get_calibrated("malicious", raw_conf)
    ttl_after = _apply_confidence_calibration(DEFAULT_TTL_SECONDS, raw_conf, calibrated_after)
    check("AFTER crossing MIN_SAMPLES_FOR_CALIBRATION real observations: "
          "get_calibrated() now returns a real value, automatically, with NO code "
          "change or deploy -- this is the exact 'self-activates as samples arrive' "
          "property the malicious track was missing before this phase",
          calibrated_after is not None, f"got {calibrated_after}")
    check("AFTER real volume: the confirmed-intel TTL is no longer the untouched "
          "default -- calibration is actually influencing the outcome",
          ttl_after != DEFAULT_TTL_SECONDS, f"got {ttl_after}")
    # Malicious prior is deliberately conservative (Beta(1,3)) -- exactly 20 correct
    # observations (alpha=1+20=21, beta=3 unchanged) gives a posterior mean of
    # 21/24=0.875, which is SLIGHTLY BELOW the 0.9 raw confidence being calibrated,
    # not above it -- the conservative prior's residual weight hasn't fully washed out
    # yet at the minimum sample floor. This is intentional design (module docstring:
    # "a handful of early... labels can't produce a falsely-confident calibrated
    # number"), not a bug -- verify the actual math, not a naive "clean record ->
    # extends TTL" assumption.
    check("at exactly MIN_SAMPLES_FOR_CALIBRATION, the conservative prior's residual "
          "weight still pulls the posterior mean (0.875) slightly BELOW the 0.9 raw "
          "confidence -- the TTL shortens slightly, not lengthens, at this sample size",
          calibrated_after is not None and abs(calibrated_after - 0.875) < 1e-9
          and ttl_after < ttl_before,
          f"got calibrated={calibrated_after}, ttl_before={ttl_before}, ttl_after={ttl_after}")
    check("the TTL scaling stays within _apply_confidence_calibration()'s own "
          "[0.4, 1.5] clamp -- never an unbounded swing",
          DEFAULT_TTL_SECONDS * 0.4 <= ttl_after <= DEFAULT_TTL_SECONDS * 1.5,
          f"got {ttl_after}")

    # Feed a much larger, sustained track record (180 more correct observations, 200
    # total) -- enough real volume to overwhelm the conservative prior's residual
    # weight and demonstrate the OTHER direction: a bucket that keeps proving reliable
    # over real volume eventually DOES earn a longer TTL than the untouched default,
    # exactly the "keeps improving as more samples arrive" property that was asked for.
    for _ in range(180):
        calibrator.record_outcome("malicious", raw_conf, correct=True)
    calibrated_mature = calibrator.get_calibrated("malicious", raw_conf)
    ttl_mature = _apply_confidence_calibration(DEFAULT_TTL_SECONDS, raw_conf, calibrated_mature)
    check("with real sustained volume (200 observations), the posterior (0.985) now "
          "exceeds the raw 0.9 confidence -- the TTL genuinely EXTENDS, demonstrating "
          "the calibration keeps improving/shifting as more real samples accumulate, "
          "not just a one-time activation",
          calibrated_mature is not None and calibrated_mature > raw_conf and ttl_mature > DEFAULT_TTL_SECONDS,
          f"got calibrated={calibrated_mature}, ttl={ttl_mature}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 67 malicious-calibration-wiring checks PASSED.")
