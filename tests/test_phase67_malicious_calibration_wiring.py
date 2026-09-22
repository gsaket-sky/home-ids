"""
Standalone runtime test for Phase 67 (HEE_ROADMAP.md item 6, malicious-track
calibration wiring)'s surviving, still-live half: `local_intel.py`'s per-entry TTL
override and `fp_engine.py`'s `record_confirmed_threat()` threading it through.

v16 NOTE: this file originally also covered a Section C -- `ConfidenceCalibrator`'s
malicious-track self-activation and `ollama_soc.py`'s `_apply_confidence_calibration()`
consuming it to modulate the confirmed-intel TTL. Both `intelligence/
confidence_calibration.py` and `scripts/ollama_soc.py` were retired in the v16
cleanup (the calibrator had no other consumer once ollama_soc.py was gone -- confirmed
via a repo-wide grep before deleting), so Section C was removed along with them.
Sections A/B below are unrelated to that mechanism and remain fully live.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase67_malicious_calibration_wiring.py`
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
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


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 67 malicious-calibration-wiring checks PASSED.")
