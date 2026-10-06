"""
CL-AFPE verdict labels (argus/cl_afpe/verdicts.py, MASTER_TODO M3 "CONFIRMED_THREAT while the reasoning says monitor").

On .94, 373 of 408 alerts in the 11 h after the 2026-10-05 deploy carried fp_verdict CONFIRMED_THREAT (Stage 3, low
false-positive probability) while the decision said "SUSPICIOUS / monitor"; 25 more came from Stage 1, some of them
from an old local confirmed-intel entry alone (a NordVPN server). Covers: a Stage-3 result is never CONFIRMED_THREAT;
a hard stop from the local confirmed-intel match alone is PREVIOUSLY_FLAGGED (still never suppressed); an independent
trigger keeps CONFIRMED_THREAT; old alerts read correctly (canonical_verdict); the alert records which Stage-1 checks
fired; the Telegram confidence line does not call a previously-flagged hit a signature match; the console counts each
verdict on its own and old Stage-3 records as "likely real"; the backtest's ground truth ignores Stage-3 results.

Run directly: `venv/Scripts/python.exe tests/test_argus_fp_verdict_labels.py`
"""
import json
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.cl_afpe.verdicts import (CONFIRMED_THREAT, FULL_SEVERITY_VERDICTS, LIKELY_REAL,  # noqa: E402
                                    PREVIOUSLY_FLAGGED, canonical_verdict, is_confirmed_threat)

# --- reading a verdict, old records included ---------------------------------------------------------------------------
check("an old Stage-3 CONFIRMED_THREAT reads as LIKELY_REAL",
      canonical_verdict({"verdict": "CONFIRMED_THREAT", "stage": "STAGE_3_COMBINED"}) == LIKELY_REAL)
check("an old Stage-1 CONFIRMED_THREAT stays a confirmation (its triggers were not stored)",
      is_confirmed_threat({"verdict": "CONFIRMED_THREAT", "stage": "STAGE_1_HARD_STOP"}))
check("a record without a stage keeps its label", canonical_verdict({"verdict": "CONFIRMED_THREAT"}) == CONFIRMED_THREAT)
check("new labels pass through", canonical_verdict({"verdict": "PREVIOUSLY_FLAGGED", "stage": "STAGE_1_HARD_STOP"})
      == PREVIOUSLY_FLAGGED and canonical_verdict({"verdict": "LIKELY_REAL", "stage": "STAGE_3_COMBINED"}) == LIKELY_REAL)
check("no fp_verdict is no verdict", canonical_verdict(None) is None and canonical_verdict("x") is None
      and not is_confirmed_threat(None))
check("Stage-3 and previously-flagged results are not confirmations",
      not is_confirmed_threat({"verdict": "LIKELY_REAL"}) and not is_confirmed_threat({"verdict": "PREVIOUSLY_FLAGGED"}))
check("all three are published at full severity", FULL_SEVERITY_VERDICTS == {CONFIRMED_THREAT, PREVIOUSLY_FLAGGED, LIKELY_REAL})

# --- the engine ----------------------------------------------------------------------------------------------------------
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402

SAFE = {"ti_risk": 0.0, "zeek_lateral_moves": 0, "zeek_ja3_malicious": 0, "zeek_ja4_malicious": 0,
        "zeek_honeypot_hits": 0, "abuseipdb_risk": 0.0, "outbound_bytes_z": 0.0}


def alert(device, domain, ip):
    return {"device": {"id": device, "hostname": device + "-host"},
            "network_context": {"queried_domain": domain, "destination_ip": ip},
            "signature": "", "timestamp": time.time()}


tmp = tempfile.mkdtemp(prefix="fp_verdict_labels_")
fp = ClAfpeEngine(GraphStore(str(Path(tmp) / "graph.db")), local_intel=LocalConfirmedIntel(tmp))
fp.record_confirmed_threat("dev_a", "flagged-before.example", "198.51.100.7", reason="unit_test")

v = fp.evaluate(alert("dev_b", "flagged-before.example", "198.51.100.7"), dict(SAFE))
check("a hard stop from the local confirmed-intel match alone is PREVIOUSLY_FLAGGED",
      v["verdict"] == PREVIOUSLY_FLAGGED and v["stage"] == "STAGE_1_HARD_STOP", str(v))
check("...and is still never suppressed", v["suppress"] is False)
check("...and names its trigger", any("Local confirmed-threat match" in r for r in v["reasons"]), str(v["reasons"]))

v2 = fp.evaluate(alert("dev_c", "flagged-before.example", "198.51.100.7"), dict(SAFE, ti_risk=3.5))
check("an independent trigger next to the local match keeps CONFIRMED_THREAT",
      v2["verdict"] == CONFIRMED_THREAT and v2["stage"] == "STAGE_1_HARD_STOP", str(v2))

v3 = fp.evaluate(alert("dev_d", "ordinary-unknown-xyz123.example", "203.0.113.20"), dict(SAFE))
check("a Stage-3 result is never CONFIRMED_THREAT",
      v3["stage"] == "STAGE_3_COMBINED" and v3["verdict"] != CONFIRMED_THREAT, str(v3))
check("a low-scoring Stage-3 result is LIKELY_REAL, published", v3["verdict"] in (LIKELY_REAL, "UNCERTAIN")
      and v3["suppress"] is False, str(v3))

# --- the Telegram confidence line ----------------------------------------------------------------------------------------
from core.pipeline import _build_confidence_line  # noqa: E402

label, line, mixed = _build_confidence_line(80, {"verdict": PREVIOUSLY_FLAGGED, "stage": "STAGE_1_HARD_STOP",
                                                 "reasons": ["Local confirmed-threat match: flagged-before.example"]}, 5, None)
check("a previously-flagged hit is not called a known-bad signature match",
      label == "Moderate" and "signature" not in line and "before" in line, line)
label2, line2, _ = _build_confidence_line(80, {"verdict": CONFIRMED_THREAT, "stage": "STAGE_1_HARD_STOP",
                                               "reasons": ["ThreatIntel IOC match (ti_risk=3.5)"]}, 5, None)
check("an independent hard stop still reads Very High", label2 == "Very High", line2)

# --- the console's counts ------------------------------------------------------------------------------------------------
from middleware.routers import overview_api  # noqa: E402

now = time.time()
records = [
    {"timestamp": now, "fp_verdict": {"verdict": "CONFIRMED_THREAT", "stage": "STAGE_1_HARD_STOP"}},
    {"timestamp": now, "fp_verdict": {"verdict": "PREVIOUSLY_FLAGGED", "stage": "STAGE_1_HARD_STOP"}},
    {"timestamp": now, "fp_verdict": {"verdict": "LIKELY_REAL", "stage": "STAGE_3_COMBINED"}},
    {"timestamp": now, "fp_verdict": {"verdict": "CONFIRMED_THREAT", "stage": "STAGE_3_COMBINED"}},   # before the split
    {"timestamp": now, "fp_verdict": {"verdict": "FALSE_POSITIVE", "stage": "STAGE_3_COMBINED"}},
    {"timestamp": now, "fp_verdict": {"verdict": "UNCERTAIN", "stage": "STAGE_3_COMBINED"}},
]
path = Path(tmp) / "alerts.json"
path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
st = overview_api._alert_stats(path)
check("the console counts only independent confirmations as confirmed threats", st["fp_confirmed_threats"] == 1, str(st))
check("previously flagged and likely real have their own counts (old Stage-3 records as likely real)",
      st["fp_previously_flagged"] == 1 and st["fp_likely_real"] == 2, str(st))
check("the counts still add up to the evaluations",
      st["fp_evaluations"] == 6 == st["fp_confirmed_threats"] + st["fp_previously_flagged"] + st["fp_likely_real"]
      + st["fp_suppressed"] + st["fp_uncertain"], str(st))
day = next(iter(st["fp_likely_real_by_day"]), None)
check("...per day too", day is not None and st["fp_likely_real_by_day"][day] == 2
      and st["fp_previously_flagged_by_day"][day] == 1)

# --- the backtest's ground truth -----------------------------------------------------------------------------------------
from argus.ops import backtest_job  # noqa: E402

src = Path(backtest_job.__file__).read_text(encoding="utf-8")
code = "\n".join(l for l in src.splitlines() if not l.strip().startswith("#"))
check("the backtest reads every confirmation through is_confirmed_threat()/canonical_verdict()",
      '.get("verdict") == "CONFIRMED_THREAT"' not in code and '.get("verdict") != "CONFIRMED_THREAT"' not in code
      and code.count("is_confirmed_threat(") >= 8)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("All CL-AFPE verdict label checks PASSED.")
