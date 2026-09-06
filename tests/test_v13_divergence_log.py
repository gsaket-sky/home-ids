"""
Standalone runtime test for v13's divergence comparator (src/v13/compare/divergence_log.py,
Phase 7 wiring -- Documentation/V13_REMAINING_WORK.md item A8).

Covers: AlertsJsonlTailer's cursor persistence/partial-line safety/rotation
(same algorithm as the other v13 tailers, independently verified here);
_extract_vcurrent_fields' real-shape parsing and missing-field safety;
compare_window's full classification matrix (AGREE, DIFFERENT_PATH,
VCURRENT_ONLY both sub-cases, V13_ONLY, and the "no divergence" case for a
v13 BENIGN decision with nothing to compare against); tolerance-window
edges; and run_comparison's end-to-end wiring with a real GraphStore.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_divergence_log.py`
"""
import json
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath

sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.compare.divergence_log import (  # noqa: E402
    AlertsJsonlTailer, _extract_vcurrent_fields, compare_window,
    append_divergences_jsonl, run_comparison, TOLERANCE_SECONDS,
)
from v13.graph.store import GraphStore  # noqa: E402


# --- AlertsJsonlTailer: cursor persistence, partial-line safety, rotation ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    alerts_path = tmp_path / "alerts.json"
    cursor_path = tmp_path / "cursor.json"

    alerts_path.write_text('{"device":{"ip":"1.2.3.4"},"timestamp":1.0}\n', encoding="utf-8")
    tailer = AlertsJsonlTailer(alerts_path, cursor_path)
    check("a fresh tailer seeks to EOF, does not replay pre-existing content",
          tailer.read_new_alerts() == [])

    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write('{"device":{"ip":"1.2.3.5"},"timestamp":2.0}\n')
    alerts = tailer.read_new_alerts()
    check("read_new_alerts picks up a newly-appended complete line", len(alerts) == 1 and alerts[0]["timestamp"] == 2.0)

    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write('{"device":{"ip":"1.2.3.6"}')  # no trailing newline
    check("a not-yet-newline-terminated line is left for the next poll", tailer.read_new_alerts() == [])

    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write(',"timestamp":3.0}\n')
    alerts2 = tailer.read_new_alerts()
    check("the same line is picked up once its newline actually arrives",
          len(alerts2) == 1 and alerts2[0]["device"]["ip"] == "1.2.3.6")

    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write("not valid json\n")
        f.write('{"device":{"ip":"1.2.3.7"},"timestamp":4.0}\n')
    alerts3 = tailer.read_new_alerts()
    check("a malformed JSON line is skipped, not fatal, later lines still process",
          len(alerts3) == 1 and alerts3[0]["device"]["ip"] == "1.2.3.7")

    tailer2 = AlertsJsonlTailer(alerts_path, cursor_path)
    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write('{"device":{"ip":"1.2.3.8"},"timestamp":5.0}\n')
    alerts4 = tailer2.read_new_alerts()
    check("a new tailer instance resumes from the saved cursor, not EOF or 0",
          len(alerts4) == 1 and alerts4[0]["device"]["ip"] == "1.2.3.8")

    alerts_path.unlink()
    alerts_path.write_text('{"device":{"ip":"1.2.3.9"},"timestamp":6.0}\n', encoding="utf-8")
    alerts5 = tailer2.read_new_alerts()
    check("a rotated (replaced) alerts.json is detected and re-read from position 0",
          len(alerts5) == 1 and alerts5[0]["device"]["ip"] == "1.2.3.9")


# --- _extract_vcurrent_fields ---
real_shaped_alert = {
    "device": {"id": "abc123", "ip": "192.168.1.50", "hostname": "test-device", "type": "smart_tv"},
    "timestamp": 1000.0, "hee_decision_path": "hypothesis_suspicious",
    "signature": "NETWORK_INTRUSION", "risk": 4.0,
}
fields = _extract_vcurrent_fields(real_shaped_alert)
check("_extract_vcurrent_fields extracts device.ip, not a top-level ip field",
      fields is not None and fields["device_ip"] == "192.168.1.50")
check("_extract_vcurrent_fields extracts decision_path/signature/risk correctly",
      fields["decision_path"] == "hypothesis_suspicious" and fields["signature"] == "NETWORK_INTRUSION"
      and fields["risk"] == 4.0)
check("_extract_vcurrent_fields returns None when device.ip is missing",
      _extract_vcurrent_fields({"timestamp": 1.0}) is None)
check("_extract_vcurrent_fields returns None when timestamp is missing",
      _extract_vcurrent_fields({"device": {"ip": "1.2.3.4"}}) is None)


# --- compare_window: the full classification matrix ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    store = GraphStore(str(tmp_path / "compare_test.db"))
    now = 1_000_000.0

    def alert(ip, ts, decision_path, signature="NETWORK_INTRUSION", risk=4.0):
        return {"device": {"ip": ip}, "timestamp": ts, "hee_decision_path": decision_path,
                 "signature": signature, "risk": risk}

    # AGREE: v13 decision with the SAME decision_path within tolerance
    store.insert_decision(device_id="10.0.0.1", timestamp=now, state="HIGH",
                            decision_path="hypothesis_high", confidence=0.9, risk_score=8.0)
    result = compare_window(store, [alert("10.0.0.1", now + 10, "hypothesis_high")], since=now - 10, until=now + 100)
    agree = [d for d in result if d.device_ip == "10.0.0.1"]
    check("compare_window classifies matching decision_path as AGREE",
          len(agree) == 1 and agree[0].kind == "AGREE")

    # DIFFERENT_PATH: both non-benign, different decision_path
    store.insert_decision(device_id="10.0.0.2", timestamp=now, state="SUSPICIOUS",
                            decision_path="hypothesis_suspicious", confidence=0.4, risk_score=4.0)
    result = compare_window(store, [alert("10.0.0.2", now + 10, "tier5_confirmed")], since=now - 10, until=now + 100)
    diff = [d for d in result if d.device_ip == "10.0.0.2"]
    check("compare_window classifies same-device-different-path as DIFFERENT_PATH",
          len(diff) == 1 and diff[0].kind == "DIFFERENT_PATH")

    # VCURRENT_ONLY (v13 evaluated but BENIGN)
    store.insert_decision(device_id="10.0.0.3", timestamp=now, state="BENIGN",
                            decision_path="benign", confidence=0.0, risk_score=0.0)
    result = compare_window(store, [alert("10.0.0.3", now + 10, "hypothesis_high")], since=now - 10, until=now + 100)
    vc_benign = [d for d in result if d.device_ip == "10.0.0.3"]
    check("compare_window classifies a v13-BENIGN-nearby alert as VCURRENT_ONLY, flagged evaluated_but_benign",
          len(vc_benign) == 1 and vc_benign[0].kind == "VCURRENT_ONLY" and vc_benign[0].v13_evaluated_but_benign is True)

    # VCURRENT_ONLY (no v13 decision at all for this device)
    result = compare_window(store, [alert("10.0.0.4", now + 10, "hypothesis_high")], since=now - 10, until=now + 100)
    vc_none = [d for d in result if d.device_ip == "10.0.0.4"]
    check("compare_window classifies a device with NO v13 decision at all as VCURRENT_ONLY, not evaluated_but_benign",
          len(vc_none) == 1 and vc_none[0].kind == "VCURRENT_ONLY" and vc_none[0].v13_evaluated_but_benign is False)

    # V13_ONLY: a real v13 non-benign decision with no corresponding alert
    store.insert_decision(device_id="10.0.0.5", timestamp=now, state="HIGH",
                            decision_path="hypothesis_high", confidence=0.9, risk_score=8.0)
    result = compare_window(store, [], since=now - 10, until=now + 100)
    v13_only = [d for d in result if d.device_ip == "10.0.0.5"]
    check("compare_window classifies an unmatched non-benign v13 decision as V13_ONLY",
          len(v13_only) == 1 and v13_only[0].kind == "V13_ONLY")

    # A v13 BENIGN decision with no matching alert must NOT be a divergence at all
    store.insert_decision(device_id="10.0.0.6", timestamp=now, state="BENIGN",
                            decision_path="benign", confidence=0.0, risk_score=0.0)
    result = compare_window(store, [], since=now - 10, until=now + 100)
    benign_unmatched = [d for d in result if d.device_ip == "10.0.0.6"]
    check("a v13 BENIGN decision with nothing to compare against produces NO divergence record",
          len(benign_unmatched) == 0)

    # Tolerance window: just inside vs. just outside
    store.insert_decision(device_id="10.0.0.7", timestamp=now, state="HIGH",
                            decision_path="hypothesis_high", confidence=0.9, risk_score=8.0)
    inside = compare_window(store, [alert("10.0.0.7", now + TOLERANCE_SECONDS - 1, "hypothesis_high")],
                              since=now - 10, until=now + TOLERANCE_SECONDS + 100)
    inside_matches = [d for d in inside if d.device_ip == "10.0.0.7"]
    check("an alert just INSIDE the tolerance window correlates (AGREE, not VCURRENT_ONLY)",
          len(inside_matches) == 1 and inside_matches[0].kind == "AGREE")

    store.insert_decision(device_id="10.0.0.8", timestamp=now, state="HIGH",
                            decision_path="hypothesis_high", confidence=0.9, risk_score=8.0)
    outside = compare_window(store, [alert("10.0.0.8", now + TOLERANCE_SECONDS + 50, "hypothesis_high")],
                               since=now - 10, until=now + TOLERANCE_SECONDS + 100)
    outside_matches = [d for d in outside if d.device_ip == "10.0.0.8"]
    # An alert outside tolerance does NOT correlate with the nearby v13
    # decision -- so BOTH sides end up unmatched and are independently
    # reported: the alert as VCURRENT_ONLY (no v13 decision found nearby) and
    # the v13 decision as its own V13_ONLY (no v-current alert found nearby).
    # This is correct, not a bug -- neither side's signal found its match.
    check("an alert just OUTSIDE the tolerance window does not AGREE with the nearby v13 decision",
          not any(d.kind in ("AGREE", "DIFFERENT_PATH") for d in outside_matches))
    check("outside tolerance, the alert is reported VCURRENT_ONLY with no v13 decision attached",
          any(d.kind == "VCURRENT_ONLY" and d.v13_state is None for d in outside_matches))
    check("outside tolerance, the v13 decision is INDEPENDENTLY reported as V13_ONLY (both sides miss)",
          any(d.kind == "V13_ONLY" for d in outside_matches))

    store.close()


# --- append_divergences_jsonl ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    out_path = tmp_path / "nested" / "divergences.jsonl"
    from v13.compare.divergence_log import Divergence
    divs = [Divergence(kind="AGREE", device_ip="1.2.3.4", timestamp=1.0)]
    append_divergences_jsonl(divs, out_path)
    check("append_divergences_jsonl creates parent directories if missing", out_path.exists())
    lines = out_path.read_text(encoding="utf-8").strip().split("\n")
    check("append_divergences_jsonl writes one real, parseable JSON line per divergence",
          len(lines) == 1 and json.loads(lines[0])["kind"] == "AGREE")
    append_divergences_jsonl(divs, out_path)
    check("append_divergences_jsonl appends, does not overwrite, on a second call",
          len(out_path.read_text(encoding="utf-8").strip().split("\n")) == 2)


# --- run_comparison: end-to-end wiring ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    store = GraphStore(str(tmp_path / "run_test.db"))
    alerts_path = tmp_path / "alerts.json"
    alerts_path.write_text("", encoding="utf-8")
    tailer = AlertsJsonlTailer(alerts_path, tmp_path / "cursor.json")
    out_path = tmp_path / "divergence.jsonl"

    now = time.time()
    check("run_comparison returns an empty list when no new alerts have arrived",
          run_comparison(store, tailer, out_path, now=now) == [])

    store.insert_decision(device_id="9.9.9.9", timestamp=now, state="HIGH",
                            decision_path="hypothesis_high", confidence=0.9, risk_score=8.0)
    with open(alerts_path, "a", encoding="utf-8") as f:
        f.write(json.dumps({"device": {"ip": "9.9.9.9"}, "timestamp": now,
                              "hee_decision_path": "hypothesis_high", "signature": "X", "risk": 8.0}) + "\n")
    found = run_comparison(store, tailer, out_path, now=now + 1)
    check("run_comparison finds and returns a real divergence record end-to-end", len(found) == 1)
    check("run_comparison persists divergences to the output JSONL file", out_path.exists())
    store.close()


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 divergence-log checks PASSED.")
