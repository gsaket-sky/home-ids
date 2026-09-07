"""
Standalone runtime test for src/v13/ops/live_retro_hunter.py -- the scheduled job that
runs v13's RetroHunter against .94's own live graph (v13 full-architecture plan, Phase 4).

Not part of the pytest suite -- run directly: `python3 tests/test_v13_live_retro_hunter.py`.
"""
import json
import sys
import tempfile
import time
from unittest.mock import patch
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import v13.ops.live_retro_hunter as live_retro_hunter  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402

TMPDIR = _PathForSysPath(tempfile.mkdtemp(prefix="live_retro_hunter_test_"))

# Phase 7: redirect CL-AFPE's own v13-only local-intel store to an isolated temp
# dir for every test in this file -- the real default (v13/ops/live_engine.py's
# _CL_AFPE_LOCAL_INTEL_DIR, "state/v13_cl_afpe") is a relative path that would
# otherwise create real files under this repo's own working directory during a
# test run.
live_retro_hunter._CL_AFPE_LOCAL_INTEL_DIR = str(TMPDIR / "cl_afpe_local_intel_shared")


# --- no db yet: a clean no-op, not an error (matches live_prune.py's own convention) ---
_no_db_dir = TMPDIR / "no_db"
_no_db_dir.mkdir()
live_retro_hunter.CONFIG = {"state_path": str(_no_db_dir / "ids_state.json")}
live_retro_hunter.main()
check("main() is a clean no-op when the graph db doesn't exist yet (engine=v_current, "
      "or live_engine.py has never run with a device_id)",
      not (_no_db_dir / "v13_graph.db").exists())
check("main() still writes job_health.json even on the no-op path",
      json.loads((_no_db_dir / "job_health.json").read_text())["live_retro_hunter"]["skipped"] == "no_db_yet")


# --- real hunt against a real graph: a fake lookup, NO real network call ---
# real_threat_intel_lookup_factory() is mocked at the call site -- never invoked for
# real here, matching test_v13_retro_hunter.py's own established convention for the
# exact same reason (it calls ThreatIntel._refresh_all(), a real network round-trip).
_real_dir = TMPDIR / "real"
_real_dir.mkdir()
db_path = _real_dir / "v13_graph.db"
store = GraphStore(str(db_path))
now = time.time()
store.insert_evidence(Evidence(
    device_id="dev1", destination_id="evil.example.com", evidence_type="dns_query",
    independence_family="dns", timestamp=now - 2 * 86400, source="zeek",
))
store.insert_evidence(Evidence(
    device_id="dev2", destination_id="benign.example.com", evidence_type="dns_query",
    independence_family="dns", timestamp=now - 1 * 86400, source="zeek",
))
store.close()


def fake_lookup_factory(config, state_dir, refresh=True):
    def lookup(domain):
        if domain == "evil.example.com":
            return {"confidence": 0.95, "tags": ["malware"], "source": "test_intel"}
        return None
    return lookup


live_retro_hunter.CONFIG = {"state_path": str(_real_dir / "ids_state.json")}
with patch.object(live_retro_hunter, "real_threat_intel_lookup_factory", side_effect=fake_lookup_factory) as mock_factory:
    live_retro_hunter.main()
    check("main() calls real_threat_intel_lookup_factory with refresh=True (the real-usage "
          "default -- a warm ThreatIntel cache, matching v-current's own run_retro_hunt())",
          mock_factory.call_args.kwargs.get("refresh") is True or mock_factory.call_args.args[-1] is True)

verify_store = GraphStore(str(db_path))
new_evidence = verify_store._conn.execute(
    "SELECT device_id, destination_id, source, confidence FROM evidence WHERE source='retro_hunter'"
).fetchall()
check("main() wrote back exactly one new reputation Evidence item (only the malicious "
      "destination matched, the benign one didn't)",
      len(new_evidence) == 1)
check("the write-back is attributed to the correct device (dev1, which touched the "
      "confirmed-malicious destination)",
      len(new_evidence) == 1 and new_evidence[0][0] == "dev1")
check("the write-back carries the destination that was actually confirmed malicious",
      len(new_evidence) == 1 and new_evidence[0][1] == "evil.example.com")
check("the write-back's confidence matches the fake intel lookup's confidence",
      len(new_evidence) == 1 and abs(new_evidence[0][3] - 0.95) < 1e-6)
check("main() did NOT write anything back for dev2 (its destination never matched)",
      verify_store._conn.execute(
          "SELECT 1 FROM evidence WHERE device_id='dev2' AND source='retro_hunter'"
      ).fetchone() is None)

health = json.loads((_real_dir / "job_health.json").read_text())
check("job_health.json records a real findings_count (1)",
      health["live_retro_hunter"]["findings_count"] == 1)
check("job_health.json has no 'error' key on a successful run",
      "error" not in health["live_retro_hunter"])


# --- the graph-to-decision feedback loop: the new evidence is visible to the NEXT
# read of this device's graph window, not stranded in the evidence table alone ---
window_evidence = verify_store.get_device_destinations_since(now - 3 * 86400)
check("the newly-written reputation evidence is visible via the same "
      "get_device_destinations_since() query live_engine.py's windowed read uses -- "
      "the actual feedback loop this job exists to close, not just a table insert",
      ("dev1", "evil.example.com") in window_evidence)
verify_store.close()


# --- a real threat-intel lookup exception mid-hunt fails safe, doesn't crash the job ---
_error_dir = TMPDIR / "error"
_error_dir.mkdir()
error_db_path = _error_dir / "v13_graph.db"
error_store = GraphStore(str(error_db_path))
error_store.insert_evidence(Evidence(
    device_id="dev3", destination_id="whatever.example.com", evidence_type="dns_query",
    independence_family="dns", timestamp=now - 1 * 86400, source="zeek",
))
error_store.close()

live_retro_hunter.CONFIG = {"state_path": str(_error_dir / "ids_state.json")}
with patch.object(live_retro_hunter, "real_threat_intel_lookup_factory", side_effect=RuntimeError("feed unreachable")):
    live_retro_hunter.main()

error_health = json.loads((_error_dir / "job_health.json").read_text())
check("a threat-intel factory failure is recorded in job_health.json rather than "
      "crashing the scheduled job process",
      "error" in error_health["live_retro_hunter"])


# --- Phase 7: local-intel cross-reference + Telegram notification wiring ---
_li_dir = TMPDIR / "local_intel_phase7"
_li_dir.mkdir()
li_db_path = _li_dir / "v13_graph.db"
li_store = GraphStore(str(li_db_path))
li_store.insert_evidence(Evidence(
    device_id="li_confirmer", destination_id="already-bad.example.com", evidence_type="dns_query",
    independence_family="dns", timestamp=now - 1 * 86400, source="zeek",
))
li_store.insert_evidence(Evidence(
    device_id="li_victim", destination_id="already-bad.example.com", evidence_type="dns_query",
    independence_family="dns", timestamp=now - 2 * 86400, source="zeek",
))
li_store.close()

_li_intel_dir = TMPDIR / "cl_afpe_local_intel_phase7"
LocalConfirmedIntel(str(_li_intel_dir)).record(
    "domain", "already-bad.example.com", "li_confirmer", reason="STAGE_1_HARD_STOP")

live_retro_hunter.CONFIG = {"state_path": str(_li_dir / "ids_state.json"),
                              "telegram_token": "fake-token", "telegram_chat_id": "fake-chat"}
with patch.object(live_retro_hunter, "_CL_AFPE_LOCAL_INTEL_DIR", str(_li_intel_dir)), \
     patch.object(live_retro_hunter, "real_threat_intel_lookup_factory", side_effect=fake_lookup_factory), \
     patch.object(live_retro_hunter, "send_telegram") as mock_send_telegram:
    live_retro_hunter.main()

check("main() finds the cross-device local-intel match (li_victim touched a domain "
      "already confirmed by li_confirmer) via the SAME v13-only LocalConfirmedIntel "
      "store CL-AFPE's own shadow mode writes into",
      json.loads((_li_dir / "job_health.json").read_text())["live_retro_hunter"]["local_intel_matches_count"] == 1)
check("main() sends exactly one Telegram notification for the local-intel match "
      "(no external-TI matches this run -- fake_lookup_factory only recognizes "
      "'evil.example.com')",
      mock_send_telegram.call_count == 1)
sent_msg = mock_send_telegram.call_args.args[1] if mock_send_telegram.call_count else ""
check("the Telegram message names the victim device and the matched domain",
      "li_victim" in sent_msg and "already-bad.example.com" in sent_msg)
check("the Telegram message correctly attributes the confirmation to li_confirmer",
      "li_confirmer" in sent_msg)


# --- Phase 7: zero matches of either kind sends NO Telegram notification ---
_quiet_dir = TMPDIR / "quiet_phase7"
_quiet_dir.mkdir()
quiet_db_path = _quiet_dir / "v13_graph.db"
quiet_store = GraphStore(str(quiet_db_path))
quiet_store.insert_evidence(Evidence(
    device_id="quiet_dev", destination_id="perfectly-fine.example.com", evidence_type="dns_query",
    independence_family="dns", timestamp=now - 1 * 86400, source="zeek",
))
quiet_store.close()

live_retro_hunter.CONFIG = {"state_path": str(_quiet_dir / "ids_state.json"),
                              "telegram_token": "fake-token", "telegram_chat_id": "fake-chat"}
with patch.object(live_retro_hunter, "_CL_AFPE_LOCAL_INTEL_DIR", str(TMPDIR / "cl_afpe_local_intel_empty")), \
     patch.object(live_retro_hunter, "real_threat_intel_lookup_factory", side_effect=fake_lookup_factory), \
     patch.object(live_retro_hunter, "send_telegram") as mock_send_telegram_quiet:
    live_retro_hunter.main()

check("main() sends NO Telegram notification when neither external-TI nor "
      "local-intel finds anything -- send_telegram itself is never called on a "
      "genuinely quiet run",
      mock_send_telegram_quiet.call_count == 0)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All live_retro_hunter.py checks PASSED.")
