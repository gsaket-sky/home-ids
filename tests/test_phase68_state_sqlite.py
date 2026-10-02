"""
Phase 68 (2026-10-02, flash wear): StateManager persists to SQLite rows (core/state_store.py) instead of rewriting the
whole ids_state.json. A flush writes only the rows whose content changed; an existing JSON file is migrated once; the
engine and its API subprocess still see each other's IPS/ledger changes. Run directly: python tests/test_phase68_state_sqlite.py
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core import state_store  # noqa: E402
from core.state_guard import StateManager  # noqa: E402


def fresh_path():
    return str(Path(tempfile.mkdtemp()) / "ids_state.json")


# -- A: fresh store, change detection ------------------------------------------------------------------------------
path = fresh_path()
sm = StateManager(state_path=path)
sm.load_from_disk()
for i in range(5):
    sm.get_or_create(f"dev{i}", f"192.168.1.{10 + i}", f"host{i}")
sm.record_action("a1", "published_alert", "x.example", "dev0", extra={"alert_payload": {"big": "x" * 5000}})
check("first flush succeeds", sm.flush_to_disk())
check("database written, no JSON file", state_store.exists(path) and not Path(path).exists())
first = sm.rows_written_last_flush
check("first flush writes every row (5 devices + 1 ledger + kv)", first >= 7, str(first))

sm.flush_to_disk()
check("unchanged state -> nothing written", sm.rows_written_last_flush == 0 and sm.flushes_skipped_unchanged >= 1,
      str(sm.rows_written_last_flush))

with sm.lock_device("dev3") as st:
    st.hostname = "renamed"
sm.flush_to_disk()
check("one changed device -> exactly one row written", sm.rows_written_last_flush == 1, str(sm.rows_written_last_flush))

sm.record_action("a2", "published_alert", "y.example", "dev1")
sm.flush_to_disk()
check("one new ledger entry -> exactly one row written", sm.rows_written_last_flush == 1, str(sm.rows_written_last_flush))
sm.revoke_action("a1")
sm.flush_to_disk()
check("revoke -> exactly one row written", sm.rows_written_last_flush == 1, str(sm.rows_written_last_flush))

sm.remove_device("dev4")
sm.flush_to_disk()
snap = state_store.read_snapshot(path)
check("removed device is deleted from the database", "dev4" not in snap["devices"] and len(snap["devices"]) == 4)
check("snapshot has the old JSON shape", set(snap) >= {"devices", "ips_state", "action_ledger", "merge_redirects"})
check("revoke persisted", snap["action_ledger"]["a1"]["revoked"] is True)
check("ledger-free snapshot skips the ledger", state_store.read_snapshot(path, ledger=False)["action_ledger"] == {})

# -- B: reload round trip ------------------------------------------------------------------------------------------
sm2 = StateManager(state_path=path)
check("reload finds the 4 devices", sm2.load_from_disk() == 4)
with sm2.lock_device("dev3") as st:
    check("reloaded device keeps its change", st.hostname == "renamed")
sm2.flush_to_disk()      # from_dict() fills an empty known_ips with the device's own IP once -- rows converge
sm3 = StateManager(state_path=path)
sm3.load_from_disk()
sm3.flush_to_disk()
check("load + flush of an unchanged store writes nothing", sm3.rows_written_last_flush == 0,
      str(sm3.rows_written_last_flush))

# -- C: migration from ids_state.json ------------------------------------------------------------------------------
legacy = fresh_path()
src = StateManager(state_path=legacy)
src.get_or_create("old1", "10.0.0.1", "legacy-host")
src.record_action("L1", "published_alert", "z.example", "old1")
snapshot = {"ips_state": src.get_ips_state(),
            "devices": {"old1": src._states["old1"].to_dict()},
            "merge_redirects": {"gone": "old1"},
            "action_ledger": {"L1": src.get_action("L1")}}
snapshot["ips_state"]["blocked_domains"] = {"bad.example": {"hostname": "legacy-host", "timestamp": 1.0}}
Path(legacy).write_text(json.dumps(snapshot), encoding="utf-8")
mig = StateManager(state_path=legacy)
check("legacy JSON loads", mig.load_from_disk() == 1)
check("the first flush migrates", mig.flush_to_disk() and state_store.exists(legacy))
check("JSON renamed to .pre-sqlite", not Path(legacy).exists() and Path(legacy + ".pre-sqlite").exists())
after = StateManager(state_path=legacy)
after.load_from_disk()
check("migrated: device, ledger, redirects and blocks survive",
      after.has_device("old1") and after.get_action("L1") is not None
      and after.resolve_merge_redirect("gone") == "old1"
      and "bad.example" in after.get_ips_state()["blocked_domains"])

# -- D: engine + API subprocess ------------------------------------------------------------------------------------
path = fresh_path()
engine = StateManager(state_path=path)
engine.load_from_disk()
engine.get_or_create("d1", "192.168.1.50", "tv")
engine.record_action("pub1", "published_alert", "c2.example", "d1")
engine.flush_to_disk()
warm = StateManager(state_path=path)        # one reload normalises known_ips (see section B)
warm.load_from_disk()
warm.flush_to_disk()
engine.load_from_disk()

api = StateManager(state_path=path)          # the IPC subprocess: fresh load, change, flush
api.load_from_disk()
api.update_ips_state_atomic({"tarpit_targets": {"192.168.1.50": {"since": 1}}})
api.revoke_action("pub1")
api.flush_to_disk()
check("API process writes only what it changed (ips_state + 1 ledger row)", api.rows_written_last_flush == 2,
      str(api.rows_written_last_flush))

check("engine reconciles", engine.reconcile_ips_from_disk())
check("engine sees the tarpit and the revoke",
      "192.168.1.50" in engine.get_ips_state()["tarpit_targets"] and engine.get_action("pub1")["revoked"] is True)
engine.flush_to_disk()
final = state_store.read_snapshot(path)
check("engine's next flush keeps the API's changes",
      "192.168.1.50" in final["ips_state"]["tarpit_targets"] and final["action_ledger"]["pub1"]["revoked"] is True)

# -- E: cache helper -----------------------------------------------------------------------------------------------
check("last_modified sees the database", state_store.last_modified(path) is not None)
from middleware.state_client import get_cached_state_manager  # noqa: E402
c1 = get_cached_state_manager(path)
c2 = get_cached_state_manager(path)
check("cached reader reuses its instance while nothing changed", c1 is c2 and c1.has_device("d1"))

# -- F: read-only view without the ledger -------------------------------------------------------------------------
ro = StateManager(state_path=path)
check("read-only load gets the devices", ro.load_from_disk(ledger=False) == 1 and ro.has_device("d1"))
check("read-only load skips the ledger", ro.get_action("pub1") is None)
check("read-only instance refuses to flush (would drop ledger rows)", ro.flush_to_disk() is False)
check("ledger still intact on disk", state_store.read_snapshot(path)["action_ledger"]["pub1"]["revoked"] is True)

print()
if FAILURES:
    print(f"{len(FAILURES)} FAILED: {FAILURES}")
    sys.exit(1)
print("All phase-68 SQLite state checks PASSED.")
