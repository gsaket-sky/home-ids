"""
Standalone runtime test for Phase 3 (closed-loop autonomous actions with async revoke).
Not part of the pytest suite — run directly: `python3 test_phase3_revoke.py`. Exercises
the real AutonomousFPEngine and StateManager code paths, no mocks (matching
test_phase4_reidentify.py's style).

Covers:
  1. Non-negotiable fix: the trust-cache fast path re-runs Stage-1 hard-stop checks on
     every cache hit instead of unconditionally suppressing.
  2. _immunize_domain() returns whether the immunization was NEW (vs a TTL refresh).
  3. revoke_immunization() actually removes a domain from the trust cache and is
     idempotent (returns False on a domain that was never/no-longer cached).
  4. StateManager's action ledger: record_action / revoke_action / get_action /
     prune_expired_actions.
  5. reconcile_ips_from_disk() merges a separately-written action_ledger (the IPC
     subprocess split-brain fix) instead of losing it on the next flush.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import json
import tempfile

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# Tests 1-3 (trust-cache hard-stop override, new-vs-refresh immunization, revoke) are covered against the live
# CL-AFPE in test_argus_cl_afpe.py.

# ── Test 4: StateManager action ledger ──────────────────────────────────────────────
from core.state_guard import StateManager

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir2:
    sm = StateManager(state_path=f"{tmpdir2}/ids_state.json")

    sm.record_action("act1", "immunize_domain", "sub.example.com", "dev1", "test-host", ttl_seconds=3600.0)
    entry = sm.get_action("act1")
    check("record_action() stores a retrievable ledger entry with expected fields",
          entry is not None and entry["type"] == "immunize_domain" and entry["target"] == "sub.example.com"
          and entry["revoked"] is False, f"got {entry}")

    revoked_entry = sm.revoke_action("act1")
    check("revoke_action() returns the entry and marks it revoked",
          revoked_entry is not None and revoked_entry["revoked"] is True)

    double_revoke = sm.revoke_action("act1")
    check("revoke_action() returns None on a second revoke attempt (no duplicate Telegram-tap side effects)",
          double_revoke is None)

    unknown_revoke = sm.revoke_action("does-not-exist")
    check("revoke_action() on an unknown action_id returns None (maps to a 404, not a crash)",
          unknown_revoke is None)

    # prune_expired_actions: entries past TTL and never revoked get dropped;
    # revoked entries and not-yet-expired entries are kept.
    sm.record_action("act_expired", "immunize_domain", "old.example.com", "dev2", "old-host", ttl_seconds=1.0)
    sm.record_action("act_fresh", "immunize_domain", "new.example.com", "dev3", "new-host", ttl_seconds=99999.0)
    pruned_count = sm.prune_expired_actions(now=time.time() + 10.0)  # act_expired's 1s TTL has passed
    check("prune_expired_actions() removes exactly the one truly-expired, never-revoked entry",
          pruned_count == 1, f"got pruned_count={pruned_count}")
    check("prune_expired_actions() leaves the not-yet-expired entry alone",
          sm.get_action("act_fresh") is not None)
    check("prune_expired_actions() leaves the already-revoked entry alone (revoked entries aren't pruned)",
          sm.get_action("act1") is not None)

    # ── Test 5: reconcile_ips_from_disk() merges a separately-written action_ledger ──
    # Simulates the real split-brain scenario: the separate FastAPI/Uvicorn IPC
    # subprocess revokes an action and flushes its OWN StateManager to disk, then the
    # main pipeline process's periodic reconcile must pick that change up instead of
    # clobbering it on its next flush_to_disk().
    sm.flush_to_disk()
    state_path = sm.state_path

    # Simulate the IPC subprocess: load fresh, revoke act_fresh, flush.
    sm_ipc = StateManager(state_path=str(state_path))
    sm_ipc.load_from_disk()
    ipc_revoked = sm_ipc.revoke_action("act_fresh")
    check("separate IPC-process StateManager instance can see act_fresh after load_from_disk()",
          ipc_revoked is not None)
    sm_ipc.flush_to_disk()

    # Main process reconciles and should now see act_fresh as revoked too.
    reconciled = sm.reconcile_ips_from_disk()
    check("reconcile_ips_from_disk() reports a change was merged", reconciled is True)
    main_view = sm.get_action("act_fresh")
    check("PHASE 3 split-brain fix: main-process StateManager's action ledger reflects the "
          "IPC subprocess's revoke after reconcile (without this fix, the next periodic "
          "flush_to_disk() from the main process would have silently overwritten the "
          "revoke and made the Phase 3 [Revoke] button unreliable)",
          main_view is not None and main_view.get("revoked") is True, f"got {main_view}")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 3 closed-loop autonomous-action checks PASSED.")
