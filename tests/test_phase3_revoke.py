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


from intelligence.fp_engine import AutonomousFPEngine

with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir:
    fp = AutonomousFPEngine(config={}, state_dir=tmpdir)

    # ── Test 1: trust-cache fast path re-runs Stage 1 hard-stop on every hit ───────
    base_domain = "immunized-example.com"
    is_new = fp._immunize_domain(base_domain, "test-host")
    check("_immunize_domain() reports True for a genuinely NEW immunization", is_new is True)

    is_new_again = fp._immunize_domain(base_domain, "test-host")
    check("_immunize_domain() reports False on a repeat call (TTL refresh, not new)",
          is_new_again is False)

    alert_payload = {
        "device": {"id": "dev1", "hostname": "test-host"},
        "network_context": {"queried_domain": f"sub.{base_domain}", "destination_ip": "1.2.3.4"},
    }
    # No hard-stop signals present -> trust cache hit should suppress as before.
    benign_features = {"ti_risk": 0.0, "zeek_lateral_moves": 0, "zeek_ja3_malicious": 0,
                        "zeek_ja4_malicious": 0, "zeek_honeypot_hits": 0, "abuseipdb_risk": 0.0,
                        "outbound_bytes_z": 0.0}
    verdict_benign = fp.evaluate(alert_payload, benign_features, risk_score=6.5, ti_engine=None)
    check("trust-cache hit with NO hard-stop signals still suppresses as FALSE_POSITIVE "
          "(unchanged happy-path behavior)",
          verdict_benign["verdict"] == "FALSE_POSITIVE" and verdict_benign["suppress"] is True,
          f"got {verdict_benign}")
    check("benign trust-cache-hit verdict stage is TRUST_CACHE (not overridden)",
          verdict_benign["stage"] == "TRUST_CACHE", f"got stage={verdict_benign['stage']}")

    # NOW: same immunized domain, but this alert ALSO carries a hard-stop signal
    # (ti_risk > 0 = confirmed ThreatIntel IOC match). Pre-fix, the trust-cache fast path
    # would have suppressed this unconditionally since the domain is immunized. Post-fix,
    # it must override the cache and report CONFIRMED_THREAT.
    malicious_features = dict(benign_features)
    malicious_features["ti_risk"] = 5.0
    verdict_override = fp.evaluate(alert_payload, malicious_features, risk_score=8.0, ti_engine=None)
    check("PHASE 3 non-negotiable fix: an immunized domain carrying a hard-stop signal "
          "(ThreatIntel IOC match) is CONFIRMED_THREAT, NOT silently suppressed by the "
          "trust cache — this was the audit's core closed-loop safety gap",
          verdict_override["verdict"] == "CONFIRMED_THREAT" and verdict_override["suppress"] is False,
          f"got {verdict_override}")
    check("overridden verdict's stage clearly identifies the trust-cache override path",
          verdict_override["stage"] == "TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP",
          f"got stage={verdict_override['stage']}")
    check("overridden verdict surfaces the actual hard-stop reason (ThreatIntel IOC) to the operator",
          any("ThreatIntel" in r for r in verdict_override["reasons"]),
          f"got reasons={verdict_override['reasons']}")

    # ── Test 2: revoke_immunization() ───────────────────────────────────────────────
    revoked = fp.revoke_immunization(base_domain)
    check("revoke_immunization() returns True for a domain that WAS in the trust cache",
          revoked is True)
    check("revoke_immunization() actually removes the domain from the in-memory trust cache",
          base_domain not in fp._trust_cache)

    revoked_again = fp.revoke_immunization(base_domain)
    check("revoke_immunization() is idempotent — returns False for an already-revoked/unknown domain",
          revoked_again is False)

    # Post-revoke: the SAME benign alert must no longer be trust-cache-suppressed.
    verdict_post_revoke = fp.evaluate(alert_payload, benign_features, risk_score=6.5, ti_engine=None)
    check("after revoke, the same domain no longer hits the trust-cache fast path "
          "(verdict stage is no longer TRUST_CACHE)",
          verdict_post_revoke["stage"] != "TRUST_CACHE", f"got stage={verdict_post_revoke['stage']}")

    # ── Test 3: _immunize_domain() rejects invalid/empty domains ───────────────────
    check("_immunize_domain('') is rejected (returns False, not treated as new)",
          fp._immunize_domain("", "test-host") is False)
    check("_immunize_domain('unknown') is rejected as an invalid placeholder value",
          fp._immunize_domain("unknown", "test-host") is False)


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
