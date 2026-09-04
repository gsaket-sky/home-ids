"""
Standalone runtime test for the "Telegram alert buttons don't reflect device's actual
containment state" bug, found via a live alert: a device (example_pc) that was ALREADY
tarpitted + router-isolated from an earlier incident got a NEW alert saying "Already
done: nothing yet" with "Approve Hardware Isolation" / "Release Device" buttons, as if
nothing had happened -- misleading, since there was nothing left to approve.

Two separate fixes, tested separately:

1. ips.py's IPSMitigator.get_containment_status() gained a dev_id fallback -- the
   primary lookups are keyed by raw client_ip (tarpit) / mac_addr (router isolation),
   which can miss a genuinely-contained device on an identifier mismatch (DHCP lease
   change, MAC not yet re-resolved this cycle). Both _tarpit_active_targets/
   _router_isolated_devices entries already store a "dev_id" field, so when the direct
   key misses, a dev_id scan is now tried before concluding "unblocked".

2. pipeline.py's inline-keyboard button set is now driven by action_summary (the SAME
   authoritative value the "Already done" status text already uses) instead of an
   independently recomputed risk/lateral_threat condition that never checked
   containment state at all. Tested here via a local mirror of the new gate logic
   (same style test_phase20_alert_quality.py already uses for action_summary itself --
   pipeline.py's _step() is too deeply embedded in one giant method to invoke directly
   in a lightweight test), with a REGRESSION check that the mirror's literal source
   matches what's actually in pipeline.py so the mirror can't silently drift from the
   real logic.

Not part of the pytest suite (no fixtures needed) -- run directly:
`python3 test_phase40_alert_button_containment_sync.py`.
"""
import sys
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

from mitigation.ips import IPSMitigator
from core.state_guard import StateManager

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ── Section A: get_containment_status()'s dev_id fallback ──────────────────────────
with tempfile.TemporaryDirectory() as tmpdir:
    state_path = str(_PathForSysPath(tmpdir) / "ids_state.json")
    sm = StateManager(state_path=state_path)
    config = {"interactive_blocking_enabled": True, "state_path": state_path}
    ips = IPSMitigator(config=config, state_manager=sm)

    DEV_ID = "abc123def456"
    OLD_IP, OLD_MAC = "192.168.1.99", "aa:bb:cc:dd:ee:ff"
    NEW_IP, NEW_MAC = "192.168.1.100", "11:22:33:44:55:66"  # this alert's own identifiers

    check("baseline: a device with no containment record at all reads as UNBLOCKED",
          "UNBLOCKED" in ips.get_containment_status(client_ip=NEW_IP, mac_addr=NEW_MAC, dev_id=DEV_ID))

    ips._tarpit_active_targets[OLD_IP] = {"mac": OLD_MAC, "hostname": "test-dev", "dev_id": DEV_ID}
    check("THE BUG (reproduced): a genuinely-tarpitted device reads as UNBLOCKED when "
          "queried under DIFFERENT identifiers and no dev_id fallback is available",
          "UNBLOCKED" in ips.get_containment_status(client_ip=NEW_IP, mac_addr=NEW_MAC))
    check("THE FIX: the SAME query, now passing dev_id, correctly finds the tarpit entry "
          "via the dev_id fallback despite the client_ip mismatch",
          "TARPITTED" in ips.get_containment_status(client_ip=NEW_IP, mac_addr=NEW_MAC, dev_id=DEV_ID))
    check("REGRESSION GUARD: the direct client_ip match still works on its own (no dev_id needed)",
          "TARPITTED" in ips.get_containment_status(client_ip=OLD_IP, mac_addr=NEW_MAC))
    del ips._tarpit_active_targets[OLD_IP]

    ips._router_isolated_devices[OLD_MAC] = {"ip": OLD_IP, "hostname": "test-dev", "dev_id": DEV_ID}
    check("THE FIX applies the same way to router isolation: dev_id fallback finds it "
          "despite a mac_addr mismatch",
          "ROUTER ISOLATED" in ips.get_containment_status(client_ip=NEW_IP, mac_addr=NEW_MAC, dev_id=DEV_ID))
    check("REGRESSION GUARD: without dev_id, the same mismatched query still misses "
          "(the fallback is additive, not a replacement for the direct lookup)",
          "UNBLOCKED" in ips.get_containment_status(client_ip=NEW_IP, mac_addr=NEW_MAC))
    del ips._router_isolated_devices[OLD_MAC]

    check("a dev_id that matches nothing still correctly falls through to UNBLOCKED "
          "(the fallback doesn't produce false positives)",
          "UNBLOCKED" in ips.get_containment_status(client_ip=NEW_IP, mac_addr=NEW_MAC, dev_id="no_such_device"))


# ── Section B: button-gate logic keyed off action_summary ──────────────────────────
def _buttons_for(action_summary: str, client_ip: str = "1.2.3.4"):
    """Mirror of pipeline.py's inline-keyboard button-gate logic. Kept as a literal
    copy (not imported) since pipeline.py's _step() is one giant method with no
    extractable unit under test — matches test_phase20_alert_quality.py's own
    established pattern for testing action_summary itself. The regression check right
    after this function asserts pipeline.py's actual source still contains the two
    conditions this mirror encodes, so the mirror can't silently drift from reality.

    BUGFIX (2026-09-01, button/description audit): no longer takes an
    interactive_blocking_enabled parameter -- pipeline.py's real gate never should
    have had one either. That flag controls whether a NEW containment action needs
    approval before happening, not whether an ALREADY-contained device can be
    released; wrapping Release in it meant a device autonomously tarpitted/isolated/
    blocked (interactive_blocking_enabled=False -- the config's own default when
    unset) got NO Release button at all, even though _build_status_lines' text for
    those states explicitly says "tap Release". See
    Documentation/CHANGELOG.md's entry for this fix.
    """
    keyboard = []
    if action_summary in ("tarpitted (Layer-2)", "router isolated", "auto-blocked"):
        keyboard.append([{"text": "🔓 Release Device", "callback_data": f"unblock:{client_ip}"}])
    elif action_summary == "awaiting approval":
        keyboard.append([
            {"text": "🔒 Approve Hardware Isolation", "callback_data": f"block:{client_ip}"}
        ])
    return keyboard


check("THE BUG's core scenario, now fixed: an already-tarpitted device gets ONLY a "
      "Release button, no 'Approve' (there's nothing left to approve)",
      _buttons_for("tarpitted (Layer-2)") == [[{"text": "🔓 Release Device", "callback_data": "unblock:1.2.3.4"}]])
check("same fix for router-isolated devices",
      _buttons_for("router isolated") == [[{"text": "🔓 Release Device", "callback_data": "unblock:1.2.3.4"}]])
check("same fix for an auto-blocked (domain-blocked) device",
      _buttons_for("auto-blocked") == [[{"text": "🔓 Release Device", "callback_data": "unblock:1.2.3.4"}]])
check("BUGFIX (2026-08-29, user catch): a genuinely pending device (nothing done yet) "
      "now gets ONLY Approve, not a Release button too -- action_summary==\"awaiting "
      "approval\" is itself derived from containment_status finding nothing currently "
      "contained (see the branch order above it), so Release was guaranteed to no-op "
      "there every time, violating the same 'only show a button that would actually do "
      "something' principle the three checks above this one already enforce",
      _buttons_for("awaiting approval") == [[{"text": "🔒 Approve Hardware Isolation", "callback_data": "block:1.2.3.4"}]])
check("REGRESSION GUARD: 'monitoring only' (nothing queued, nothing done) gets NO "
      "hardware buttons at all, matching the 'monitoring only' status text",
      _buttons_for("monitoring only") == [])
check("BUGFIX (2026-09-01): a device that's ACTUALLY contained (e.g. autonomously "
      "tarpitted while interactive_blocking_enabled=False -- the mitigator's "
      "'Autonomous Auto-Block' mode, see ips.py's own boot-log line) still gets a "
      "Release button -- this exact scenario used to produce NO button at all while "
      "the status text still said 'tap Release', a real dead-button bug. Release no "
      "longer takes interactive_blocking_enabled into account at all, matching that "
      "flag's actual meaning (gates NEW actions needing approval, not releasing an "
      "EXISTING one).",
      _buttons_for("tarpitted (Layer-2)") == [[{"text": "🔓 Release Device", "callback_data": "unblock:1.2.3.4"}]])

# Guard the mirror above against silently drifting from the real pipeline.py source.
_pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
check("REGRESSION GUARD: pipeline.py's real source still contains the already-contained "
      "-> Release-only branch this mirror tests (catches the mirror silently drifting "
      "from the real logic on a future edit)",
      'action_summary in ("tarpitted (Layer-2)", "router isolated", "auto-blocked")' in _pipeline_src)
check("REGRESSION GUARD: pipeline.py's real source still contains the awaiting-approval "
      "-> Approve-only branch",
      'elif action_summary == "awaiting approval":' in _pipeline_src)
check("REGRESSION GUARD: pipeline.py's awaiting-approval branch no longer also appends "
      "a Release Device button (catches a future edit silently reintroducing the "
      "guaranteed-no-op button)",
      _pipeline_src.count('{"text": "🔓 Release Device", "callback_data": f"unblock:{client_ip}"}') == 1,
      "expected exactly ONE Release-Device button construction in the whole file "
      "(the already-contained branch) -- found a different count")
check("REGRESSION GUARD (2026-09-01 fix): pipeline.py's button assembly no longer "
      "wraps Release in an interactive_blocking_enabled check -- catches a future "
      "edit silently reintroducing the dead-button bug",
      'if bool(self.config.get("interactive_blocking_enabled", False)):\n                                    if action_summary in ("tarpitted (Layer-2)"'
      not in _pipeline_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 40 alert-button/containment-sync checks PASSED.")
