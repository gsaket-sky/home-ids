"""
test_identity_reconcile_dhcp_ja4_signal.py - device-identity fragmentation fix,
continuation session: covers the 4th union signal added to
merge_fragmented_devices.py's find_fragmented_groups() (DHCP-fingerprint +
JA4-overlap + hostname scoring via device_matching.py's match_confidence(),
the SAME scoring cold-start reidentify already trusts live, applied
retroactively between two ALREADY-EXISTING devices).

Real motivation: live production data this session found a fragmented pair
(MAC-randomization -- last 5 bytes identical, only the locally-administered
bit differing) with NO shared known_ip, NO shared exact MAC, and NO shared
hostname -- the 3 original signals this script checked. A real DHCP+JA4
fingerprint match would have caught it; this test proves that path works,
and that a weak signal alone (DHCP-only, no corroboration) is correctly
NOT merged, matching AUTO_MERGE_CONFIDENCE's own conservative bar.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_identity_reconcile_dhcp_ja4_signal.py`
"""
import sys
import tempfile
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FAILURES = []


def check(label: str, condition: bool) -> None:
    status = "[PASS]" if condition else "[FAIL]"
    print(f"{status} {label}")
    if not condition:
        FAILURES.append(label)


from core.state_guard import StateManager  # noqa: E402
from merge_fragmented_devices import find_fragmented_groups, pick_canonical  # noqa: E402


def main() -> None:
    with tempfile.TemporaryDirectory() as d:
        sm = StateManager(state_path=str(Path(d) / "ids_state.json"), max_devices=100)

        # Strong signal: identical DHCP fingerprint AND real JA4 overlap, no shared
        # IP/MAC/hostname at all -- exactly the real live gap this session found.
        a = sm.get_or_create(device_id="devA1", client_ip="10.0.0.1", hostname="unknown")
        a.dhcp_fingerprint = {"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6, 15], "user_class": ""}
        a.ja4_seen.add("t13d1516h2_8daaf6152771_02713d6af862")
        b = sm.get_or_create(device_id="devB1", client_ip="10.0.0.2", hostname="unknown")
        b.dhcp_fingerprint = {"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6, 15], "user_class": ""}
        b.ja4_seen.add("t13d1516h2_8daaf6152771_02713d6af862")

        # Weak signal: DHCP-only match (a device-CLASS signal per device_matching.py's
        # own docstring, e.g. two same-model IoT units), no JA4/hostname corroboration
        # -- must NOT merge, matching AUTO_MERGE_CONFIDENCE's conservative-by-design bar.
        c = sm.get_or_create(device_id="devC1", client_ip="10.0.0.3", hostname="unknown")
        c.dhcp_fingerprint = {"vendor_class": "android-dhcp-14", "param_list": [1, 3, 6, 15, 26, 28, 51, 58, 59]}
        dd = sm.get_or_create(device_id="devD1", client_ip="10.0.0.4", hostname="unknown")
        dd.dhcp_fingerprint = {"vendor_class": "android-dhcp-14", "param_list": [1, 3, 6, 15, 26, 28, 51, 58, 59]}

        # Genuinely unrelated device, no signal in common with anything -- must never
        # be pulled into any group.
        sm.get_or_create(device_id="devE1", client_ip="10.0.0.5", hostname="printer_office")

        groups = find_fragmented_groups(sm)
        check("exactly 1 fragmented group found (the strong DHCP+JA4 pair only)", len(groups) == 1)
        if groups:
            group_ids = {m["device_id"] for m in groups[0]}
            check("the strong-signal pair (devA1/devB1) is the group found", group_ids == {"devA1", "devB1"})
        check(
            "the weak DHCP-only pair (devC1/devD1) is correctly NOT merged",
            not any({"devC1", "devD1"} <= {m["device_id"] for m in g} for g in groups),
        )
        check(
            "the unrelated device (devE1) never appears in any group",
            not any("devE1" in {m["device_id"] for m in g} for g in groups),
        )

        if groups:
            canonical = pick_canonical(groups[0])
            check("pick_canonical returns one of the two group members",
                  canonical["device_id"] in {"devA1", "devB1"})

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All identity-reconcile DHCP/JA4 signal checks PASSED.")


if __name__ == "__main__":
    main()
