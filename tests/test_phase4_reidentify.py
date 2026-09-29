"""
Standalone runtime test for Phase 4 device re-identification. Not part of the pytest
suite (no fixtures needed) — run directly: `python3 test_phase4_reidentify.py`.
Exercises the real StateManager.get_or_create() code path, no mocks.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
from core.state_guard import StateManager
from core.device_matching import dhcp_fingerprint_match, ja4_overlap, match_confidence

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ── Test 1: iPhone MAC rotation should auto-merge (DHCP fingerprint + JA4 overlap) ──
sm = StateManager(state_path="/tmp/_phase4_test_state.json")

iphone_fp = {"vendor_class": "", "param_list": [1, 121, 3, 6, 15, 108, 114, 119, 162, 252], "user_class": ""}
iphone_ja4 = {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}

old_state = sm.get_or_create("old_id_1", "192.168.1.50", "iPhone", dhcp_fingerprint=iphone_fp, ja4_set=iphone_ja4)
old_state.dhcp_fingerprint = iphone_fp
for h in iphone_ja4:
    old_state.ja4_seen.add(h)
old_state.confirmed_threat_count = 3          # history that MUST survive the merge
old_state.last_seen = time.time() - 400        # went quiet 400s ago (private MAC rotated)

# New DHCP transaction from a *new* randomized MAC -> new IP -> new device_id, same phone.
# Same DHCP fingerprint (device class unchanged) plus strong (not marginal) JA4 overlap —
# 2 of the phone's 3 observed TLS stacks repeat, which is realistic: iOS apps reuse a small
# stable set of JA4s, they don't reshuffle on every reconnect.
new_fp = {"vendor_class": "", "param_list": [1, 121, 3, 6, 15, 108, 114, 119, 162, 252], "user_class": ""}
new_ja4 = {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccccccccccc"}

new_state = sm.get_or_create("new_id_1", "192.168.1.77", "iPhone",
                              dhcp_fingerprint=new_fp, ja4_set=new_ja4)

# migrate_device_id() (existing, pre-Phase-4 code) renames the surviving state onto the
# NEW device_id going forward — matching the codebase's established migration semantics —
# while carrying its history forward. So the right assertion is "adopted the new id AND
# kept the history," not "kept the old id."
check("iPhone rotation reuses new_id_1 (not a second cold-start profile)",
      new_state.device_id == "new_id_1")
check("merged state keeps prior threat history", new_state.confirmed_threat_count == 3,
      f"confirmed_threat_count={new_state.confirmed_threat_count}")
check("merged state's client_ip updated to new IP", new_state.client_ip == "192.168.1.77")
check("old identity no longer present as its own entry", not sm.has_device("old_id_1"))


# ── Test 2: two distinct ESP32s (identical DHCP fingerprint, NO JA4/hostname corroboration)
#            must NOT merge — this is the real false-merge trap confirmed on the user's own
#            network (two different physical ESP32s share an identical param_list). ──
sm2 = StateManager(state_path="/tmp/_phase4_test_state2.json")
esp_fp = {"vendor_class": "", "param_list": [1, 3, 28, 6, 15, 44, 46, 47, 31, 33, 121, 43], "user_class": ""}

esp_a = sm2.get_or_create("esp_a", "192.168.1.101", "ESP_D23502", dhcp_fingerprint=esp_fp, ja4_set=None)
esp_a.dhcp_fingerprint = esp_fp
esp_a.last_seen = time.time() - 60  # recently quiet — inside the candidate window

esp_b = sm2.get_or_create("esp_b", "192.168.1.102", "ESP_C74DB3", dhcp_fingerprint=esp_fp, ja4_set=None)

check("two distinct same-firmware ESP32s do NOT get merged", esp_b.device_id == "esp_b",
      f"got device_id={esp_b.device_id!r} (would mean a wrongful merge)")
check("both ESP32 identities still tracked separately", sm2.has_device("esp_a") and sm2.has_device("esp_b"))


# ── Test 3: candidate outside the time window (e.g. 2 hours idle) does not match ──
sm3 = StateManager(state_path="/tmp/_phase4_test_state3.json")
old3 = sm3.get_or_create("old_id_3", "192.168.1.60", "test-device-1",
                          dhcp_fingerprint={"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6, 15], "user_class": ""})
old3.dhcp_fingerprint = {"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6, 15], "user_class": ""}
old3.last_seen = time.time() - 7200  # 2 hours ago — outside default 1800s candidate window

new3 = sm3.get_or_create("new_id_3", "192.168.1.61", "test-device-1",
                          dhcp_fingerprint={"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6, 15], "user_class": ""})
check("stale (2h-idle) candidate outside window is not merged", new3.device_id == "new_id_3")


# ── Test 4: pure-function scoring sanity checks (no StateManager involved) ──
check("identical DHCP fingerprints score 1.0",
      dhcp_fingerprint_match({"vendor_class": "MSFT 5.0", "param_list": [1, 3], "user_class": ""},
                              {"vendor_class": "MSFT 5.0", "param_list": [1, 3], "user_class": ""}) == 1.0)
check("different param_list scores 0.0",
      dhcp_fingerprint_match({"vendor_class": "MSFT 5.0", "param_list": [1, 3], "user_class": ""},
                              {"vendor_class": "MSFT 5.0", "param_list": [1, 3, 6], "user_class": ""}) == 0.0)
check("empty JA4 sets never claim overlap", ja4_overlap(set(), {"x"}) == 0.0)
check("DHCP match alone stays below auto-merge bar",
      match_confidence(dhcp_score=1.0, ja4_sim=0.0, hostname_ok=False) < 0.75)
check("DHCP match + strong JA4 overlap clears auto-merge bar",
      match_confidence(dhcp_score=1.0, ja4_sim=0.9, hostname_ok=False) >= 0.75)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 4 re-identification checks PASSED.")
