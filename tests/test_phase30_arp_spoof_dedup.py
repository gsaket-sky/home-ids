"""
Standalone runtime test for Phase 30 (ARP/NDP spoof-detection false-positive fix). Not
part of the pytest suite -- run directly: `python3 test_phase30_arp_spoof_dedup.py`.

Production found the Layer-2 spoof detector (zeek_features.py's _bind_mac()) repeatedly
firing CRITICAL on real LAN IPs (192.168.1.2, .3) oscillating between the SAME two MACs
every 0-18 seconds -- and this evidence type feeds a Stage-0 HARD-STOP in decision_engine.py
(has_arp_spoof -> CRITICAL, single evidence item, bypasses CL-AFPE entirely), so every
oscillation was queuing real router-isolation/tarpit actions for Telegram approval. A real
ARP-spoofing attacker hijacks and HOLDS an IP -- repeatedly handing control back to the
legitimate MAC and re-attacking every ~15s is self-defeating, so this pattern is far more
consistent with mesh-WiFi relay/rewrite behavior than an actual attack.

The fix: track every MAC ever seen per IP (_mac_history), and only treat a flip as a
genuine new spoof when the new MAC has NEVER been seen for that IP before. A MAC
re-appearing that's already on record for this IP is a known oscillation, not suppressed
into invisibility (still logged at DEBUG) but no longer reaching the hard-stop pipeline.
Detection of an actually-new hijacker MAC is unchanged.

FOLLOW-UP (same session, live audit): a single genuinely-new MAC is ALSO the normal
signature of MAC-randomization ("private Wi-Fi address," on by default since iOS 14/
Android 10) reconnecting or roaming between APs -- not just a hijack. A lone first-time
flip now produces weak, corroboration-required evidence (pending_spoof_evidence,
consumed by pipeline.py into NetworkIntrusionHypothesis, not decision_engine.py's
zero-corroboration hard-stop) instead of an instant CRITICAL. Only a SECOND genuinely-new
MAC on the same IP within the same 600s window still reaches the instant hard-stop
(layer2_spoofs) -- a real, actively-worked takeover plausibly re-establishes a session
in that window; a one-off privacy reconnect does not.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from extractors.zeek_features import ZeekFeatureExtractor

zfx = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])

IP = "192.168.1.3"
MAC_A = "aa:aa:aa:aa:aa:aa"
MAC_B = "bb:bb:bb:bb:bb:bb"
MAC_C = "cc:cc:cc:cc:cc:cc"

# Initial binding -- no prior MAC on record, never a spoof.
zfx._bind_mac(IP, MAC_A, ts=1000.0)
check("initial binding for a fresh IP never fires a spoof",
      not hasattr(zfx, "layer2_spoofs") or IP not in zfx.layer2_spoofs)

# First flip to a genuinely never-seen MAC, well within the 600s window -- weak,
# corroboration-required evidence now, NOT an instant hard-stop (MAC-randomization
# reconnect produces this exact same shape).
zfx._bind_mac(IP, MAC_B, ts=1010.0)
check("THE FIX: a lone flip to a genuinely NEW mac produces weak pending evidence, "
      "not an instant hard-stop",
      (not hasattr(zfx, "layer2_spoofs") or IP not in zfx.layer2_spoofs)
      and IP in zfx.pending_spoof_evidence)
if hasattr(zfx, "pending_spoof_evidence") and IP in zfx.pending_spoof_evidence:
    del zfx.pending_spoof_evidence[IP]  # simulate pipeline.py consuming it (pop on read)

# Flip BACK to MAC_A (already on record for this IP) -- known oscillation, must NOT fire.
zfx._bind_mac(IP, MAC_A, ts=1020.0)
check("THE CORE FIX: flipping back to a PREVIOUSLY-seen mac for this IP does not re-fire",
      not hasattr(zfx, "layer2_spoofs") or IP not in zfx.layer2_spoofs)

# Flip to MAC_B again (also already on record) -- still a known oscillation.
zfx._bind_mac(IP, MAC_B, ts=1030.0)
check("a second oscillation back to the other already-known mac also does not fire",
      not hasattr(zfx, "layer2_spoofs") or IP not in zfx.layer2_spoofs)

# A genuinely new third MAC arrives -- this is this IP's SECOND genuine (never-before-
# seen) flip within the 600s window (the first was MAC_B at ts=1010.0 above) -- THE
# NEW HARD-STOP CONDITION: a real, actively-worked takeover plausibly re-establishes a
# session quickly; still must fire, same as before, just via the 2-genuine-flips path
# now instead of any single new mac.
zfx._bind_mac(IP, MAC_C, ts=1040.0)
check("THE FIX: a SECOND genuine (never-before-seen) flip within the 600s window still "
      "fires the hard-stop",
      hasattr(zfx, "layer2_spoofs") and IP in zfx.layer2_spoofs)

# Different IP entirely -- MAC_A being known for 192.168.1.3 must not suppress a
# genuine first-time flip on an unrelated IP using that same MAC value. Only ONE
# genuine flip happens on IP2 below, so it's the weak/pending case, not a hard-stop --
# proves the per-IP known-mac history AND the per-IP genuine-flip-count tracking are
# both correctly scoped (not accidentally shared across IP3's own flip count above).
IP2 = "192.168.1.4"
zfx._bind_mac(IP2, MAC_A, ts=1050.0)
zfx._bind_mac(IP2, MAC_B, ts=1055.0)
check("known-mac/genuine-flip history is scoped PER-IP, not global -- a fresh IP's "
      "FIRST flip is still only the weak/pending case, not an instant hard-stop",
      (not hasattr(zfx, "layer2_spoofs") or IP2 not in zfx.layer2_spoofs)
      and IP2 in zfx.pending_spoof_evidence)

# A SECOND genuine flip on IP2, still within the window -- now it hard-stops too,
# proving the 2-flip escalation logic is genuinely per-IP and not a one-time global
# latch left over from IP's own earlier escalation above.
zfx._bind_mac(IP2, "dd:dd:dd:dd:dd:dd", ts=1060.0)
check("THE FIX: the 2-genuine-flips-within-window escalation works independently on a "
      "second IP, not just once globally",
      hasattr(zfx, "layer2_spoofs") and IP2 in zfx.layer2_spoofs)

# A flip outside the 600s window was already correctly ignored before this fix -- confirm
# that pre-existing behavior survives unchanged (not something this fix touched).
IP3 = "192.168.1.5"
zfx._bind_mac(IP3, MAC_A, ts=2000.0)
zfx._bind_mac(IP3, MAC_C, ts=2700.0)  # 700s later, outside the 600s window
check("a flip outside the 600s window still does not fire (unchanged pre-existing behavior)",
      not hasattr(zfx, "layer2_spoofs") or IP3 not in zfx.layer2_spoofs)


if FAILURES:
    print(f"\n{len(FAILURES)} Phase 30 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 30 ARP-spoof-dedup checks PASSED.")
    sys.exit(0)
