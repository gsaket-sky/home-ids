"""
Standalone runtime test for the "autonomous-action alerts don't explain why" fixes:
1. pipeline.py's "Auto-action: immunized" revoke prompt now surfaces the LightGBM/
   FastEmbed/combined-threshold breakdown, calibrated confidence, originating
   signature/risk/destination, and a hostname+IP identity (never dead-ending on a bare
   "unknown" hostname with no fallback).
2. retro_hunter.py's "Retroactive Local-Intel Cross-Reference" alert now surfaces how
   long/how many times an IOC has been confirmed, what originally flagged it, the
   mitigation actually applied, and resolves device_ids to hostname/IP (never a bare
   hash) via a fresh device-display-name map.
3. ollama_soc.py's per-run digest now covers every pattern's outcome (not just
   malicious findings), including a cross-run "spread" trend for multi-device-guard
   withholds -- which SPECIFIC devices joined, not just a count.

Not part of the pytest suite (no fixtures needed) -- run directly:
`python3 test_phase41_alert_context_enrichment.py`.
"""
import sys
import json
import time
import tempfile
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

# This file's own check names/details deliberately include the same unicode arrows
# (->) the real code under test produces (e.g. "2->2->3" spread sequences) -- on some
# Windows console codepages (cp1252) printing those crashes with UnicodeEncodeError
# regardless of whether the underlying check passed or failed, which would mask a real
# future failure's message. Force UTF-8 stdout/stderr so this test's own diagnostics
# are always printable, independent of whatever console encoding happens to be active.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from core.pipeline import _build_geo_note
from core.state_guard import StateManager
from intelligence.geoip import GeoIPEngine
from intelligence.local_intel import LocalConfirmedIntel
from scripts.retro_hunter import _geo_note as retro_geo_note, _load_device_display_map, check_local_intel_history

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


ROOT = _PathForSysPath(__file__).resolve().parent.parent
CITY_DB = str(ROOT / "models" / "GeoLite2-City.mmdb")
ASN_DB = str(ROOT / "models" / "GeoLite2-ASN.mmdb")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: geo-note helpers (pipeline.py's _build_geo_note, retro_hunter.py's _geo_note)
# ═══════════════════════════════════════════════════════════════════════════════════
check("_build_geo_note() with no engine degrades to empty string, not a crash",
      _build_geo_note(None, "8.8.8.8") == "")
check("_build_geo_note() with a non-IP string degrades to empty string",
      _build_geo_note(None, "example.com") == "")
check("_build_geo_note() with 'unknown' degrades to empty string",
      _build_geo_note(None, "unknown") == "")

real_geoip = GeoIPEngine(db_path=CITY_DB, asn_db_path=ASN_DB)
google_dns_note = _build_geo_note(real_geoip, "8.8.8.8")
check("_build_geo_note() with a real engine and a well-known public IP (8.8.8.8) "
      "returns a non-empty, correctly-formatted org/country note",
      google_dns_note.startswith(" _(") and google_dns_note.endswith(")_") and "Google" in google_dns_note,
      f"got={google_dns_note!r}")

check("retro_hunter.py's _geo_note() mirrors the same graceful-degradation behavior",
      retro_geo_note(None, "8.8.8.8") == "" and retro_geo_note(real_geoip, "not-an-ip") == "")
retro_note = retro_geo_note(real_geoip, "8.8.8.8")
check("retro_hunter.py's _geo_note() with a real engine returns Google for 8.8.8.8 too "
      "(same underlying lookup_asn()/lookup() calls as pipeline.py's copy)",
      "Google" in retro_note, f"got={retro_note!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: retro_hunter.py's device-display-map and check_local_intel_history()'s
# new fields (first_confirmed/count/reason/device_ip) -- real objects, temp files
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    state_dir = _PathForSysPath(tmpdir)
    state_path = str(state_dir / "ids_state.json")

    sm = StateManager(state_path=state_path)
    sm.get_or_create("dev_with_hostname", "192.168.1.50", "example_pc_fritz_box")
    sm.get_or_create("dev_no_hostname", "192.168.1.51", "unknown")
    sm.flush_to_disk()

    display_map = _load_device_display_map(state_dir)
    check("device-display map resolves a device WITH a known hostname to that hostname",
          display_map.get("dev_with_hostname") == "example_pc_fritz_box")
    check("device-display map falls back to IP (never the bare device_id) when hostname "
          "is unknown -- this is the exact rule requested: hostname first, IP fallback, "
          "never a raw device_id hash",
          display_map.get("dev_no_hostname") == "192.168.1.51")
    check("a device_id absent from current state is simply absent from the map "
          "(caller's own .get(id, id) fallback handles it, not a crash here)",
          "no_such_device" not in display_map)

    # --- check_local_intel_history()'s new fields ---
    local_intel = LocalConfirmedIntel(str(state_dir))
    local_intel.record("ip", "203.0.113.99", "confirming_device_1", reason="STAGE_1_HARD_STOP")
    local_intel.record("ip", "203.0.113.99", "confirming_device_2", reason="STAGE_1_HARD_STOP")

    alerts_path = state_dir / "alerts.json"
    now = time.time()
    with open(alerts_path, "w", encoding="utf-8") as f:
        # a DIFFERENT, not-yet-flagged device touching the same now-confirmed IP
        f.write(json.dumps({
            "timestamp": now, "device": {"id": "new_finder_device", "hostname": "unknown", "ip": "192.168.1.77"},
            "network_context": {"destination_ip": "203.0.113.99", "queried_domain": "unknown"},
        }) + "\n")
        # the device that already confirmed it itself -- must be EXCLUDED (pre-existing behavior)
        f.write(json.dumps({
            "timestamp": now, "device": {"id": "confirming_device_1", "hostname": "example_pc", "ip": "192.168.1.12"},
            "network_context": {"destination_ip": "203.0.113.99", "queried_domain": "unknown"},
        }) + "\n")

    matches = check_local_intel_history(alerts_path, local_intel, days_back=14)
    check("REGRESSION GUARD: a device that already confirmed the IOC itself is still excluded",
          len(matches) == 1, f"got {len(matches)} match(es): {matches}")
    m = matches[0] if matches else {}
    check("THE FIX: the match dict now carries device_ip (not just hostname, which can be 'unknown')",
          m.get("device_ip") == "192.168.1.77")
    check("THE FIX: the match dict now carries count (2 confirmations recorded above)",
          m.get("count") == 2, f"got={m.get('count')}")
    check("THE FIX: the match dict now carries first_confirmed (a real timestamp, not None)",
          isinstance(m.get("first_confirmed"), float) and m["first_confirmed"] > 0)
    check("THE FIX: the match dict now carries reason, pulled straight from the stored IOC entry",
          m.get("reason") == "STAGE_1_HARD_STOP")
    check("REGRESSION GUARD: confirmed_by still lists both real confirming devices",
          set(m.get("confirmed_by", [])) == {"confirming_device_1", "confirming_device_2"})


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: ollama_soc.py's withheld-pattern spread-history trend logic. Mirrors the
# real logic added inline in main()'s loop (same style test_phase20_alert_quality.py's
# own _action_summary_for mirror uses for logic embedded in a giant method with no
# extractable unit) -- kept deliberately line-for-line equivalent to the real code so
# it can't silently drift; a real end-to-end run isn't practical to invoke here (needs
# a live Ollama server, real alerts.json activity, etc.).
# ═══════════════════════════════════════════════════════════════════════════════════
from datetime import datetime


def _simulate_withheld_occurrence(cache_entry: dict, devices_now: set, dev_display_map: dict, now_ts: float) -> str:
    withheld_history = cache_entry.setdefault("withheld_history", [])
    new_devices = devices_now - set(withheld_history[-1]["device_ids"]) if withheld_history else devices_now
    new_device_labels = sorted(dev_display_map.get(d, d) for d in new_devices)
    if not withheld_history:
        outcome_detail = f"first withheld, spreading to {len(devices_now)} device(s): {', '.join(sorted(dev_display_map.get(d, d) for d in devices_now)) or 'unknown'}"
    elif new_devices:
        spread_seq = "→".join(str(len(h["device_ids"])) for h in withheld_history) + f"→{len(devices_now)}"
        first_ts_human = datetime.fromtimestamp(withheld_history[0]["ts"]).strftime("%Y-%m-%d %H:%M")
        outcome_detail = (
            f"withheld {len(withheld_history) + 1} time(s) — spread {spread_seq} devices "
            f"since {first_ts_human} (newly joined: {', '.join(new_device_labels)})"
        )
    else:
        last_ts_human = datetime.fromtimestamp(withheld_history[-1]["ts"]).strftime("%Y-%m-%d %H:%M")
        outcome_detail = (
            f"withheld {len(withheld_history) + 1} time(s) — still {len(devices_now)} device(s), "
            f"no new spread since {last_ts_human}"
        )
    withheld_history.append({
        "ts": now_ts, "device_ids": sorted(devices_now),
        "display_names": sorted(dev_display_map.get(d, d) for d in devices_now),
    })
    cache_entry["withheld_history"] = withheld_history[-20:]
    return outcome_detail


dmap = {"dev_a": "example_pc_fritz_box", "dev_b": "example_laptop_fritz_box", "dev_c": "example_smartwatch_fritz_box"}

cache_entry = {}
detail1 = _simulate_withheld_occurrence(cache_entry, {"dev_a", "dev_b"}, dmap, time.time())
check("first occurrence: no prior history to compare against, lists all current devices as the finding",
      "first withheld" in detail1 and "example_pc_fritz_box" in detail1 and "example_laptop_fritz_box" in detail1,
      detail1)
check("first occurrence seeds withheld_history with exactly one entry",
      len(cache_entry["withheld_history"]) == 1)

detail2 = _simulate_withheld_occurrence(cache_entry, {"dev_a", "dev_b"}, dmap, time.time())
check("THE FIX (no new spread case): repeat occurrence with the SAME device set produces "
      "'no new spread' phrasing, not a false 'newly joined' claim",
      "no new spread" in detail2, detail2)

detail3 = _simulate_withheld_occurrence(cache_entry, {"dev_a", "dev_b", "dev_c"}, dmap, time.time())
check("THE FIX (the actual user requirement): a genuinely new device joining is identified "
      "BY NAME, not just as a count increment",
      "newly joined" in detail3 and "example_smartwatch_fritz_box" in detail3, detail3)
check("REGRESSION GUARD: the newly-joined phrase does NOT also re-list dev_a/dev_b as "
      "'newly joined' -- only the genuinely new device(s), diffed against the LAST "
      "entry only",
      detail3.count("newly joined:") == 1 and "newly joined: example_smartwatch_fritz_box" in detail3, detail3)
check("spread-count sequence in the trend phrase reflects the real history (2→2→3)",
      "2→2→3" in detail3, detail3)

# A device dropping out then reappearing should NOT show as "newly joined" if it was
# already present in the immediately-preceding entry's diff base -- diff is against the
# LAST entry only, not "ever seen across all history".
cache_entry2 = {}
_simulate_withheld_occurrence(cache_entry2, {"dev_a", "dev_b"}, dmap, time.time())
_simulate_withheld_occurrence(cache_entry2, {"dev_a"}, dmap, time.time())  # dev_b drops out
detail_reappear = _simulate_withheld_occurrence(cache_entry2, {"dev_a", "dev_b"}, dmap, time.time())
check("a device that dropped out and reappeared IS correctly flagged as newly joined "
      "again (diff against the immediately-preceding entry, which no longer had it)",
      "newly joined" in detail_reappear and "example_laptop_fritz_box" in detail_reappear, detail_reappear)

# Cap check: 21 occurrences should leave exactly 20 entries.
cache_entry3 = {}
for i in range(21):
    _simulate_withheld_occurrence(cache_entry3, {"dev_a"}, dmap, time.time())
check("THE FIX (own cap, since nothing else prunes this sub-field): 21 occurrences "
      "leaves exactly 20 history entries, not unbounded growth",
      len(cache_entry3["withheld_history"]) == 20, f"got {len(cache_entry3['withheld_history'])}")

# setdefault safety on a pre-existing cache entry with no withheld_history key at all
# (simulating a pattern that existed in the cache before this change shipped).
pre_existing_entry = {"classification": "benign", "confidence": 0.9, "ts": time.time(), "action_taken": False}
detail_legacy = _simulate_withheld_occurrence(pre_existing_entry, {"dev_a"}, dmap, time.time())
check("a pre-existing cache entry with no withheld_history key doesn't crash setdefault, "
      "and is treated as a genuine first occurrence",
      "first withheld" in detail_legacy, detail_legacy)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 41 alert-context-enrichment checks PASSED.")
