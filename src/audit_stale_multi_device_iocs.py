"""
audit_stale_multi_device_iocs.py - CLI utility to find (and, after review, remove)
state/local_confirmed_intel.json entries showing the "self-reinforcing, multi-device
stale poisoning" signature.

WHAT THIS PATTERN IS
=====================================================================================
local_confirmed_intel.json's network-effect learning is supposed to work like this:
one device confirms a real threat -> a DIFFERENT device touching the SAME IOC later
gets an immediate hard-stop instead of re-earning evidence from scratch (the CL-AFPE's
Stage-1 Check 7). That's valuable *only if* the original confirmation was itself
trustworthy.

Found via a live third-party review of a real production alert (a Fire TV device
hard-stopping on an IP the system's OWN GeoIP lookup couldn't even identify): several
IP entries in this store had been confirmed by MULTIPLE unrelated devices independently
within hours of each other, with reason=TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP (the
self-reinforcing loop -- every hard-stop hit re-records the same entry, refreshing its
TTL indefinitely). On a small home network, several DIFFERENT devices independently
"confirming" the same obscure IP within a few hours is far more consistent with a
shared SYSTEMIC bug (e.g. a reverse-DNS-lookup-pool-exhaustion storm, or a
reputation-attribution bug where an unrelated domain/IP got blamed for a different
domain's risk score) poisoning the store simultaneously across devices, than with a
real coordinated multi-device compromise.

WHY THIS IS A REVIEW TOOL, NOT AN AUTO-CLEAN TOOL (unlike clean_confirmed_intel.py)
=====================================================================================
clean_confirmed_intel.py's criteria (is_telemetry_domain() / private-IP / safe_ips) are
SAFE to bulk-auto-apply, because they're independently, structurally true regardless of
context -- a domain either is known-safe infrastructure or it isn't. This pattern is
different: "multiple devices confirmed the same IOC quickly" is *suggestive* of stale
poisoning, not PROOF of it -- a genuine botnet/malware campaign hitting several devices
on the same network would look identical. That's why --apply here requires you to name
the specific IPs to remove (after reading the dry-run report and using your own
judgment, e.g. checking whether a code fix landed in that time window that explains the
false-positive shape), not a blanket "remove everything matching the pattern" flag.

Usage (from anywhere -- resolves the repo root and state file relative to this script):
  1. Stop the service first (systemctl stop soc.service or however you run it) --
     avoids a write race with the live process's own periodic saves.
  2. Dry run (lists every IP entry matching the signature, changes nothing):
       python3 src/audit_stale_multi_device_iocs.py
  3. After reviewing, remove specific ones you've judged to be stale poisoning:
       python3 src/audit_stale_multi_device_iocs.py --apply 1.2.3.4 5.6.7.8
  4. Restart the service.
"""
import json
import sys
import time
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG

# A single confirmation, or one confirmed by just one device re-hitting it repeatedly,
# is completely normal and NOT what this tool looks for -- it's specifically the
# "several INDEPENDENT devices, in a short window, all confirming the same thing" shape.
MIN_DISTINCT_DEVICES = 2
STALE_LOOP_REASON = "TRUST_CACHE_OVERRIDDEN_BY_HARD_STOP"


def find_candidates(ips: dict) -> list:
    """Returns [(ip, entry)] for every IP entry matching the self-reinforcing
    multi-device signature, sorted by confirmation count descending (most-affected
    first)."""
    candidates = [
        (ip, entry) for ip, entry in ips.items()
        if entry.get("reason") == STALE_LOOP_REASON
        and len(entry.get("sources", [])) >= MIN_DISTINCT_DEVICES
    ]
    candidates.sort(key=lambda kv: -kv[1].get("count", 0))
    return candidates


def main():
    args = sys.argv[1:]
    apply_ips = set()
    if args and args[0] == "--apply":
        apply_ips = set(args[1:])
        if not apply_ips:
            print("--apply requires at least one IP argument, e.g.:")
            print("  python3 src/audit_stale_multi_device_iocs.py --apply 1.2.3.4 5.6.7.8")
            sys.exit(1)

    state_path = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    intel_path = state_path / "local_confirmed_intel.json"

    if not intel_path.exists():
        print(f"No file at {intel_path} -- nothing to audit.")
        sys.exit(0)

    data = json.loads(intel_path.read_text(encoding="utf-8"))
    ips = data.get("ip", {})

    candidates = find_candidates(ips)
    if not candidates:
        print("No IP entries match the self-reinforcing multi-device signature "
              f"(reason={STALE_LOOP_REASON}, >={MIN_DISTINCT_DEVICES} distinct devices).")
        sys.exit(0)

    now = time.time()
    print(f"Found {len(candidates)} IP entr{'y' if len(candidates) == 1 else 'ies'} matching the "
          f"self-reinforcing multi-device signature:\n")
    for ip, entry in candidates:
        age_hr = (now - entry.get("first_confirmed", now)) / 3600.0
        marker = " <-- WILL REMOVE" if ip in apply_ips else ""
        print(f"  {ip}  count={entry.get('count')}  devices={len(entry.get('sources', []))}  "
              f"age={age_hr:.1f}h{marker}")

    unmatched = apply_ips - {ip for ip, _ in candidates}
    if unmatched:
        print(f"\nWARNING: --apply named IP(s) not found among the candidates above "
              f"(not removed): {', '.join(sorted(unmatched))}")

    if not apply_ips:
        print("\nDry run only -- nothing was changed. Review the list above, then re-run "
              "with --apply <ip> [<ip> ...] naming the specific entries you've judged to "
              "be stale poisoning, not a real multi-device confirmation.")
        return

    removed = 0
    for ip in apply_ips:
        if ip in ips:
            del ips[ip]
            removed += 1

    intel_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"\nDone. Removed {removed} IP entr{'y' if removed == 1 else 'ies'} and saved {intel_path}.")


if __name__ == "__main__":
    main()
