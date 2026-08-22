"""
clean_confirmed_intel.py - CLI utility to audit and prune state/local_confirmed_intel.json
for entries that should never have been recordable as "confirmed malicious":
  - Known-safe vendor/CDN/telemetry base domains (utils.is_telemetry_domain()) -- e.g.
    amazon.com, netflix.com, microsoft.com. These are too broad/shared to ever confirm
    at the base-domain granularity this store matches on.
  - Private/multicast/loopback/link-local/reserved IPs, or anything explicitly listed
    in config.yaml's safe_ips -- e.g. your own server/router, or IGMP/mDNS multicast
    addresses like 224.0.0.251 / ff02::fb.

fp_engine.py's record_confirmed_threat() and Stage-1 Check 7 already refuse to ever
write or honor either category going forward (see the BUGFIX comments there) -- this
tool exists for two ongoing reasons, not just the one-time historical cleanup:
  1. Those guards only protect entries ALREADY recognized as safe. A different,
     not-yet-recognized domain/IP could still get poisoned by some future bug --
     this gives you a way to audit the store on demand.
  2. If you later add a new entry to safe_ips or the telemetry-domain allowlist, any
     already-poisoned data for it stays on disk until something prunes it -- the code
     fix protects behavior immediately, but the stale data doesn't clean itself up.

Usage (from anywhere -- resolves the repo root and state file relative to this script):
  1. Stop the service first (systemctl stop soc.service or however you run it) --
     avoids a write race with the live process's own periodic saves.
  2. Dry run (shows what WOULD be removed, changes nothing):
       python3 src/clean_confirmed_intel.py
  3. Actually apply the cleanup:
       python3 src/clean_confirmed_intel.py --apply
  4. Restart the service.
"""
import ipaddress
import json
import sys
from pathlib import Path

# Ensure src/ is in sys.path (matches release_device.py's convention)
SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG
from utils import is_telemetry_domain


def is_protected_ip(ip: str, safe_ips: set) -> bool:
    if ip in safe_ips:
        return True
    try:
        addr = ipaddress.ip_address(ip)
        return bool(addr.is_private or addr.is_multicast or addr.is_loopback
                    or addr.is_link_local or addr.is_reserved or addr.is_unspecified)
    except ValueError:
        return False


def main():
    apply_changes = "--apply" in sys.argv

    state_path = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
    intel_path = state_path / "local_confirmed_intel.json"

    if not intel_path.exists():
        print(f"No file at {intel_path} -- nothing to clean.")
        sys.exit(0)

    safe_ips = set(CONFIG.get("safe_ips", []) or [])

    data = json.loads(intel_path.read_text(encoding="utf-8"))
    domains = data.get("domain", {})
    ips = data.get("ip", {})

    domains_to_remove = [d for d in domains if is_telemetry_domain(d)]
    ips_to_remove = [ip for ip in ips if is_protected_ip(ip, safe_ips)]

    if not domains_to_remove and not ips_to_remove:
        print("Nothing to clean -- no known-safe/private/multicast entries found in the store.")
        return

    verb = "Removing" if apply_changes else "Would remove"

    if domains_to_remove:
        print(f"{verb} {len(domains_to_remove)} known-safe DOMAIN entr{'y' if len(domains_to_remove) == 1 else 'ies'}:")
        for d in sorted(domains_to_remove):
            entry = domains[d]
            print(f"  {d}  (count={entry.get('count')}, sources={len(entry.get('sources', []))} device(s))")

    if ips_to_remove:
        print(f"\n{verb} {len(ips_to_remove)} known-safe/private/multicast IP entr{'y' if len(ips_to_remove) == 1 else 'ies'}:")
        for ip in sorted(ips_to_remove):
            entry = ips[ip]
            print(f"  {ip}  (count={entry.get('count')}, sources={len(entry.get('sources', []))} device(s))")

    if not apply_changes:
        print("\nDry run only -- nothing was changed. Re-run with --apply to actually remove these.")
        return

    for d in domains_to_remove:
        del domains[d]
    for ip in ips_to_remove:
        del ips[ip]

    intel_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"\nDone. Removed {len(domains_to_remove)} domain + {len(ips_to_remove)} IP entries and saved {intel_path}.")


if __name__ == "__main__":
    main()
