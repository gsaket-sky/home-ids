"""
release_wrongly_blocked_domains.py - CLI utility to review and release Pi-hole domain
blocks that were caused by tonight's now-fixed bugs (confirmed-intel poisoning,
DNS_COVERT_TUNNELING domain misattribution, DNS_EVASION on intra-LAN traffic, the
Telegram-reputation tier-escalation bug).

Found via a direct audit of state/ids_state.json's ips_state.blocked_domains: 119
domains were actively blocked, ~73 of which are legitimate services (email, NAS
remote access, streaming apps, work/dev tools) with no plausible connection to a real
threat, alongside a genuine cluster of ~46 domains on ONE device (family_pc_fritz_box)
showing a real DGA/malware-downloader-rotation pattern that should stay blocked.

Classifies every currently-blocked domain into exactly one bucket:
  SAFE_RECOGNIZED - already-established utils.is_telemetry_domain() allowlist
  SAFE_REVIEWED   - a SEPARATE, script-local list built from manually reviewing this
                    specific production blocklist (deliberately NOT merged into
                    is_telemetry_domain(), which every live detector reads -- widening
                    that shared, always-on allowlist is a bigger decision than a
                    one-time historical cleanup should make silently)
  SUSPICIOUS      - matches a known-bad pattern found in this exact data (DGA-style
                    .ru domains, the downloads77-windows.* rotation) -- NEVER touched
  UNCLASSIFIED    - anything else -- NEVER touched, left for manual review

Usage (from anywhere -- resolves state relative to config.yaml's state_path):
  1. Dry run (shows every domain's classification, changes nothing):
       python3 src/release_wrongly_blocked_domains.py
  2. Actually release the SAFE_RECOGNIZED + SAFE_REVIEWED domains:
       python3 src/release_wrongly_blocked_domains.py --apply
  Releasing uses the exact same path as the real "Mark False Positive" Telegram
  button: fp_engine.mark_false_positive() (immunizes the base domain, writes the
  training correction) + IPSMitigator.unblock_by_base_domain() (sweeps every blocked
  FQDN under that base domain, not just an exact-string match).
"""
import re
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config import CONFIG
from utils import is_telemetry_domain, etld1
from core.state_guard import StateManager
from mitigation.ips import IPSMitigator
from intelligence.fp_engine import AutonomousFPEngine

# Built from manually reviewing every non-is_telemetry_domain() entry in this exact
# production blocklist (see this file's module docstring for why this stays separate
# from the shared, always-on utils.is_telemetry_domain() allowlist).
SAFE_REVIEWED_BASE_DOMAINS = {
    "claudeusercontent.com",     # Claude (Anthropic) artifact URLs
    "sharepoint.com",            # Microsoft SharePoint
    "forter.com",                # fraud-detection CDN used by many e-commerce checkouts
    "conviva.com",                # video-streaming analytics vendor
    "taobao.com", "alibaba.com", "aliyuncs.com", "aliexpress-media.com",  # Alibaba group
    "ardmediathek.de", "zdf.de",  # German public broadcasters
    "adobe.com",                 # Adobe auth
    "coinbase.com",
    "weather.com",
    "zee5.com",                  # Indian streaming
    "nflximg.com",                # Netflix CDN (not covered by nflxvideo.net's existing entry)
    "ota-cloudfront.net",         # Amazon OTA firmware-update CDN (distinct from cloudfront.net)
    "outlook.com", "gmail.com",   # email
    "vscode-cdn.net",
    "antigravity-unleash.goog",   # Google's own gTLD (.goog) -- etld1() treats the whole
                                   # string as the base domain since "goog" is the registered TLD
    "epson.biz",
    "cdninstagram.com",
    "ntp-fireos.com",             # Amazon Fire OS NTP time sync
    "rossmann.net",               # cookie-consent vendor (Usercentrics) for Rossmann, a real retail chain
    "aws.dev",                    # AWS's own diagnostic domain
    "route71.net",                # AWS-adjacent Amazon infra domain
    "amazon.eu", "amazon-dss.com", "amazoncrl.com", "amazonsilk.com",  # Amazon family,
                                   # distinct eTLD+1s from amazon.com already covered
    "snapdeal.com",               # Indian e-commerce
    "https",                      # garbage/legacy entry, not a real domain -- pre-dates
                                   # the current comment-on-every-block convention
    "githubcopilot.com",          # GitHub Copilot's own telemetry
    "hrnmtech.de",                # ZDF (German public broadcaster) video-segment CDN
    "nintendo.net",                # Nintendo's own console CDN
    "pki.goog",                   # Google Certificate Transparency infrastructure
    "samsungnyc.com",             # Samsung's own image-resize CDN
    "rollingstone.com",           # Rolling Stone magazine
    "exp-tas.com",                # Microsoft/Azure-hosted, no malware/phishing history
    "nmrodam.com",                # Nielsen Marketing (TV measurement) -- legit company,
                                   # user accepted it's ad/tracking infra, chose to unblock
}

# Patterns found in THIS production data with a real malware/DGA signature -- never
# touched regardless of --apply, even if a future edit to SAFE_REVIEWED_BASE_DOMAINS
# accidentally overlapped (defense in depth, not expected to ever matter).
SUSPICIOUS_PATTERNS = [
    re.compile(r"^qwertyuiopasdfghjklzxcvbnm-\d+\.ru$"),
    re.compile(r"^xkqz289dfj10dj-\d+\.ru$"),
    re.compile(r"^downloads77-windows\."),
]


def classify(domain: str, base_domain: str) -> str:
    if any(p.match(domain) or p.match(base_domain) for p in SUSPICIOUS_PATTERNS):
        return "SUSPICIOUS"
    if is_telemetry_domain(base_domain):
        return "SAFE_RECOGNIZED"
    if base_domain in SAFE_REVIEWED_BASE_DOMAINS:
        return "SAFE_REVIEWED"
    return "UNCLASSIFIED"


def main():
    apply_changes = "--apply" in sys.argv

    state_path = CONFIG.get("state_path", "state/ids_state.json")
    sm = StateManager(state_path=state_path)
    sm.load_from_disk()

    blocked = dict(sm.get_ips_state().get("blocked_domains", {}))
    if not blocked:
        print("No blocked domains found -- nothing to review.")
        return

    buckets = {"SAFE_RECOGNIZED": {}, "SAFE_REVIEWED": {}, "SUSPICIOUS": {}, "UNCLASSIFIED": {}}
    for domain, meta in blocked.items():
        base = etld1(domain) or domain
        bucket = classify(domain, base)
        buckets[bucket].setdefault(base, []).append((domain, meta))

    print(f"Total blocked domains: {len(blocked)}\n")
    for bucket_name in ("SAFE_RECOGNIZED", "SAFE_REVIEWED", "SUSPICIOUS", "UNCLASSIFIED"):
        bases = buckets[bucket_name]
        total_domains = sum(len(v) for v in bases.values())
        print(f"=== {bucket_name}: {len(bases)} base domain(s), {total_domains} blocked FQDN(s) ===")
        for base in sorted(bases):
            entries = bases[base]
            hostnames = sorted({m.get("hostname", "unknown") for _, m in entries})
            print(f"  {base}  <- {', '.join(d for d, _ in entries)}  (device: {', '.join(hostnames)})")
        print()

    to_release = {**buckets["SAFE_RECOGNIZED"], **buckets["SAFE_REVIEWED"]}
    if not to_release:
        print("Nothing classified as safe to release.")
        return

    if not apply_changes:
        print(f"Dry run only -- would release {len(to_release)} base domain(s) "
              f"({sum(len(v) for v in to_release.values())} blocked FQDNs total). "
              f"Re-run with --apply to actually release them.\n"
              f"SUSPICIOUS and UNCLASSIFIED entries are never touched by this script.")
        return

    fp = AutonomousFPEngine(config=CONFIG, state_dir=str(Path(state_path).parent))
    ips = IPSMitigator(config=CONFIG, state_manager=sm)

    total_released = 0
    for base, entries in to_release.items():
        # Same path the real "Mark False Positive" Telegram button uses: a minimal
        # synthetic alert_payload (signature="" takes the default domain-based
        # immunization branch -- see mark_false_positive()'s own PHASE 21D2 comment)
        # so it's ONE well-tested code path, not a bespoke direct-immunize call.
        hostname = entries[0][1].get("hostname", "unknown")
        device_id = entries[0][1].get("device", {}).get("id") if isinstance(entries[0][1].get("device"), dict) else entries[0][1].get("device_id", "unknown")
        alert_payload = {"signature": "", "device": {"id": device_id}}
        result = fp.mark_false_positive(alert_payload, hostname, base, source="operator")
        released = ips.unblock_by_base_domain(result.get("base_domain", base))
        total_released += len(released)
        print(f"Released {len(released)} FQDN(s) under '{base}': {', '.join(released) if released else '(none matched -- already released?)'}")

    sm.flush_to_disk()
    print(f"\nDone. Immunized {len(to_release)} base domain(s), released {total_released} blocked FQDN(s) total.")
    print("Restart the service (or wait for the next .ipc_sync_signal-triggered reload) to pick up the change.")


if __name__ == "__main__":
    main()
