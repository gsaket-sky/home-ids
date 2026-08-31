"""
utils.py – Utility helper functions.
Houses static string parsers, heuristic evaluations (DGA calculations, entropy math),
and bypass allowlists (CDNs, Telemetry) used to prevent false positive alert floods.

RECENT FIXES:
- FIXED: Resolved duplicate 'switch' key collision in infer_device_type mapping (gaming console vs. iot).
- Adjusted DGA logic to trap zero-vowel evading logic correctly.
- Added strict LRU caching on socket DNS lookups to prevent thread exhaustion.
- Adjusted digit ratio threshold in 6–11 character DGA bucket to accurately capture alphanumeric variants.
- FIXED: Added infra mapping (router, dns_server, gateway) to infer_device_type to activate deterministic scoring paths.
- FIXED: Corrected structural indentation in infer_device_type loop that bypassed the entire pattern dictionary.
- ADDED (SOC): Expanded infer_device_type pattern engine to automatically identify modern smart home,
  camera, and industrial IoT vendors out-of-the-box.
- ADDED: Centralized .arpa reverse DNS handling into is_telemetry_domain and suspicious_dga bypasses.
- FIXED (REGRESSION): Reordered infer_device_type dictionary to prevent substring collisions (e.g., samsung vs samsungtv).
- FIXED (REGRESSION): Increased digit ratio ceiling to <0.75 in DGA logic to catch heavy alphanumeric hashes.
- FIXED (MATH): Lowered entropy threshold to >3.2 for n>=12; previous 3.8 threshold exceeded max theoretical entropy (log2(N)) for strings under 14 chars.
- FIXED: Added explicit bypasses for .local and .lan domains to prevent mDNS hashes from triggering DGA/DNS penalties.
"""
import math
import ipaddress
import logging
import json
import time
from pathlib import Path

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    from manuf import manuf as _manuf_module
    # update=False (also the library's own default): pure offline lookup against the
    # bundled Wireshark manuf database, no network call at startup -- matches this
    # project's offline-first pattern (GeoIP mmdb reads, tldextract's suffix list).
    _MAC_PARSER = _manuf_module.MacParser(update=False)
except Exception:
    _MAC_PARSER = None

LOGGER = logging.getLogger("home_ids.utils")

def memory_limited_preexec_fn(limit_bytes: int):
    """Returns a preexec_fn for subprocess.run(...) that caps the CHILD process's
    virtual address space (RLIMIT_AS) before exec -- a cheap, no-IPC-required backstop
    against one oversized subprocess invocation (reactive-capture's batch Zeek/Suricata
    scans -- see fritzbox_capture.py's reprocess_with_zeek() and suricata_scan.py's
    run_suricata_on_pcap()) consuming unbounded memory inside the parent's own cgroup.
    See Documentation/REACTIVE_CAPTURE_LOAD_ANALYSIS.md §7 for why this exists: the
    2026-08-31 soc.service OOM incident showed capture-burst size (and therefore
    Zeek/Suricata's own memory use processing it) has no ceiling today.

    POSIX-only: returns None (i.e. "no preexec_fn, no limit applied") on any platform
    where the resource module or RLIMIT_AS isn't available (Windows dev machines,
    notably), or when limit_bytes<=0 (feature explicitly disabled) -- callers pass the
    result straight to subprocess.run(preexec_fn=...) with no platform check of their
    own needed. A child that exceeds the limit fails its own allocation (typically a
    non-zero exit or a signal death) -- both existing call sites already treat a
    non-zero-exit/timeout as a non-fatal, logged, "no findings this burst" outcome, so
    no new exception handling is needed at either call site."""
    if limit_bytes <= 0:
        return None
    try:
        import resource
        if not hasattr(resource, "RLIMIT_AS"):
            return None
    except ImportError:
        return None

    def _set_limit():
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))

    return _set_limit


def normalize_domain(domain):
    """Lowercases and cleans up trailing dots from raw DNS queries."""
    return str(domain).lower().strip(".")

def get_mac_vendor(mac_addr: str) -> str:
    """Offline MAC-OUI vendor lookup (Wireshark's manuf database via the `manuf`
    package, no network dependency) -- feeds infer_device_type()'s mac_vendor
    parameter, which existed but was never actually wired up by any caller until this
    fix (see identity.py's apply_device_type()). Returns "" (not None, never raises)
    for empty/"unknown" input, a locally-administered/randomized MAC (the increasingly
    common iOS/Android privacy-MAC behavior -- these have no registered OUI to find),
    or an OUI the bundled database doesn't recognize -- infer_device_type() already
    treats an empty mac_vendor as "no signal" and falls through to its next layer."""
    if not mac_addr or mac_addr == "unknown" or _MAC_PARSER is None:
        return ""
    try:
        vendor = _MAC_PARSER.get_manuf_long(mac_addr) or _MAC_PARSER.get_manuf(mac_addr)
        return vendor or ""
    except Exception:
        return ""

def sanitize_hostname(host):
    """Prevents invalid characters in Prometheus labels and dashboard variables."""
    if not host:
        return "unknown"
    return host.lower().replace(".", "_").replace("-", "_")[:40]

def etld1(domain):
    """Extracts the base domain and suffix (e.g., mail.google.com -> google.com)."""
    if not domain:
        return ""
    # PHASE 8 FIX: a bare IP address (raw-IP connection with no resolved DNS name) has no
    # eTLD+1. tldextract correctly returns an empty domain/suffix for IPs, but the naive
    # last-two-labels fallback below doesn't know that and happily chops one into a fake
    # 2-octet "domain" (e.g. "149.154.166.110" -> "166.110") — this silently populated
    # fp_engine's trust cache with a meaningless, collision-prone key (found sitting in
    # state/fp_trust_cache.json as literally "166.110"). Reject IP-shaped input up front.
    try:
        ipaddress.ip_address(domain.strip("."))
        return ""
    except ValueError:
        pass
    if tldextract is not None:
        try:
            ext = tldextract.extract(domain)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        except Exception:
            pass
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain

def entropy(text):
    """Computes Shannon entropy of a string. High entropy suggests encryption or DGA."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    ent = 0
    for v in freq.values():
        p = v / len(text)
        ent -= p * math.log2(p)
    return ent

def vowel_ratio(text):
    """Measures vowel concentration. DGA strings often lack human-readable vowel structures."""
    vowels = sum(1 for c in text if c in "aeiou")
    return vowels / max(len(text), 1)

_CDN_PARENT_ALLOWLIST = frozenset({
    "cloudfront.net", "amazonaws.com", "awsstatic.com", "amazonvideo.com", "aiv-cdn.net", "aiv-delivery.net", "media-amazon.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akamaiedge.net", "akadns.net", "edgesuite.net", "edgekey.net",
    "googlevideo.com", "ggpht.com", "gstatic.com", "googleusercontent.com", "googlesyndication.com", "doubleclick.net",
    "fastly.net", "fastlylb.net", "fastly-edge.com", "cloudflare.net", "cdn.ampproject.org", "fbcdn.net", "azureedge.net", "msecnd.net",
    "aaplimg.com", "mzstatic.com", "nflxvideo.net", "nflxso.net", "nflxext.com",
    "scdn.co", "spotifycdn.com", "twimg.com", "ytimg.com",
    "samsungcloud.com", "samsungcloud.net", "samsungrm.net", "samsungdm.com", "samsung.com", "samsungapps.com",
    "gvt1.com", "gvt2.com", "gvt3.com", "crashlytics.com", "app-measurement.com", "firebaseio.com",
    "icloud.com", "apple-dns.net", "push.apple.com", "googleapis.com", "android.clients.google.com",
    "appsflyersdk.com", "amplitude.com", "moengage.com", "iterable.com", "mwbsys.com",
    # PHASE 8 FIX: found by tracing the live alerts.json flood — 97 of 169
    # DNS_COVERT_TUNNELING alerts (43% of ALL alerts in the file) were msh.amazon.co.uk
    # alone (Amazon Alexa/FireTV device-management telemetry), the same
    # long/encoded-session-token-subdomain shape as the aiv-delivery.net Prime Video hotfix
    # already in this file, just a different Amazon domain and never patched. facebook.com/
    # whatsapp were the next-largest repeat offenders (z-m-gateway.facebook.com,
    # g.whatsapp.net, media-*.cdn.whatsapp.net) — both Meta-owned, same CDN pattern.
    "amazon.co.uk", "amazon.de", "facebook.com", "whatsapp.com", "whatsapp.net",
    "netflix.net", "pluto.tv", "bugsnag.com", "ntp.org"
})

_TELEMETRY_DOMAINS = frozenset({
    "appsflyersdk.com", "crashlytics.com", "google-analytics.com",
    "firebaseio.com", "aria.microsoft.com", "bugsmirror.com",
    "app-measurement.com", "moengage.com", "zomato.com",
    "samsungdm.com", "samsungcloud.com", "samsungrm.net",
    "amplitude.com", "iterable.com", "asnapieu.com", "mwbsys.com"
})

_DYNAMIC_TELEMETRY_ALLOWLIST = set()

def register_dynamic_allowlist_domain(domain: str) -> None:
    """Dynamically adds an autonomously verified domain to the live telemetry allowlist."""
    if not domain:
        return
    base_dom = etld1(domain.lower().strip("."))
    _DYNAMIC_TELEMETRY_ALLOWLIST.add(base_dom)
    LOGGER.debug("Registered dynamic telemetry domain: %s", base_dom)

# PHASE 18: shared by every scripts/*.py cron job (ollama_soc.py, retro_hunter.py,
# top_domains_report.py, train_fp_classifier.py) to report its own health -- these are
# all separate short-lived processes with no Prometheus HTTP server of their own, so
# this small relay file is how their activity becomes visible to Grafana at all.
# core/metrics_sync.py's sync_relay_metrics() reads it from the long-running pipeline
# process. Read-modify-write against one shared file; last-write-wins is acceptable
# since scheduled jobs are staggered by design (config.yaml: "Verified: no two enabled
# jobs fire in the same hour").
def write_job_health(state_dir, job_name: str, duration_seconds: float, extra: dict = None) -> None:
    path = Path(state_dir) / "job_health.json"
    try:
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        existing = {}
    entry = {"last_success": time.time(), "duration_seconds": duration_seconds}
    if extra:
        entry.update(extra)
    existing[job_name] = entry
    try:
        path.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    except Exception as exc:
        LOGGER.debug("Failed to write job_health.json for %s: %s", job_name, exc)

def is_telemetry_domain(domain: str) -> bool:
    """True if domain matches known high-volume telemetry SDKs, reverse DNS (.arpa), local network boundaries, cloud telemetry infrastructure, or CL-AFPE dynamic trust cache."""
    if not domain:
        return False
    norm = str(domain).lower().strip(".")
    
    # Fast path: Reverse DNS and local network lookups are inherently safe telemetry
    if norm.endswith(".arpa") or norm.endswith(".local") or norm.endswith(".lan") or norm.endswith(".sky") or norm.endswith(".home") or norm.endswith(".fritz.box") or norm.endswith(".internal") or norm.endswith(".home.arpa"):
        return True
        
    base_dom = etld1(norm)
    if base_dom in _DYNAMIC_TELEMETRY_ALLOWLIST:
        return True

    parts = norm.split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in _TELEMETRY_DOMAINS:
        return True
    if len(parts) >= 3 and ".".join(parts[-3:]) in _TELEMETRY_DOMAINS:
        return True
    return _is_cdn_or_cloud_domain(norm)

def _is_cdn_domain(domain: str) -> bool:
    """True if the domain's parent or grandparent is a known CDN."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2 and ".".join(parts[-2:]) in _CDN_PARENT_ALLOWLIST:
        return True
    if len(parts) >= 3 and ".".join(parts[-3:]) in _CDN_PARENT_ALLOWLIST:
        return True
    return False

_SYSTEM_SAFE_BASE_DOMAINS = frozenset({
    # Homelab & Router TLDs
    "fritz.box", "sky", "local", "lan", "home", "internal",
    
    # Amazon & Alexa Ecosystem
    "amazon.com", "amazonaws.com", "a2z.com", "amazon.dev", "amazonalexa.com",
    "amazonvideo.com", "media-amazon.com", "cloudfront.net", "awsstatic.com",
    "aiv-cdn.net", "aiv-delivery.net", "amazon-adsystem.com", "ssl-images-amazon.com",
    "firetvcaptiveportal.com", "mmechocaptiveportal.com", "kindle.com",
    "amazon.co.uk", "amazon.de",  # PHASE 8 FIX: msh.amazon.co.uk was 43% of all alerts
    # PHASE 9.0.1 FIX: found via a live state-folder audit -- these were poisoning
    # local_confirmed_intel.json as "confirmed malicious" (200/44/19/1/1/4/1
    # confirmations respectively), cascading into Stage-1 hard-stops for every device
    # legitimately using Amazon/Alexa infrastructure. See fp_engine.py's
    # _is_domain_causal_hard_stop() -- the underlying attribution bug is fixed there;
    # these are the already-known-safe domains that bug happened to poison in
    # production before the fix landed.
    "acsechocaptiveportal.com", "tabletcaptiveportal.com", "aws.dev", "pv-cdn.net",
    "amazoncrl.com", "amazonsilk.com", "route71.net",

    # Meta / Facebook / WhatsApp Ecosystem — PHASE 8 FIX
    "facebook.com", "whatsapp.com", "whatsapp.net",
    "cdninstagram.com",  # PHASE 9.0.1 FIX: same live audit as above (5 confirmations)
    
    # Google & Android Ecosystem
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "googleusercontent.com", "googlesyndication.com", "google-analytics.com",
    "gvt1.com", "gvt2.com", "gvt3.com", "android.com", "ggpht.com",
    "doubleclick.net", "youtube.com", "ytimg.com", "1e100.net", "fastly-edge.com",
    # PHASE 9.0.1 FIX: same live audit -- antigravity-unleash.goog is a .goog TLD
    # (Google-exclusive, registry-restricted to Google itself) with 127 confirmations;
    # run.app is Google Cloud Run's own domain.
    "antigravity-unleash.goog", "run.app",
    
    # Apple & iOS/macOS Ecosystem
    "apple.com", "icloud.com", "icloud-content.com", "cdn-apple.com",
    "mzstatic.com", "aaplimg.com", "apple-dns.net", "push.apple.com",
    
    # Microsoft, Sentry & Developer/Security Ecosystem
    "microsoft.com", "windows.com", "azure.com", "live.com", "office.com",
    "msn.com", "office365.com", "msftncsi.com", "skype.com", "sentry.io",
    "brave.com", "wordnik.com", "napps-2.com", "bitdefender.net", "bitdefender.com",
    "trafficmanager.net", "azureedge.net", "msecnd.net", "windowsupdate.com",
    # PHASE 9.0.1 FIX: same live audit -- sharepoint.com/microsoftonline.com/
    # vscode-cdn.net (Microsoft's own dev-tooling CDN) and malwarebytes.com (an
    # antivirus VENDOR being flagged as "confirmed malicious" is the clearest possible
    # symptom of the non-causal-attribution bug fixed in fp_engine.py).
    "sharepoint.com", "microsoftonline.com", "vscode-cdn.net", "malwarebytes.com",
    
    # Smart Home, Synology, IoT & Streaming Platforms
    "quickconnect.to", "synology.me", "synology.com", "samsungcloud.com",
    "samsung.com", "samsungcloud.net", "samsungrm.net", "samsungdm.com", "lgsmartad.com",
    "lgthing.com", "roku.com", "netflix.com", "nflxvideo.net", "nflxso.net",
    "nflxext.com", "netflix.net", "spotify.com", "scdn.co", "spotifycdn.com", "plex.tv",
    "sonos.com", "tplinkcloud.com", "tuya.com", "tuyacn.com", "myq-cloud.com",
    "pluto.tv",  # PHASE 8 FIX: service-media-catalog.clusters.pluto.tv false positives
    # PHASE 9.0.1 FIX: same live audit -- nflximg.com (Netflix's own image CDN, 145
    # confirmations -- the single largest poisoned entry found), dreame.tech (a real
    # smart-vacuum vendor, 245 confirmations -- the largest of all), samsungqbe.com
    # (Samsung's QBE cloud service), avm.de (this router's OWN manufacturer's domain).
    "nflximg.com", "dreame.tech", "samsungqbe.com", "avm.de",

    # Alibaba Ecosystem -- PHASE 9.0.1 FIX: same live audit (alibaba.com=12,
    # aliyuncs.com=6, alicdn.com=2 confirmations); ucweb.com/taobao.com were already
    # curated safe in release_wrongly_blocked_domains.py's SAFE_REVIEWED list this
    # same session but never made it into this shared, canonical allowlist until now.
    "alibaba.com", "aliyuncs.com", "alicdn.com", "ucweb.com", "taobao.com",

    # Media, Education & Misc Vendors -- PHASE 9.0.1 FIX: same live audit.
    "zdf.de", "khanacademykids.org", "epson.biz",
    "claudeusercontent.com",  # Anthropic/Claude's own content domain
    # NOTE: coinbase.com is deliberately NOT added here, despite also being poisoned in
    # local_confirmed_intel.json (16 confirmations) -- threat_signals.py's
    # _VENDOR_CLOUD_API_DOMAINS already covers it on purpose, kept OUT of this broader
    # telemetry allowlist so an exfiltration burst against it is DAMPENED (0.35
    # confidence) rather than fully excluded (see that list's own comment: "a broad
    # match here would create a real blind spot"). Adding it here would silently defeat
    # that existing, deliberate design boundary. Its confirmed-intel entry ages out via
    # normal TTL instead -- the root-cause fix in fp_engine.py's
    # _is_domain_causal_hard_stop() already stops it from being re-poisoned.

    # Global CDNs & Security Ingestion
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com", "fastly.net", "fastlylb.net", "fastly-edge.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akamaiedge.net",
    "appsflyersdk.com", "amplitude.com", "moengage.com", "iterable.com", "mwbsys.com",
    "akadns.net", "edgesuite.net", "edgekey.net", "brave.com", "nordvpn.com",
    "bitdefender.net", "bitdefender.com", "fritz.box",
    "bugsnag.com",  # PHASE 8 FIX: sessions.bugsnag.com — legit crash reporting (same class as sentry.io)
    "ntp.org",  # PHASE 8 FIX: pool.ntp.org subdomains (e.g. datadog.pool.ntp.org) — standard NTP, never malicious
})

_CLOUD_PUSH_PATTERNS = (
    ".push.apple.com", ".cloudfront.net", ".amazonaws.com", ".amazon.com", ".a2z.com", ".amazon.dev", ".amazonalexa.com",
    ".firetvcaptiveportal.com", "mmechocaptiveportal.com", ".amazon-adsystem.com", ".media-amazon.com", ".akadns.net",
    ".google-analytics.com", ".googleapis.com", ".gstatic.com", ".google.com", ".gvt1.com", ".gvt2.com",
    ".azure.com", ".trafficmanager.net", ".microsoft.com", ".windows.com", ".msftncsi.com", ".live.com",
    ".quickconnect.to", ".synology.me", ".synology.com", ".sentry.io", ".spotify.com", ".roku.com"
)

# Operator-editable ADDITION to _SYSTEM_SAFE_BASE_DOMAINS above, populated from
# config.yaml's `safe_cdn_base_domains` (see core/pipeline.py's _on_config_reload) --
# for the residual case a niche single-vendor domain (e.g. samsungcloudsolution.net)
# is neither popular enough for Tranco nor hosted on infrastructure a recognized
# cloud/CDN ASN-org match would catch (is_cloud_cdn_provider_org() above), so it needs
# a manual entry -- but that entry now lives in config.yaml, hot-reloads with every
# other [LIVE] config key, and never requires a code change/deploy to add one. This is
# additive only, on top of every hardcoded set above -- never replaces them.
_CONFIG_SAFE_CDN_BASE_DOMAINS: set = set()

def register_safe_cdn_base_domains(domains) -> None:
    """Replaces the config-supplied CDN/vendor base-domain set wholesale (not additive
    across calls -- each call reflects the CURRENT config.yaml `safe_cdn_base_domains`
    list in full, so a removed entry actually stops being trusted on the next reload)."""
    global _CONFIG_SAFE_CDN_BASE_DOMAINS
    _CONFIG_SAFE_CDN_BASE_DOMAINS = {str(d).lower().strip().strip(".") for d in (domains or []) if str(d).strip()}

def _is_cdn_or_cloud_domain(domain: str) -> bool:
    """True if domain or its eTLD+1 base domain is a known safe CDN/Cloud/Vendor infrastructure."""
    norm = domain.lower().strip(".")
    if _is_cdn_domain(norm):
        return True
    if any(norm.endswith(pat) for pat in _CLOUD_PUSH_PATTERNS):
        return True
    base = etld1(norm)
    if base in _SYSTEM_SAFE_BASE_DOMAINS:
        return True
    return base in _CONFIG_SAFE_CDN_BASE_DOMAINS

# PHASE 21C2: recognized commercial VPN provider ASN organization-name substrings.
# Used by dns_evasion.py's blind-spot audit to avoid flagging legitimate VPN traffic as
# an unexplained connection -- the exact false-positive case found live this session
# (an iPhone running NordVPN showed real traffic to an IP with no matching DNS history,
# which without this check would look identical to a device deliberately evading DNS).
# Matched case-insensitively as a substring against GeoIP ASN org names, deliberately
# NOT a CIDR/IP-range list -- published VPN IP ranges change too often to hand-maintain,
# while an ASN org name is far more stable and refreshes automatically with MaxMind's
# own database updates.
_VPN_PROVIDER_ORG_KEYWORDS = frozenset({
    "nordvpn", "nord vpn", "expressvpn", "express vpn", "mullvad", "surfshark",
    "protonvpn", "proton vpn", "private internet access", "cyberghost",
    "windscribe", "ivpn", "torguard", "privatevpn", "purevpn", "hidemyass",
    "hotspot shield", "tunnelbear", "vyprvpn", "perfect privacy",
})

def is_vpn_provider_org(org_name: str) -> bool:
    """True if a GeoIP ASN organization name matches a known commercial VPN provider.
    Deliberately name-based, not IP/CIDR-based -- see the constant's comment above."""
    if not org_name:
        return False
    norm = org_name.lower()
    return any(kw in norm for kw in _VPN_PROVIDER_ORG_KEYWORDS)

# BUGFIX (live audit): _SYSTEM_SAFE_BASE_DOMAINS/_CDN_PARENT_ALLOWLIST above kept
# needing one-off patches every time a legitimate vendor domain string wasn't already
# enumerated (nflximg.com, samsungqbe.com, samsungcloudsolution.net -- each found only
# after it had already false-positived live). Most of those domains aren't hosted on
# the vendor's OWN infrastructure at all -- they're sitting on AWS/Azure/GCP/a major
# CDN, the same way countless other legitimate services are. Matching the ASN
# ORGANIZATION that actually owns the IP (same name-based-not-CIDR-based reasoning as
# is_vpn_provider_org() above, MaxMind's DB refreshes this automatically) catches any
# such domain the FIRST time it's seen, popular or not, without ever needing its exact
# domain string enumerated anywhere. Deliberately a short, recognizable list of major
# cloud/CDN operators -- not a blanket "any registered business" match, which would
# create a real blind spot for C2 hosted on the same infrastructure.
_CLOUD_CDN_ORG_KEYWORDS = frozenset({
    "akamai", "fastly", "cloudflare", "amazon.com", "amazon technologies",
    "aws", "google llc", "google cloud", "microsoft corporation", "microsoft azure",
    "netflix", "digitalocean", "ovh", "hetzner", "oracle corporation", "alibaba",
    "tencent", "fly.io", "linode", "akamai technologies",
    # BUGFIX (2026-08-29, live retro-hunter audit): this method's own docstring/callers
    # already claimed Apple-owned IPs were covered (fp_engine.py's
    # _is_ip_protected_from_confirmed_intel comment), but "apple" was never actually in
    # this list -- confirmed live: 17.57.146.55/17.57.146.59 (Apple Push Notification
    # infrastructure, touched by every iPhone/Apple Watch on the network) had been
    # recorded "confirmed malicious" and cascaded sensitivity-tightening to every other
    # device sharing them. Facebook/Meta CDN IPs (e.g. 157.240.223.61) found poisoned
    # the same audit, same fix.
    "apple inc", "facebook", "meta platforms",
    # Broadened 2026-08-29 alongside the canary regression test (test_phase45) that
    # checks this list against real IPs for the top providers by prevalence -- a few
    # more commonly-seen operators not yet covered, same reasoning as every entry above.
    # "constant company" is Vultr's CURRENT legal ASN-org name (verified live against
    # the real GeoLite2-ASN.mmdb: AS20473 "The Constant Company, LLC" across multiple
    # Vultr ranges) -- "vultr"/"choopa" kept too as a safety net for any RIR record
    # still carrying the pre-rebrand name, but neither actually matched real traffic
    # when checked.
    "ibm cloud", "softlayer", "vultr", "choopa", "constant company", "leaseweb",
    "scaleway", "contabo",
})

def is_cloud_cdn_provider_org(org_name: str) -> bool:
    """True if a GeoIP ASN organization name matches a known major cloud/CDN operator.
    Deliberately name-based, not IP/CIDR-based -- same reasoning as
    is_vpn_provider_org() above, just for "this destination is on recognized cloud/CDN
    infrastructure" instead of "this destination is a VPN exit node"."""
    if not org_name:
        return False
    norm = org_name.lower()
    return any(kw in norm for kw in _CLOUD_CDN_ORG_KEYWORDS)

# Deliberately a short, stable, name-brand list -- these IPs are as close to
# universally-recognized internet infrastructure as exists, unlike a general "trust
# this cloud provider" list that would create a real blind spot for C2 hosted on the
# same infrastructure. Originally lived only in dns_evasion.py (a device's own DNS
# QUERY traffic to a well-known public resolver, e.g. a Chromecast querying 8.8.8.8
# directly, was guaranteed to be flagged as "unexplained" -- the connection itself IS
# how domain resolution happens, so no domain lookup can ever explain it). Shared here
# so fp_engine.py's confirmed-intel write/read guards can protect the exact same IPs --
# found live: 8.8.8.8 itself had 64 "confirmed malicious" recordings in production,
# from devices whose OWN direct-resolver traffic (the same DNS_POLICY_BYPASS shape)
# kept re-confirming Google's public resolver as attacker infrastructure.
KNOWN_PUBLIC_DNS_RESOLVERS = frozenset({
    "8.8.8.8", "8.8.4.4",              # Google Public DNS
    "1.1.1.1", "1.0.0.1",              # Cloudflare
    "9.9.9.9", "149.112.112.112",      # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "94.140.14.14", "94.140.15.15",    # AdGuard DNS
    "2001:4860:4860::8888", "2001:4860:4860::8844",  # Google Public DNS, IPv6
    "2606:4700:4700::1111", "2606:4700:4700::1001",  # Cloudflare, IPv6
})

def suspicious_dga(domain):
    """
    Heuristic DGA (Domain Generation Algorithm) detector.
    Evaluates entropy, digit ratios, and consonant cluster improbability.
    Bypasses CDNs, Cloud infrastructure, reverse DNS (.arpa), and local domains (.local, .lan).
    """
    if not domain:
        return False
    norm = normalize_domain(domain)
    
    # Bypass DGA logic for local discovery networks, CDNs, and Cloud infrastructure
    if norm.endswith(".arpa") or norm.endswith(".local") or norm.endswith(".lan") or _is_cdn_or_cloud_domain(norm):
        return False
        
    left = norm.split(".", 1)[0]
    n = len(left)
    
    if 6 <= n <= 11:
        vr = vowel_ratio(left)
        ent = entropy(left)
        digits = sum(1 for c in left if c.isdigit())
        # Catch zero/very-low vowel DGAs or heavy digit-mixed strings without flagging brand names (e.g., samsungtv)
        if (vr <= 0.12 and ent > 2.6 and digits / n < 0.40) or (digits / n >= 0.45 and ent > 3.0):
            return True
        return False
        
    if n < 12:
        return False
        
    ent = entropy(left)
    vr = vowel_ratio(left)
    digits = sum(1 for c in left if c.isdigit())
    dr = digits / n
    
    return ent > 3.2 and vr < 0.25 and dr < 0.75

def infer_device_type(hostname: str, user_agent: str = "", mac_vendor: str = "") -> str:
    """
    Multi-heuristic device classification combining hostname keywords, User-Agent patterns,
    and MAC vendor OUIs to reduce 'unknown' classifications to an absolute minimum.
    """
    h = (hostname or "").lower()
    ua = (user_agent or "").lower()
    mv = (mac_vendor or "").lower()
    
    # 1. Hostname-based classification
    patterns = {
        # Specific Entertainment Overrides
        "samsungtv": "smart_tv", "samsungsmartmonitor": "smart_tv", "smartmonitor": "smart_tv",
        "androidtv": "smart_tv", "android-4": "smart_tv", "firetv": "smart_tv", "appletv": "smart_tv", 
        "bravia": "smart_tv", "lgwebos": "smart_tv", "roku": "smart_tv", "chromecast": "smart_tv", 
        "shield": "smart_tv", "amazon": "smart_tv", "tv": "smart_tv",
        "nintendo_switch": "gaming_console", "switch": "gaming_console",
        
        # Mobile & Portable Workstations
        "iphone": "phone", "android": "phone", "pixel": "phone", "samsung": "phone", "galaxy": "phone", "mobile": "phone", "note": "phone", "xiaomi": "phone", "redmi": "phone", "oneplus": "phone",
        "ipad": "tablet", "tablet": "tablet",
        "lptp": "laptop", "laptop": "laptop", "macbook": "laptop", "thinkpad": "laptop", "dell": "laptop", "hp": "laptop", "lenovo": "laptop", "linux": "laptop", "desktop": "laptop", "pc": "laptop", "workstation": "laptop",
        
        # General Entertainment
        "monitor": "smart_tv", 
        "xbox": "gaming_console", "playstation": "gaming_console", "nintendo": "gaming_console", "ps4": "gaming_console", "ps5": "gaming_console",
        
        # Office & Storage
        "hp-print": "printer", "printer": "printer", "epson": "printer", "canon": "printer", "brother": "printer",
        "nas": "nas", "synology": "nas", "qnap": "nas", "unraid": "nas", "truenas": "nas",
        
        # Security Cameras
        "camera": "camera", "ring": "camera", "arlo": "camera", "wyze": "camera", "reolink": "camera", "eufy": "camera", "hikvision": "camera", "dahua": "camera", "amcrest": "camera",
        
        # Automated Smart Home IoT & Controllers
        "echo": "iot", "alexa": "iot", "nest": "iot", "thermostat": "iot", "bulb": "iot", "plug": "iot", "wall_switch": "iot", "smart_switch": "iot",
        "espressif": "iot", "esp32": "iot", "esp8266": "iot", "tuya": "iot", "shelly": "iot", "sonoff": "iot", "tasmota": "iot",
        "tplink": "iot", "kasa": "iot", "nanoleaf": "iot", "hue": "iot", "broadlink": "iot", "wemo": "iot",
        "zigbee": "iot", "zwave": "iot", "homeassistant": "iot", "hass": "iot", "homebridge": "iot", "matter": "iot",
        
        # Network Infrastructure
        "pihole": "dns_server", "adguard": "dns_server", "unbound": "dns_server",
        "router": "router", "fritz": "router", "pfsense": "router", "opnsense": "router", "unifi": "router", "openwrt": "router", "udm": "router", "mikrotik": "router",
        "gateway": "gateway", "modem": "gateway", "firewall": "gateway"
    }
    
    for key, dtype in patterns.items():
        if key in h:
            return dtype

    # 2. User-Agent heuristic fallback
    if ua:
        if "iphone" in ua or "android" in ua and "mobile" in ua:
            return "phone"
        if "ipad" in ua or "android" in ua and "tablet" in ua:
            return "tablet"
        if "macintosh" in ua or "windows nt" in ua or "x11; linux" in ua:
            return "laptop"
        if "tizen" in ua or "webos" in ua or "roku" in ua or "googletv" in ua:
            return "smart_tv"
        if "esp32" in ua or "espressif" in ua or "tuya" in ua:
            return "iot"

    # 3. MAC Vendor OUI fallback
    if mv:
        if "apple" in mv or "samsung" in mv or "google" in mv or "xiaomi" in mv:
            return "phone"
        if "espressif" in mv or "tuya" in mv or "shenzhen" in mv or "tp-link" in mv:
            return "iot"
        if "synology" in mv or "qnap" in mv:
            return "nas"
        if "epson" in mv or "canon" in mv or "brother" in mv:
            return "printer"

    # 4. Weak string heuristic: only trust this when the hostname actually said something
    if "pc" in h or "mac" in h or "win" in h or "box" in h:
        return "laptop"

    # BUGFIX (2026-08-29, live-audit): this used to default to "laptop" unconditionally
    # -- confirmed on production state: 13 of 36 devices were typed "laptop", and 12 of
    # those 13 (92%) actually had hostname="unknown", i.e. NO real signal was ever
    # found by any layer above. "laptop" was silently functioning as "unclassified,"
    # not a real detection, and this has real behavioral effect (not just cosmetic) --
    # fp_engine.py's dev_type_weights dict already defines an "unknown": 0.3 entry that
    # was never reachable before this fix, because this function never returned
    # "unknown"; misclassified devices instead got laptop's 0.5 weight. Returning
    # "unknown" here activates that already-intended bucket instead of inventing a new
    # category -- device_matching.py/identity.py's _GENERIC_HOSTNAMES sets already
    # treat "unknown" as a recognized value too.
    return "unknown"