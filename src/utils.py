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
import hashlib
import socket
import ipaddress
import logging
import functools

try:
    import tldextract
except ImportError:
    tldextract = None

LOGGER = logging.getLogger("home_ids.utils")

def normalize_domain(domain):
    """Lowercases and cleans up trailing dots from raw DNS queries."""
    return str(domain).lower().strip(".")

def safe_label(label):
    """Hashes labels that are too long or weird into safe representations."""
    return hashlib.sha1(str(label).encode()).hexdigest()[:8]

def sanitize_hostname(host):
    """Prevents invalid characters in Prometheus labels and dashboard variables."""
    if not host:
        return "unknown"
    return host.lower().replace(".", "_").replace("-", "_")[:40]

def etld1(domain):
    """Extracts the base domain and suffix (e.g., mail.google.com -> google.com)."""
    if not domain:
        return ""
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
    "samsungcloud.com", "samsungcloud.net", "samsungrm.net", "samsungdm.com", "samsung.com",
    "gvt1.com", "gvt2.com", "gvt3.com", "crashlytics.com", "app-measurement.com", "firebaseio.com",
    "icloud.com", "apple-dns.net", "push.apple.com", "googleapis.com", "android.clients.google.com",
    "appsflyersdk.com", "amplitude.com", "moengage.com", "iterable.com", "mwbsys.com"
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
    
    # Google & Android Ecosystem
    "google.com", "googleapis.com", "gstatic.com", "googlevideo.com",
    "googleusercontent.com", "googlesyndication.com", "google-analytics.com",
    "gvt1.com", "gvt2.com", "gvt3.com", "android.com", "ggpht.com",
    "doubleclick.net", "youtube.com", "ytimg.com", "1e100.net", "fastly-edge.com",
    
    # Apple & iOS/macOS Ecosystem
    "apple.com", "icloud.com", "icloud-content.com", "cdn-apple.com",
    "mzstatic.com", "aaplimg.com", "apple-dns.net", "push.apple.com",
    
    # Microsoft, Sentry & Developer/Security Ecosystem
    "microsoft.com", "windows.com", "azure.com", "live.com", "office.com",
    "msn.com", "office365.com", "msftncsi.com", "skype.com", "sentry.io",
    "brave.com", "wordnik.com", "napps-2.com", "bitdefender.net", "bitdefender.com",
    "trafficmanager.net", "azureedge.net", "msecnd.net", "windowsupdate.com",
    
    # Smart Home, Synology, IoT & Streaming Platforms
    "quickconnect.to", "synology.me", "synology.com", "samsungcloud.com",
    "samsung.com", "samsungcloud.net", "samsungrm.net", "samsungdm.com", "lgsmartad.com",
    "lgthing.com", "roku.com", "netflix.com", "nflxvideo.net", "nflxso.net",
    "nflxext.com", "spotify.com", "scdn.co", "spotifycdn.com", "plex.tv",
    "sonos.com", "tplinkcloud.com", "tuya.com", "tuyacn.com", "myq-cloud.com",
    
    # Global CDNs & Security Ingestion
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com", "fastly.net", "fastlylb.net", "fastly-edge.com",
    "akamaized.net", "akamai.net", "akamaihd.net", "akamaiedge.net",
    "appsflyersdk.com", "amplitude.com", "moengage.com", "iterable.com", "mwbsys.com",
    "akadns.net", "edgesuite.net", "edgekey.net", "brave.com", "nordvpn.com",
    "bitdefender.net", "bitdefender.com", "fritz.box"
})

_CLOUD_PUSH_PATTERNS = (
    ".push.apple.com", ".cloudfront.net", ".amazonaws.com", ".amazon.com", ".a2z.com", ".amazon.dev", ".amazonalexa.com",
    ".firetvcaptiveportal.com", "mmechocaptiveportal.com", ".amazon-adsystem.com", ".media-amazon.com", ".akadns.net",
    ".google-analytics.com", ".googleapis.com", ".gstatic.com", ".google.com", ".gvt1.com", ".gvt2.com",
    ".azure.com", ".trafficmanager.net", ".microsoft.com", ".windows.com", ".msftncsi.com", ".live.com",
    ".quickconnect.to", ".synology.me", ".synology.com", ".sentry.io", ".spotify.com", ".roku.com"
)

def _is_cdn_or_cloud_domain(domain: str) -> bool:
    """True if domain or its eTLD+1 base domain is a known safe CDN/Cloud/Vendor infrastructure."""
    norm = domain.lower().strip(".")
    if _is_cdn_domain(norm):
        return True
    if any(norm.endswith(pat) for pat in _CLOUD_PUSH_PATTERNS):
        return True
    base = etld1(norm)
    return base in _SYSTEM_SAFE_BASE_DOMAINS

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

@functools.lru_cache(maxsize=10000)
def resolve_domain(domain):
    """Attempts to do a physical socket check on a domain to find its true endpoint[cite: 3]."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(1.0)
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            ip = info[4][0]
            parsed = ipaddress.ip_address(ip)
            if not parsed.is_private and not parsed.is_loopback and not parsed.is_multicast and not parsed.is_link_local:
                return ip
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_timeout)
    return None

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

    # 4. Defaults: If IP ends up unclassified, default to laptop/phone based on basic string heuristics
    if "pc" in h or "mac" in h or "win" in h or "box" in h:
        return "laptop"

    return "laptop"  # Default fallback to laptop profile instead of raw 'unknown'