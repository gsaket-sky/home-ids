#!/usr/bin/env python3
"""
threat_simulator.py -- Home-IDS detection self-test tool.

Run this FROM A DIFFERENT DEVICE on the same LAN as your Home-IDS deployment
(a spare laptop, a Raspberry Pi, an Android phone via Termux -- anything that
can run Python 3.8+). It generates REAL network traffic shaped like each
detector's actual trigger condition, so what fires in Grafana/Telegram/
alerts.json is genuinely earned by the running pipeline -- this never talks to
the IDS process directly or injects fake evidence.

STDLIB ONLY (socket, struct, random, time, argparse) -- runs unmodified on
Windows, Linux, and Android/Termux. The one optional scenario that needs
`scapy` (arp_spoof) degrades to a clear "not available" message if it's
missing, which is expected on most Android/Termux setups without root.

Quick start:
    python3 threat_simulator.py --list                     # see every scenario
    python3 threat_simulator.py --scenario arp_sweep        # run one
    python3 threat_simulator.py --all                       # run every SAFE scenario
    python3 threat_simulator.py --escalation-loop dns_evasion --duration 900

Every scenario prints what it actually sent, what evidence type it should
trigger, which Grafana panel to watch, and what you should see in
state/scheduler.log / state/alerts.json / Telegram.

SAFETY: default scenarios only touch YOUR OWN outbound traffic and read-only
probes against LAN IPs you specify. The one exception (arp_spoof) can
genuinely disrupt a real device's connectivity for a few seconds if pointed
at a real device instead of a spare/unused IP -- it is excluded from --all,
requires scapy, requires --target-decoy-ip explicitly, and requires
--confirm-arp-spoof-test. Read its scenario description before using it.
"""
import argparse
import ipaddress
import random
import socket
import string
import struct
import sys
import time

try:
    from scapy.all import ARP, Ether, sendp, conf as scapy_conf  # noqa
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# ============================================================================
# Small shared helpers
# ============================================================================

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def random_dga_label(min_len=8, max_len=15):
    """Consonant-heavy, low-vowel string -- matches utils.py's suspicious_dga()
    heuristic (vowel_ratio <= 0.12, entropy > 2.6) closely enough to trigger it."""
    consonants = "bcdfghjklmnpqrstvwxyz"
    vowels = "aeiou"
    n = random.randint(min_len, max_len)
    out = []
    for i in range(n):
        # ~1-in-9 vowel chance keeps vowel_ratio well under the 0.12 bar
        out.append(random.choice(vowels) if random.random() < 0.08 else random.choice(consonants))
    return "".join(out)


def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Minimal, dependency-free DNS query packet builder (A record by default).
    No dnspython/scapy needed -- this is just RFC 1035 header + one question."""
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(
        bytes([len(part)]) + part.encode("ascii", errors="ignore")
        for part in domain.strip(".").split(".")
    ) + b"\x00"
    question = qname + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def send_raw_dns_query(domain: str, resolver_ip: str, resolver_port: int = 53, timeout: float = 2.0):
    """Sends ONE raw UDP DNS query directly to `resolver_ip` -- bypasses
    whatever DNS server this OS/network is actually configured to use. This is
    the literal shape dns_evasion.py's DNS_POLICY_BYPASS check looks for: a
    direct port-53 connection to a non-Pi-hole resolver."""
    pkt = build_dns_query(domain)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(pkt, (resolver_ip, resolver_port))
        try:
            s.recvfrom(512)
        except socket.timeout:
            pass  # fine -- we only need the query to be SENT and observed on the wire


def normal_dns_lookup(domain: str, timeout: float = 2.0):
    """Uses the OS's own configured resolver (should be your Pi-hole) --
    the "normal" baseline every scenario's setup/teardown uses so this
    simulator's OWN startup doesn't itself look evasive."""
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(domain)
    except Exception:
        pass


def tcp_touch(ip: str, port: int, timeout: float = 1.5):
    """One TCP connect attempt -- succeeds, refuses, or times out, all three
    are fine (Zeek logs the attempt regardless of outcome; a refusal/timeout is
    exactly what feeds zeek_s0_rej_count)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect_ex((ip, port))
    except Exception:
        pass
    finally:
        s.close()


def udp_burst(ip: str, port: int, total_bytes: int, chunk_size: int = 60000):
    """Fire-and-forget UDP burst -- generates real outbound byte volume at the
    network layer without needing anything to actually receive/process it.
    Point this at your OWN router/gateway IP (default) so nothing leaves your
    LAN and nothing is "exfiltrated" anywhere real; Zeek still sees the bytes
    leave THIS device, which is all zeek_exfiltration's z-score check looks at."""
    payload_chunk = bytes(random.getrandbits(8) for _ in range(min(chunk_size, 1400)))
    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while sent < total_bytes:
            s.sendto(payload_chunk, (ip, port))
            sent += len(payload_chunk)
    return sent


def local_subnet_ips(base_ip: str, count: int, start_host: int = 2):
    """Generates `count` sequential host IPs in the same /24 as base_ip,
    skipping base_ip itself. Good enough for a home /24 -- if your LAN uses a
    different mask, pass --targets explicitly instead."""
    parts = base_ip.split(".")
    prefix = ".".join(parts[:3])
    out = []
    h = start_host
    while len(out) < count and h < 255:
        candidate = f"{prefix}.{h}"
        if candidate != base_ip:
            out.append(candidate)
        h += 1
    return out


def get_own_ip(gateway_hint: str = None) -> str:
    """Best-effort local IP discovery -- opens a UDP socket toward a public IP
    (no packet is actually sent for UDP connect()) purely to ask the OS which
    local interface/IP would be used, which works identically on Windows,
    Linux, and Termux without any extra permissions."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((gateway_hint or "8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def guess_gateway(own_ip: str) -> str:
    parts = own_ip.split(".")
    return ".".join(parts[:3]) + ".1"


LATERAL_PORTS = [22, 445, 3389, 5900, 23]


# ============================================================================
# Scenario registry -- each entry is (fn, metadata) where metadata documents
# exactly what to watch for. `--list` and `--doc <name>` both read this.
# ============================================================================

SCENARIOS = {}


def scenario(name, evidence_type, grafana_panel, expected_signature, expected_action,
             safety="safe", requires=None):
    """Decorator that registers a scenario function alongside its documentation."""
    def deco(fn):
        SCENARIOS[name] = {
            "fn": fn,
            "evidence_type": evidence_type,
            "grafana_panel": grafana_panel,
            "expected_signature": expected_signature,
            "expected_action": expected_action,
            "safety": safety,
            "requires": requires or [],
            "doc": fn.__doc__ or "",
        }
        return fn
    return deco


@scenario(
    "arp_sweep",
    evidence_type="arp_sweep (independence_group=lan_recon)",
    grafana_panel="3_device_deep_dive.json -- 'ARP Sweep Count' / home_ids_zeek_arp_sweep_count",
    expected_signature="CONNECTION_ABUSE (needs a 2nd independent signal to reach HIGH -- arp_sweep alone stays SUSPICIOUS)",
    expected_action="monitoring only (SUSPICIOUS) unless another signal corroborates in the same window",
)
def sc_arp_sweep(args):
    """ARP host-discovery sweep. Touches N sequential LAN IPs quickly enough
    that the OS has to ARP-resolve each one fresh -- Zeek's arp.log sees this
    as zeek_arp_sweep_count. Default threshold is 8 distinct targets within one
    300s window; this sends 20 to clear it with margin."""
    own_ip = get_own_ip(args.gateway)
    targets = local_subnet_ips(own_ip, args.count, start_host=2)
    log(f"Own IP: {own_ip}. Sweeping {len(targets)} LAN targets: {targets[0]}..{targets[-1]}")
    for ip in targets:
        tcp_touch(ip, 62222, timeout=0.3)  # unlikely-open port; connect attempt is what forces ARP
    log(f"Sent connection attempts to {len(targets)} distinct hosts. "
        f"Check: state/scheduler.log or Grafana for zeek_arp_sweep_count >= 8 on this device.")


@scenario(
    "conn_abuse",
    evidence_type="zeek_conn_abuse (independence_group=zeek_network)",
    grafana_panel="3_device_deep_dive.json -- 'S0/Rejected Connections' panel",
    expected_signature="CONNECTION_ABUSE",
    expected_action="monitoring only (SUSPICIOUS) or awaiting approval (HIGH) if corroborated",
)
def sc_conn_abuse(args):
    """Repeated rejected/no-reply TCP connections against a SMALL set of LAN
    IPs -- the v12 fix specifically requires s0_rej_unique_ips > learned
    threshold (default 5) AND total attempts > 25. Hits 6 targets, ~20 attempts
    each = 120 total, well over both bars."""
    own_ip = get_own_ip(args.gateway)
    targets = local_subnet_ips(own_ip, 6, start_host=10)
    log(f"Hammering {len(targets)} LAN targets on an unlikely-open port, ~20x each...")
    for _ in range(20):
        for ip in targets:
            tcp_touch(ip, 59999, timeout=0.3)
    log(f"Sent ~120 connection attempts across {len(targets)} unique IPs. "
        f"Check: zeek_s0_rej_count and zeek_s0_rej_unique_ips for this device.")


@scenario(
    "dga_burst",
    evidence_type="dns_dga_burst (independence_group=dns_behavior)",
    grafana_panel="2_threat_landscape.json -- 'DGA/Suspicious Domains' panel",
    expected_signature="DGA_BOTNET_C2",
    expected_action="awaiting approval (HIGH) if this device has no interactive-blocking override",
)
def sc_dga_burst(args):
    """Bursts of consonant-heavy, high-entropy, low-vowel domain names --
    matches utils.py's suspicious_dga() heuristic. Sends 18 lookups (threshold
    is 15) under a fake TLD via your OWN configured resolver (normal DNS path,
    NOT a policy bypass) -- these will mostly NXDOMAIN, which is expected and
    harmless."""
    log("Querying 18 DGA-shaped fake domains via your normal DNS resolver...")
    for _ in range(18):
        domain = f"{random_dga_label()}.example-test-dga.invalid"
        normal_dns_lookup(domain, timeout=1.0)
    log("Sent 18 DGA-shaped lookups. Check: home_ids_suspicious_domains for this device.")


@scenario(
    "dns_tunneling",
    evidence_type="dns_tunnel_v2 (independence_group=dns_tunnel_v2)",
    grafana_panel="2_threat_landscape.json -- 'DNS Tunneling Signatures' panel",
    expected_signature="DNS_COVERT_TUNNELING",
    expected_action="awaiting approval (HIGH) if this device has no interactive-blocking override",
)
def sc_dns_tunneling(args):
    """Encoded-looking, long subdomain labels (fanout under one parent, plus
    one single label > 55 chars) -- the two dns_tunnel_v2 trigger shapes.
    Uses a domain NOT on the CDN/telemetry allowlist so the exemption doesn't
    dampen it."""
    parent = "sim-tunnel-test.invalid"
    log(f"Sending 10 encoded-label subdomains under {parent} (fanout shape)...")
    hex_chars = "0123456789abcdef"
    for _ in range(10):
        label = "".join(random.choice(hex_chars) for _ in range(20))
        normal_dns_lookup(f"{label}.{parent}", timeout=1.0)
    long_label = "".join(random.choice(hex_chars) for _ in range(60))
    log("Sending one 60-char single label (encoded_labels shape)...")
    normal_dns_lookup(f"{long_label}.{parent}", timeout=1.0)
    log(f"Sent tunneling-shaped DNS traffic. Check: home_ids_zeek_notices / dns_tunnel_v2 evidence.")


@scenario(
    "dns_evasion",
    evidence_type="dns_evasion_anomaly, subtag=no_dns_history",
    grafana_panel="4_system_health.json -- 'DNS Evasion / Blind-Spot Audit' panel",
    expected_signature="DNS_EVASION",
    expected_action="awaiting approval (HIGH) if this device has no interactive-blocking override",
    safety="safe (contacts one real public IP directly by address -- no data sent beyond a TCP handshake)",
)
def sc_dns_evasion(args):
    """Opens a raw TCP connection directly to a real public IP by its NUMERIC
    address -- never resolving it by name first. This only fires via the
    reactive-capture blind-spot audit (WiFi-visible devices), so it needs that
    subsystem enabled to show up -- see reactive_capture_* in config.yaml."""
    target_ip = args.evasion_ip or "93.184.216.34"  # example.com's long-standing IP
    log(f"Connecting directly to {target_ip}:443 with NO prior DNS lookup for it...")
    tcp_touch(target_ip, 443, timeout=2.0)
    log(f"Connected to {target_ip} with no DNS history. This only surfaces via a reactive-capture "
        f"burst -- trigger one (e.g. run arp_sweep too) or wait for the next scheduled burst.")


@scenario(
    "dns_policy_bypass",
    evidence_type="dns_evasion_anomaly, subtag=policy_bypass",
    grafana_panel="4_system_health.json -- 'DNS Policy Bypass' panel",
    expected_signature="DNS_POLICY_BYPASS",
    expected_action="auto-blocked (domain) -- unless this device is classified as infra (dns_server/router/gateway)",
)
def sc_dns_policy_bypass(args):
    """Sends a raw DNS query directly to a resolver on port 53 that is NOT
    your configured Pi-hole -- the literal shape this signature exists to
    catch. Deliberately avoids KNOWN_PUBLIC_DNS_RESOLVERS (8.8.8.8, 1.1.1.1,
    9.9.9.9, etc. -- utils.py) since those are now explicitly exempted; uses
    a less common public resolver instead so the bypass is genuinely unexplained."""
    # BUGFIX (caught reviewing this script): the obvious "well-known public resolver"
    # defaults (Google/Cloudflare/Quad9/OpenDNS/AdGuard) are ALL in
    # KNOWN_PUBLIC_DNS_RESOLVERS (utils.py) and now correctly exempted by the v12 fix --
    # using one as the default here would silently defeat the whole scenario. Verisign's
    # public resolver is real, reliable, and genuinely NOT in that exempt list.
    resolver = args.bypass_resolver or "64.6.64.6"  # Verisign Public DNS
    _exempted = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9",
                 "149.112.112.112", "208.67.222.222", "208.67.220.220",
                 "94.140.14.14", "94.140.15.15"}
    if resolver in _exempted:
        log("WARNING: that resolver is in KNOWN_PUBLIC_DNS_RESOLVERS and is now exempted -- "
            "pass --bypass-resolver with a different public DNS IP for a genuine test.")
    log(f"Sending a raw DNS query directly to {resolver}:53 (bypassing your LAN's real resolver)...")
    send_raw_dns_query("policy-bypass-test.invalid", resolver)
    log(f"Sent. This is exactly what your own paperless/unbound box does for LEGITIMATE recursive "
        f"resolution -- if THIS device is classified dns_server/router/gateway via device_type_overrides, "
        f"it should now be dampened (v12 fix). Run this from an ordinary client device to see it fire.")


@scenario(
    "data_exfiltration",
    evidence_type="zeek_exfiltration (independence_group=zeek_network)",
    grafana_panel="3_device_deep_dive.json -- 'Outbound Bytes' panel",
    expected_signature="DATA_EXFILTRATION",
    expected_action="awaiting approval (HIGH)",
    safety="safe by default -- sends to your OWN gateway IP, nothing leaves your LAN",
)
def sc_data_exfiltration(args):
    """Fire-and-forget UDP burst of several MB. Defaults to your own gateway/
    router IP on an unused port so nothing is actually exfiltrated anywhere --
    Zeek only cares about bytes leaving THIS device, not who receives them."""
    own_ip = get_own_ip(args.gateway)
    dest = args.exfil_target or guess_gateway(own_ip)
    total = args.exfil_bytes or 8_000_000  # 8MB, clears the 2.5MB absolute floor with room for z-score too
    log(f"Sending ~{total/1_000_000:.1f}MB via UDP to {dest}:{args.exfil_port} (your own gateway by default)...")
    sent = udp_burst(dest, args.exfil_port, total)
    log(f"Sent {sent/1_000_000:.1f}MB. Check: home_ids_zeek_outbound_bytes / outbound_bytes_z for this device.")


@scenario(
    "c2_beaconing",
    evidence_type="zeek_beaconing (independence_group=zeek_network)",
    grafana_panel="2_threat_landscape.json -- 'Beaconing Detections' panel",
    expected_signature="C2_BEACONING",
    expected_action="awaiting approval (HIGH) or monitoring only (SUSPICIOUS)",
)
def sc_c2_beaconing(args):
    """Regular-interval connections to the SAME external IP over several
    minutes -- the periodicity itself is the signal, not the destination.
    Needs real wall-clock time to pass; --duration controls how long (default
    600s, matching decision_engine's own suspicious_escalation_seconds)."""
    target_ip = args.beacon_ip or "93.184.216.34"
    interval = args.beacon_interval
    duration = args.duration or 600
    log(f"Beaconing to {target_ip}:443 every {interval}s for {duration}s "
        f"({duration // interval} check-ins)...")
    end = time.time() + duration
    while time.time() < end:
        tcp_touch(target_ip, 443, timeout=2.0)
        time.sleep(interval)
    log("Beaconing sequence complete. Check: home_ids_zeek_notices / beaconing_c2_count for this device.")


@scenario(
    "lateral_movement",
    evidence_type="zeek_lateral_scan (independence_group=zeek_network)",
    grafana_panel="2_threat_landscape.json -- 'Lateral Movement' panel",
    expected_signature="NETWORK_INTRUSION",
    expected_action="awaiting approval (HIGH) if 2+ distinct targets AND corroborated",
)
def sc_lateral_movement(args):
    """Connection attempts against SSH/SMB/RDP/VNC/Telnet-shaped ports
    (config.yaml's lateral_movement_ports) on 3 distinct LAN IPs -- clears the
    default lateral_movement_unique_targets_threshold (2) with margin."""
    own_ip = get_own_ip(args.gateway)
    targets = local_subnet_ips(own_ip, 3, start_host=20)
    log(f"Touching lateral-movement ports {LATERAL_PORTS} on {len(targets)} LAN targets: {targets}")
    for ip in targets:
        for port in LATERAL_PORTS:
            tcp_touch(ip, port, timeout=0.5)
    log(f"Touched {len(LATERAL_PORTS)} ports x {len(targets)} targets. "
        f"Check: home_ids_zeek_lateral_moves / zeek_lateral_unique_targets for this device.")


@scenario(
    "honeypot_access",
    evidence_type="honeypot_access (independence_group=honeypot) -- HARD-STOP, zero corroboration needed",
    grafana_panel="1_main_overview.json -- 'Honeypot Hits' panel (should jump immediately)",
    expected_signature="Internal Honeypot Accessed",
    expected_action="router isolated / tarpitted -- CRITICAL, immediate",
    safety="safe -- this is your own decoy, touching it is exactly what it's for",
)
def sc_honeypot_access(args):
    """Single connection to your configured honeypot decoy IP
    (config.yaml's honeypot_ips). This is a HARD-STOP -- expect the fastest,
    most severe response of every scenario in this tool."""
    ip = args.honeypot_ip
    if not ip:
        log("ERROR: --honeypot-ip is required for this scenario (no safe default -- "
            "must match YOUR config.yaml's honeypot_ips exactly).")
        return
    log(f"Connecting to honeypot decoy {ip}:445 ...")
    tcp_touch(ip, 445, timeout=2.0)
    log(f"Done. This should be your FASTEST, most severe result -- CRITICAL, no corroboration required.")


@scenario(
    "arp_spoof",
    evidence_type="arp_spoofing (2nd genuine flip) -- HARD-STOP; arp_spoof_pending (1st flip) -- weak evidence",
    grafana_panel="1_main_overview.json -- 'ARP/NDP Spoofing Events' panel",
    expected_signature="Layer-2 ARP Spoofing Detected (2nd flip) / NETWORK_INTRUSION (1st flip, weak)",
    expected_action="router isolated -- CRITICAL, on the 2nd flip only (v12 fix)",
    safety="RISKY -- can disrupt a real device's connectivity if pointed at one. Requires scapy, "
           "--target-decoy-ip, and --confirm-arp-spoof-test. Excluded from --all.",
    requires=["scapy", "--target-decoy-ip", "--confirm-arp-spoof-test"],
)
def sc_arp_spoof(args):
    """Sends two gratuitous ARP replies for the SAME IP with two DIFFERENT,
    never-before-seen fake MAC addresses, ~10s apart (within the 600s
    corroboration window) -- this is the v12-fixed 2-genuine-flips escalation
    path. ONLY point this at a decoy/unused IP you specify -- never a real
    device's IP, or you will genuinely disrupt it for a few seconds."""
    if not SCAPY_AVAILABLE:
        log("scapy is not installed/available -- this scenario cannot run here "
            "(expected on most Android/Termux setups without root). Skipping.")
        return
    if not args.target_decoy_ip:
        log("ERROR: --target-decoy-ip is required -- point this at an UNUSED IP in your subnet, "
            "never a real device.")
        return
    if not args.confirm_arp_spoof_test:
        log("ERROR: pass --confirm-arp-spoof-test to acknowledge you understand this can disrupt "
            "connectivity if misdirected at a real device.")
        return
    ip = args.target_decoy_ip
    for i in range(2):
        fake_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))
        log(f"Sending gratuitous ARP #{i+1}: {ip} is-at {fake_mac} ...")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=ip, hwsrc=fake_mac)
        sendp(pkt, verbose=False)
        if i == 0:
            time.sleep(10)
    log("Sent 2 genuine MAC flips ~10s apart. Check: Layer-2 ARP Spoofing Detected, CRITICAL, immediate.")


NOT_SIMULATABLE = [
    ("malicious_ja3_ja4", "TLS ClientHello fingerprint hashes are hardcoded exact matches "
     "(zeek_features.py's _MALICIOUS_JA3/_MALICIOUS_JA4). No test client will produce one by "
     "chance. Verify via test_phase*.py's existing unit coverage instead."),
    ("geofencing", "Needs traffic that GeoIP-resolves to a real blocklisted country. Not safely "
     "simulatable without a VPN exit point in that country. Verify by temporarily adding a "
     "country you WILL actually connect to (e.g. your own) to geofencing_countries and confirming "
     "the alert fires, then revert."),
    ("confirmed_malicious_ioc", "Would mean deliberately connecting to real, currently-listed "
     "threat-intel infrastructure (Feodo/ThreatFox/URLhaus). Not something this tool will ever do. "
     "Verify via decision_engine.py's own test coverage (rep.tier==5 branch) instead."),
    ("suricata_exploit_match", "Depends entirely on YOUR specific installed ruleset -- no packet "
     "this tool crafts is guaranteed to match it. If you're running ET-OPEN, many rulesets ship a "
     "harmless self-test signature (check your ruleset's docs for one) -- point "
     "reactive_capture_suricata_rules_path at it temporarily to verify the pipeline end-to-end."),
]


# ============================================================================
# CLI
# ============================================================================

def print_list():
    print("\nSAFE scenarios (included in --all):\n")
    for name, meta in SCENARIOS.items():
        if meta["safety"].startswith("safe"):
            print(f"  {name:<20} -> {meta['expected_signature']}")
    print("\nOPT-IN scenarios (NOT included in --all, need extra flags):\n")
    for name, meta in SCENARIOS.items():
        if not meta["safety"].startswith("safe"):
            print(f"  {name:<20} -> {meta['expected_signature']}  [{meta['safety']}]")
    print("\nNOT SIMULATABLE from a test client (documented, not attempted):\n")
    for name, reason in NOT_SIMULATABLE:
        print(f"  {name:<20} -> {reason}\n")
    print("Run --doc <scenario> for full detail on any one scenario.\n")


def print_doc(name):
    meta = SCENARIOS.get(name)
    if not meta:
        print(f"Unknown scenario '{name}'. Run --list to see valid names.")
        return
    print(f"\n{name}\n{'=' * len(name)}")
    print(meta["fn"].__doc__ or "(no description)")
    print(f"\nEvidence type:        {meta['evidence_type']}")
    print(f"Expected signature:   {meta['expected_signature']}")
    print(f"Expected action:      {meta['expected_action']}")
    print(f"Grafana panel:        {meta['grafana_panel']}")
    print(f"Safety:               {meta['safety']}")
    if meta["requires"]:
        print(f"Requires:             {', '.join(meta['requires'])}")
    print()


def run_scenario(name, args):
    meta = SCENARIOS.get(name)
    if not meta:
        log(f"Unknown scenario '{name}'. Run --list to see valid names.")
        return
    log(f"=== Running scenario: {name} ===")
    log(f"Expect: {meta['expected_signature']} -> {meta['expected_action']}")
    log(f"Watch: {meta['grafana_panel']}")
    if args.dry_run:
        log("(--dry-run: not actually sending anything)")
        return
    meta["fn"](args)
    log(f"=== {name} complete ===\n")


def run_escalation_loop(name, args):
    """Repeats a scenario every poll_interval (default 2s doesn't matter here --
    what matters is total elapsed time) across suspicious_escalation_seconds
    (default 600s) so you can watch a SUSPICIOUS verdict escalate to HIGH via
    persistence alone -- and confirm the v12 fix: confidence caps at 55%
    (not 75%+) and the signature gets a "(persisted Ns)" suffix, visibly
    distinguishable from a genuinely-corroborated HIGH."""
    meta = SCENARIOS.get(name)
    if not meta:
        log(f"Unknown scenario '{name}'.")
        return
    duration = args.duration or 900
    interval = args.escalation_interval or 60
    log(f"=== Escalation-loop: repeating '{name}' every {interval}s for {duration}s ===")
    log(f"Watch for: same signature recurring in Telegram/alerts.json, growing a "
        f"'(persisted Ns)' suffix, confidence capped at 0.55 (NOT 0.75+) once escalated.")
    end = time.time() + duration
    round_num = 0
    while time.time() < end:
        round_num += 1
        log(f"-- round {round_num} --")
        if not args.dry_run:
            meta["fn"](args)
        time.sleep(interval)
    log(f"=== Escalation loop complete after {round_num} rounds ===")


def build_parser():
    p = argparse.ArgumentParser(
        description="Home-IDS detection self-test tool. Run from a DIFFERENT device on your LAN.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--list", action="store_true", help="List every scenario and exit.")
    p.add_argument("--doc", metavar="SCENARIO", help="Print full documentation for one scenario and exit.")
    p.add_argument("--scenario", metavar="NAME", help="Run one scenario.")
    p.add_argument("--all", action="store_true", help="Run every SAFE scenario in sequence.")
    p.add_argument("--escalation-loop", metavar="NAME", help="Repeat one scenario to demonstrate persistence escalation.")
    p.add_argument("--duration", type=int, default=None, help="Seconds for --escalation-loop or beaconing (default varies by scenario).")
    p.add_argument("--escalation-interval", type=int, default=60, help="Seconds between rounds in --escalation-loop (default 60).")
    p.add_argument("--dry-run", action="store_true", help="Print what would happen without sending anything.")

    p.add_argument("--gateway", default=None, help="Your router/gateway IP, e.g. 192.168.1.1 (auto-detected if omitted).")
    p.add_argument("--count", type=int, default=20, help="Target count for arp_sweep (default 20).")
    p.add_argument("--honeypot-ip", default=None, help="Your configured honeypot decoy IP (config.yaml honeypot_ips) -- required for honeypot_access.")
    p.add_argument("--evasion-ip", default=None, help="Numeric IP for dns_evasion scenario (default: a long-standing example.com IP).")
    p.add_argument("--bypass-resolver", default=None, help="Public DNS resolver IP for dns_policy_bypass (must NOT be in KNOWN_PUBLIC_DNS_RESOLVERS).")
    p.add_argument("--exfil-target", default=None, help="Target IP for data_exfiltration (default: your own gateway -- stays on your LAN).")
    p.add_argument("--exfil-port", type=int, default=59998, help="Target port for data_exfiltration (default 59998).")
    p.add_argument("--exfil-bytes", type=int, default=None, help="Bytes to send for data_exfiltration (default 8000000 = 8MB).")
    p.add_argument("--beacon-ip", default=None, help="Target IP for c2_beaconing (default: a long-standing example.com IP).")
    p.add_argument("--beacon-interval", type=int, default=20, help="Seconds between beacons (default 20).")
    p.add_argument("--target-decoy-ip", default=None, help="UNUSED IP to target for arp_spoof -- never a real device.")
    p.add_argument("--confirm-arp-spoof-test", action="store_true", help="Required acknowledgement for arp_spoof.")

    return p


def main():
    args = build_parser().parse_args()

    if args.list:
        print_list()
        return
    if args.doc:
        print_doc(args.doc)
        return
    if args.escalation_loop:
        run_escalation_loop(args.escalation_loop, args)
        return
    if args.scenario:
        run_scenario(args.scenario, args)
        return
    if args.all:
        log("Running every SAFE scenario in sequence (this will take a few minutes; "
            "c2_beaconing alone takes 10 minutes by default -- pass --duration to shorten it "
            "for a quick pass).")
        for name, meta in SCENARIOS.items():
            if meta["safety"].startswith("safe"):
                run_scenario(name, args)
                time.sleep(3)
        log("All safe scenarios complete. Opt-in (arp_spoof) and not-simulatable scenarios were "
            "skipped -- see --list for why.")
        return

    build_parser().print_help()


if __name__ == "__main__":
    main()
