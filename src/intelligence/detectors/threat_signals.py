"""
threat_signals.py - PHASE 1: Evidence detector for the scoring.py-derived signal
categories that previously had no path into the live hypothesis/evidence pipeline at all.

scoring.py computed DGA/algorithmic-domain bursts, real DNS tunneling signals (TXT/NULL
abuse, long labels, suspicious TLDs), exfiltration byte bursts, C2 beaconing periodicity,
and TCP connection-abuse/port-scan patterns — but scoring.py is dead code, never imported
by the live pipeline (confirmed via `grep -rn "RiskScorer" src/ tests/`). The live risk
path only ever went through DecisionEngine + HypothesisEngine, which only ever saw
dns_rate / dns_entropy / dns_unique_ratio / malicious_ja3 / malicious_ja4 / zeek_notice
evidence. Every one of those richer signal categories was being computed every cycle
(dns_extractor.compute() and zeek_fx.get_features() already produce all the raw numbers
below) and then silently discarded.

This detector reads that same already-computed `features` dict — no new feature
extraction, no new I/O — and turns each category into Evidence objects so the new
Phase 1 Hypothesis subclasses (DGAHypothesis, ExfiltrationHypothesis, BeaconingHypothesis,
DNSTunnelingV2Hypothesis, ConnectionAbuseHypothesis) in hypotheses/engine.py can actually
see them.
"""
import ipaddress
import time
from typing import Any, Dict, List, Optional

from intelligence.hypotheses.evidence import Evidence
from utils import is_telemetry_domain, _is_cdn_or_cloud_domain

# Same small curated list scoring.py used for "this outbound burst is probably a
# legitimate cloud-vendor sync, not exfiltration" — kept narrow and explicit rather than
# reusing the much broader general CDN allowlist, since this one specifically dampens an
# exfiltration signal and a broad match here would create a real blind spot.
_VENDOR_CLOUD_API_DOMAINS = (
    "coinbase.com", "microsoft.com", "apple.com", "amazonaws.com", "google.com",
    "azure.com", "cloudflare.com", "fritz.box", "github.com", "sentry.io",
)


def _is_local_dest(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_loopback or ip_obj.is_reserved:
            return True
        if ip_obj.version == 4 and str(ip_obj).endswith(".255"):
            return True
        return False
    except ValueError:
        return False


class ThreatSignalDetector:
    def detect(self, device: str, features: Dict[str, Any], top_domain: Optional[str] = None) -> List[Evidence]:
        ev_list: List[Evidence] = []
        now = time.time()

        top_domain = (top_domain or "").lower().strip(".")
        is_telemetry = bool(top_domain) and is_telemetry_domain(top_domain)
        is_vendor_cloud_api = bool(top_domain) and any(top_domain.endswith(d) for d in _VENDOR_CLOUD_API_DOMAINS)

        def add(etype: str, value: float, confidence: float, group: str, note: str,
                subtag: Optional[str] = None) -> None:
            # `subtag` is a STABLE category tag (e.g. "txt_null_abuse") distinct from the
            # free-text `note`, which contains cycle-to-cycle-varying numbers. Hypotheses
            # that need to count how many *distinct signal categories* fired (e.g.
            # DNSTunnelingV2Hypothesis's strong-score bonus for corroborating sub-signals)
            # must key off `subtag`, not raw provenance text — before this fix, every
            # dns_tunnel_v2 evidence item shared the exact same provenance prefix
            # ("detector:threat_signals:dns_tunnel_v2:") regardless of which of the three
            # tunneling checks fired, so the "2+ distinct categories" bonus could never
            # actually trigger (caught by test_phase1_hypotheses.py).
            tag = subtag or etype
            ev_list.append(Evidence(
                type=etype, source="threat_signals", timestamp=now, device=device,
                value=value, confidence=max(0.0, min(1.0, confidence)),
                independence_group=group, provenance=f"detector:threat_signals:{etype}:{tag}:{note}",
            ))

        # ── DGA / algorithmic-domain burst ──────────────────────────────────────────
        if not is_telemetry:
            sd = float(features.get("suspicious_domains", 0.0) or 0.0)
            entropy_avg = float(features.get("entropy_avg", 0.0) or 0.0)
            dga_score = float(features.get("dga_score", 0.0) or 0.0)
            if sd >= 15:
                add("dns_dga_burst", sd, min(1.0, 0.6 + sd / 50.0), "dns_behavior",
                    f"absolute burst {int(sd)} domains")
            elif sd >= 5 and entropy_avg > 3.5:
                add("dns_dga_burst", sd, 0.6, "dns_behavior",
                    f"elevated {int(sd)} domains entropy={entropy_avg:.2f}")
            elif dga_score > 0.40:
                add("dns_dga_burst", dga_score, min(1.0, dga_score), "dns_behavior",
                    f"classifier score {dga_score:.2f}")

        # ── Real DNS tunneling signals (distinct from the existing rate/entropy-based
        #    "DNS_TUNNELING" hypothesis, which is really a burst detector) ────────────
        if not is_telemetry:
            max_label = float(features.get("max_label_length", 0.0) or 0.0)
            tunnel_domains = float(features.get("dns_tunneling_domains", 0.0) or 0.0)
            txt_null_ratio = float(features.get("dns_txt_null_ratio", 0.0) or 0.0)
            susp_tld_ratio = float(features.get("suspicious_tld_ratio", 0.0) or 0.0)

            if (tunnel_domains >= 2 or max_label > 55) and not (top_domain and _is_cdn_or_cloud_domain(top_domain)):
                add("dns_tunnel_v2", max_label, min(1.0, 0.5 + tunnel_domains * 0.15), "dns_tunnel_v2",
                    f"encoded/long labels max={int(max_label)} count={int(tunnel_domains)}",
                    subtag="encoded_labels")
            if txt_null_ratio > 0.15:
                add("dns_tunnel_v2", txt_null_ratio, min(1.0, txt_null_ratio * 2.0), "dns_tunnel_v2",
                    f"txt/null ratio {txt_null_ratio:.2f}", subtag="txt_null_abuse")
            if susp_tld_ratio > 0.15:
                add("dns_tunnel_v2", susp_tld_ratio, min(1.0, susp_tld_ratio * 2.0), "dns_tunnel_v2",
                    f"suspicious tld ratio {susp_tld_ratio:.2f}", subtag="suspicious_tld")

        # ── Exfiltration byte bursts ─────────────────────────────────────────────────
        outbound_z = float(features.get("outbound_bytes_z", 0.0) or 0.0)
        outbound_bytes = float(features.get("zeek_outbound_bytes", 0.0) or 0.0)
        if outbound_z > 5.0 and outbound_bytes > 2500000 and not is_vendor_cloud_api:
            add("zeek_exfiltration", outbound_z, 0.9, "zeek_network",
                f"massive burst Z={outbound_z:.2f} bytes={int(outbound_bytes)}")
        elif outbound_z > 3.5 and outbound_bytes > 250000 and not is_telemetry:
            conf = 0.35 if is_vendor_cloud_api else 0.6
            add("zeek_exfiltration", outbound_z, conf, "zeek_network",
                f"elevated Z={outbound_z:.2f} bytes={int(outbound_bytes)}")
        elif outbound_bytes > 50000000 and not is_telemetry and not is_vendor_cloud_api:
            add("zeek_exfiltration", outbound_bytes, 0.55, "zeek_network",
                f"absolute volume bytes={int(outbound_bytes)}")

        # ── C2 beaconing periodicity ──────────────────────────────────────────────────
        beacon_c2_1h = float(features.get("beaconing_c2_1h", 0.0) or 0.0)
        beacon_tdr = float(features.get("beacon_tdr", 0.0) or 0.0)
        beacon_total = float(features.get("beacon_total", 0.0) or 0.0)
        c2_jitter = float(features.get("beaconing_c2_count", 0.0) or 0.0)
        last_dest_ip = str(features.get("last_dest_ip", "unknown") or "unknown")

        if beacon_c2_1h > 0 and not is_telemetry:
            add("zeek_beaconing", beacon_c2_1h, 0.7, "zeek_network",
                f"low-and-slow c2 periodicity {int(beacon_c2_1h)} sequences")
        elif beacon_tdr > 0.75 and beacon_total >= 15:
            conf = min(1.0, beacon_tdr) * (0.1 if is_telemetry else 1.0)
            if conf > 0:
                add("zeek_beaconing", beacon_tdr, conf, "zeek_network",
                    f"persistent single-target beaconing tdr={beacon_tdr:.2f} total={int(beacon_total)}")
        elif c2_jitter > 0 and not is_telemetry and not _is_local_dest(last_dest_ip):
            conf = 0.3 if outbound_bytes == 0 else 0.55
            add("zeek_beaconing", c2_jitter, conf, "zeek_network",
                f"uniform check-in jitter {int(c2_jitter)} hits")

        # ── TCP connection abuse / port scan ─────────────────────────────────────────
        s0_rej = float(features.get("zeek_s0_rej_count", 0.0) or 0.0)
        s0_rej_unique = float(features.get("zeek_s0_rej_unique_ips", 0.0) or 0.0)
        if s0_rej > 25 and s0_rej_unique > 5:
            conf = 0.9 if s0_rej_unique > 15 else 0.6
            add("zeek_conn_abuse", s0_rej, conf, "zeek_network",
                f"rejected connections {int(s0_rej)} across {int(s0_rej_unique)} unique IPs")

        # ── Long-lived / covert-tunnel connections ───────────────────────────────────
        max_dur = float(features.get("zeek_max_duration", 0.0) or 0.0)
        if max_dur > 43200:
            add("zeek_long_conn", max_dur, 0.85, "zeek_network", f"extreme duration {int(max_dur)}s")
        elif max_dur > 14400:
            add("zeek_long_conn", max_dur, 0.5, "zeek_network", f"long duration {int(max_dur)}s")

        return ev_list
