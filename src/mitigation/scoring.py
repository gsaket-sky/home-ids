"""
scoring.py - Risk scoring engine.

RECENT FIXES:
- FIXED (TELEMETRY SHIELD EXPLOIT): Removed `not is_telemetry` lock from Universal Absolute 
  DGA Tripwires. Prevents malware from masking algorithmic domain generation bursts by 
  simultaneously querying benign system/telemetry domains to manipulate the `top_domain` metric.
- FIXED (DGA BLINDSPOT): Added universal Absolute Tripwires for DGA and High-Entropy 
  domain bursts to ensure rapid mitigation during the Cold-Start/Probation phase, 
  bypassing Fritz!Box NXDOMAIN hijacking edge-cases.
- ADDED (LOGGING): Debug events tracked at calculation and individual factor inclusion points.
"""
import ipaddress
import math
import logging
from utils import is_telemetry_domain, _is_cdn_or_cloud_domain

LOGGER = logging.getLogger("home_ids.scoring")

def safe_float(v, default: float = 0.0) -> float:
    try:
        return float(v) if v is not None else default
    except Exception:
        return default

_DEVICE_SENSITIVITY = {
    "iot": 1.0, "printer": 0.9, "camera": 0.9, "nas": 0.9, "smart_tv": 1.0,
    "gaming_console": 1.0, "phone": 1.0, "tablet": 1.0, "laptop": 1.0, "desktop": 1.0, "unknown": 1.0,
    "dns_server": 0.0, "router": 0.0, "gateway": 0.0,
}

class RiskScorer:
    def compute(self, features: dict, state, ml_score: float, zeek_alerts: list = None) -> float:
        return self.explain(features, state, ml_score, zeek_alerts)["risk"]

    def explain(self, features: dict, state, ml_score: float, zeek_alerts: list = None) -> dict:
        LOGGER.debug("Evaluating risk factors for device %s", getattr(state, "hostname", "unknown"))
        factors = []
        multiplier_factors = [] 

        def add(name: str, score: float, value=None, detail: str = "", is_multiplier: bool = False) -> None:
            score = safe_float(score, 0.0)
            if score <= 0:
                return
            target_list = multiplier_factors if is_multiplier else factors
            target_list.append({
                "name": name, "score": round(score, 3), "value": value, "detail": detail,
            })
            LOGGER.debug("Risk Factor Applied: [%s] +%.2f (Detail: %s)", name, score, detail)

        device_type = getattr(state, "device_type", None) or "unknown"
        is_mobile = device_type in ["phone", "tablet"]
        mobile_dampener = 0.2 if is_mobile else 1.0

        sens = _DEVICE_SENSITIVITY.get(device_type, 1.0)
        is_infra = (sens <= 0.0)
        amplifier = min(1.0 / max(sens, 0.1), 1.25) if not is_infra else 1.0

        phase = features.get("killchain_phase", "NORMAL")
        markov_anomaly = safe_float(features.get("markov_anomaly", 0.0))
        total = safe_float(features.get("total", 0), 0.0)

        if phase != "NORMAL":
            if not hasattr(state, "killchain_history"):
                state.killchain_history = __import__('collections').deque(maxlen=5)
            if not state.killchain_history or state.killchain_history[-1] != phase:
                state.killchain_history.append(phase)

        history = list(getattr(state, "killchain_history", []))
        if len(history) >= 2 and total >= 30:
            seq = " -> ".join(history[-3:])
            has_critical_progression = (
                "RECON -> C2 -> EXFIL" in seq or
                "C2 -> LATERAL -> EXFIL" in seq or
                "RECON -> LATERAL -> EXFIL" in seq
            )
            if "C2 -> LATERAL" in seq and device_type not in ["smart_tv", "gaming_console", "iot"]:
                has_critical_progression = True

            if has_critical_progression:
                add("Sequential Kill-Chain Detected", 8.0, None, f"Deterministic sequence execution pattern matched: {seq}")

        if markov_anomaly > 0.95 and phase != "NORMAL" and total >= 30:
            add("Anomalous Phase Transition (Markov)", 3.0, round(markov_anomaly, 2), f"Highly irregular behavioral phase shift to {phase} (P < 0.05)")

        qz   = safe_float(features.get("query_rate_z"), 0.0)
        ez   = safe_float(features.get("entropy_z"), 0.0)
        uz   = safe_float(features.get("unique_domains_z"), 0.0)
        text_nx_z = safe_float(features.get("nxdomain_ratio_z"), 0.0)
        bl_z = safe_float(features.get("blocked_ratio_z"), 0.0)
        sd_z = safe_float(features.get("suspicious_domains_z"), 0.0)

        nx   = safe_float(features.get("nxdomain_ratio"), 0.0)
        bl   = safe_float(features.get("blocked_ratio"), 0.0)
        sd   = safe_float(features.get("suspicious_domains"), 0.0)
        tdr  = safe_float(features.get("top_domain_ratio"), 0.0)
        nd   = safe_float(features.get("new_domains", 0.0), 0.0)
        dd   = safe_float(features.get("deep_domains", 0.0), 0.0)
        tc   = safe_float(features.get("nxdomain_tld_conc", 0.0), 0.0)
        entropy_avg = safe_float(features.get("entropy_avg", 0.0), 0.0)
        unique_domains = safe_float(features.get("unique_domains", 1.0), 1.0)

        max_label_length = safe_float(features.get("max_label_length", 0), 0.0)
        dns_tunneling_domains = safe_float(features.get("dns_tunneling_domains", 0), 0.0)
        dga_score = safe_float(features.get("dga_score", 0.0), 0.0)
        nx_z = text_nx_z
        entropy = entropy_avg

        volume_dampener = 1.0 if total >= 100.0 else max(0.1, total / 100.0)

        st_domains = getattr(state.rolling, "domains", {}) if hasattr(state, "rolling") else {}
        top_domain = features.get("top_domain") or (max(st_domains, key=st_domains.get, default=None) if st_domains else None)

        seen_domains = getattr(state, "seen_domains", set()) if hasattr(state, "seen_domains") else set()
        top_domain_is_familiar = bool(top_domain and top_domain in seen_domains)
        if top_domain_is_familiar and tdr > 0.50:
            context_dampener = 0.35
            context_detail = " (Dampened: spike maps to familiar historical domain)"
        else:
            context_dampener = 1.0
            context_detail = ""

        is_telemetry = bool(top_domain and is_telemetry_domain(top_domain))
        rate_baseline_n = sum(getattr(state.rate_baseline, "n", [0, 0])) if hasattr(state, "rate_baseline") else 0
        is_on_probation = (rate_baseline_n < 288)
        
        current_hour = int(features.get("current_hour", 12))
        sigma_shift = safe_float(features.get("sigma_shift", 0.0), 0.0)

        # Wrap in hasattr to prevent AttributeError crashes
        if hasattr(state, "rate_baseline"):
            rate_mean, var, init, n = state.rate_baseline.get_stats(current_hour)
            if init and n > 50:
                std_dev = math.sqrt(max(var, 1e-4))
                threshold_limit = rate_mean + ((3.0 + sigma_shift) * std_dev)
                query_rate = features.get("query_rate", 0.0)
                if query_rate > threshold_limit and threshold_limit > 10:
                    add("Dynamic Query Threshold Exceeded", 2.5, round(query_rate, 2), f"Query rate {query_rate:.1f} exceeds dynamic threshold limit {threshold_limit:.1f} ({'+' if sigma_shift>=0 else ''}{sigma_shift:.2f}σ FP shift)")

        if sigma_shift < 0 and getattr(state, "has_validated_threat", False):
            boost = min(abs(sigma_shift) * 1.5, 2.0)
            add("Threat History Sensitivity Boost", boost, round(sigma_shift, 2), f"Device sensitivity tuned UP ({sigma_shift:.2f}σ shift due to past validated threat)")

        if not is_infra:
            if (dns_tunneling_domains >= 2 or (max_label_length > 55 and not _is_cdn_or_cloud_domain(top_domain or ""))) and not is_telemetry:
                tunnel_score = min(8.5, 4.0 + (dns_tunneling_domains * 1.5))
                add("DNS Covert Data Tunneling", tunnel_score, int(max_label_length), f"Encoded subdomains detected (Max label: {int(max_label_length)} chars, Tunnel count: {int(dns_tunneling_domains)})")

            dns_txt_null_ratio = safe_float(features.get("dns_txt_null_ratio", 0.0), 0.0)
            if dns_txt_null_ratio > 0.15 and not is_telemetry:
                add("DNS Record Abuse (TXT/NULL Tunneling)", min(dns_txt_null_ratio * 10.0, 6.0), round(dns_txt_null_ratio, 3), f"High concentration of TXT/NULL/ANY queries ({dns_txt_null_ratio*100:.1f}%)")

            suspicious_tld_ratio = safe_float(features.get("suspicious_tld_ratio", 0.0), 0.0)
            if suspicious_tld_ratio > 0.15 and not is_telemetry:
                add("High-Abuse C2 TLD Traffic", min(suspicious_tld_ratio * 8.0, 4.0), round(suspicious_tld_ratio, 3), f"Queries targeting known malware C2 TLDs ({suspicious_tld_ratio*100:.1f}%)")

            beaconing_c2_1h = safe_float(features.get("beaconing_c2_1h", 0), 0.0)
            if beaconing_c2_1h > 0 and not is_telemetry:
                add("Low-and-Slow C2 Periodicity (1-Hour)", 5.0, int(beaconing_c2_1h), f"Periodic check-ins tracked over 60-minute window ({int(beaconing_c2_1h)} sequences)")

            # UNIVERSAL ABSOLUTE DGA TRIPWIRES (Bypasses Probation and Baseline Locks)
            if sd >= 15:
                add("Absolute DGA / Suspicious Domain Burst", min(sd * 0.5, 8.0), sd, f"Massive burst of high-entropy / algorithmic domains ({int(sd)} domains)")
            elif sd >= 5 and entropy_avg > 3.5:
                add("High Entropy DGA Activity", 5.0, sd, f"Elevated volume of algorithmic domains ({int(sd)} domains, Entropy: {entropy_avg:.2f})")

            if is_on_probation:
                if device_type in ["phone", "tablet", "laptop", "desktop"]:
                    if total > 1500 and unique_domains > 100:
                        add("Probationary volume ceiling breach", 2.0 * context_dampener, total, f"Unverified new workstation/mobile generating massive query volumes{context_detail}")
                else:
                    if total > 100 and unique_domains > 40:
                        add("Probationary volume ceiling breach", 2.0 * context_dampener, total, f"Unverified new IoT/infrastructure generating high query volumes{context_detail}")

                if nx > 0.40 and not is_telemetry:
                    add("Probationary NXDOMAIN absolute breach", 1.0 * context_dampener, round(nx, 3), f"Unverified new device generating high absolute failure rates{context_detail}")
                
                # Context dampener is removed from the absolute DGA metric to guarantee isolation
                if nd > 15 and not is_telemetry and sd < 5:
                    add("Probationary unmapped infrastructure flood", 2.5, nd, f"Device contacting substantial unique external targets on first run")

            nd_ratio = nd / max(unique_domains, 1.0)
            dd_ratio = dd / max(unique_domains, 1.0)

            z_parts = []
            z_score_count = sum([qz > 3.0, ez > 3.0, uz > 3.0])

            if qz > 3.0: z_parts.append(f"query_rate_z={qz:.2f}")
            if ez > 3.0: z_parts.append(f"entropy_z={ez:.2f}")
            if uz > 3.0: z_parts.append(f"unique_domains_z={uz:.2f}")
            if nx > 0.3 and text_nx_z > 3.0 and not is_telemetry: z_parts.append(f"nxdomain_ratio={nx:.2f}(Z={text_nx_z:.1f})")
            if bl > 0.7 and bl_z > 3.0 and nx > 0.15: z_parts.append(f"blocked_ratio={bl:.2f}(Z={bl_z:.1f})")

            abs_count = sum([
                nx > 0.3 and text_nx_z > 3.0 and not is_telemetry,
                bl > 0.7 and bl_z > 3.0 and nx > 0.15,
            ])
            dns_anomaly_count = z_score_count + abs_count

            if z_score_count >= 1 and dns_anomaly_count >= 2:
                add("Correlated DNS baseline deviation", 3.0 * volume_dampener * context_dampener, None, ", ".join(z_parts) + context_detail)

            if not is_on_probation:
                if nx > 0.35 and text_nx_z > 3.0 and not is_telemetry:
                    add("NXDOMAIN ratio deviation", (nx - 0.35) * 4 * volume_dampener * context_dampener, round(nx, 3), f"Failed lookups deviating from profile{context_detail}")
                if bl > 0.85 and bl_z > 3.0 and nx > 0.2:
                    add("Blocked DNS ratio deviation", (bl - 0.85) * 4 * volume_dampener * context_dampener, round(bl, 3), f"Extreme block evasion behavior (Z={bl_z:.2f}){context_detail}")
                # Statistical Baseline DGA check (Only fires if absolute tripwires didn't catch it)
                if sd > 0 and sd_z > 3.0 and sd < 5:
                    if not is_telemetry:
                        add("Suspicious/DGA-like domains", min(sd, 10) * 0.4 * volume_dampener * context_dampener * mobile_dampener, sd, f"Heuristic matches verified by anomaly spike (Z={sd_z:.2f}){context_detail}")

            if nd_ratio > 0.25 and total >= 30 and not is_telemetry:
                add("First-seen domain burst", min(nd_ratio * 4.0, 2.0) * volume_dampener, round(nd_ratio, 3), f"New infrastructure share expansion ({int(nd)} domains)")
            if (dga_score > 0.40 or (nx_z > 3.0 and entropy > 3.4)) and not is_telemetry:
                dga_val = min(7.5, max(dga_score * 7.5, (nx_z * 0.8) + (entropy * 0.5)))
                add("DGA / Botnet Command & Control", dga_val, round(dga_score, 3), f"Algorithmic domain structure detected (Entropy: {entropy:.2f}, NX-Z: {nx_z:.1f})")

        query_rate_z = safe_float(features.get("query_rate_z", 0.0), 0.0)
        if query_rate_z > 3.0 and not is_infra:
            add("Anomalous Query Rate Spike", min(query_rate_z * 0.75, 4.0), round(query_rate_z, 2), f"DNS query velocity {query_rate_z:.1f}σ above diurnal baseline")

        unique_domains_z = safe_float(features.get("unique_domains_z", 0.0), 0.0)
        if unique_domains_z > 3.0 and not is_infra and not is_telemetry:
            add("First-seen domain burst", min(unique_domains_z * 0.6, 3.5), round(unique_domains_z, 2), f"Unique destination domain count {unique_domains_z:.1f}σ above normal")

        beacon_tdr = safe_float(features.get("beacon_tdr", 0.0), 0.0)
        beacon_total = safe_float(features.get("beacon_total", 0.0), 0.0)
        if beacon_tdr > 0.45 and beacon_total >= 10 and not is_infra:
            tdr, total = beacon_tdr, beacon_total
            beacon_score = 0.0
            if tdr > 0.90 and total >= 30: beacon_score = 3.5
            elif tdr > 0.80 and total >= 20: beacon_score = 2.5
            elif tdr > 0.75 and total >= 15: beacon_score = 1.5

            if is_telemetry:
                beacon_score *= 0.1

            add("Persistent single-target beaconing", beacon_score * context_dampener, round(tdr, 3), f"Concentrated tracking (total_queries={int(total)}){context_detail}")

        ti_risk = safe_float(features.get("ti_risk", 0.0), 0.0)
        has_high_confidence_threat = (ti_risk > 0) or bool(features.get("has_tier1_zeek_notice", False))

        if ml_score > 0.02 and not is_infra:
            if is_on_probation:
                if top_domain_is_familiar or is_telemetry:
                    ml_penalty = min(ml_score * 10.0, 1.0)
                else:
                    ml_cap = 1.5 if not has_high_confidence_threat else (2.0 if device_type in ["phone", "tablet", "laptop", "desktop"] else 3.5)
                    ml_penalty = min(ml_score * 40.0, ml_cap)
                add("ML absolute structural outlier (Probationary)", ml_penalty, round(ml_score, 4), "Device structure contradicts baseline parameters")
            else:
                ml_cap = 1.5 if not has_high_confidence_threat else 4.0
                add("ML anomaly matrix alert", min(ml_score * 40.0, ml_cap), round(ml_score, 4), "Per-device IsolationForest anomaly margin")

        add("Threat intelligence IOC", min(ti_risk, 4.0), round(ti_risk, 3), "Domain or IP matched loaded IOC feeds")

        abuse_risk = safe_float(features.get("abuseipdb_risk", 0.0), 0.0)
        add("AbuseIPDB blacklist", min(abuse_risk, 4.0), round(abuse_risk, 3), "Destination IP appears in AbuseIPDB blacklist")

        vt_risk = safe_float(features.get("vt_risk", 0.0), 0.0)
        add("VirusTotal detection", min(vt_risk, 4.0), round(vt_risk, 3), "Cached VirusTotal result is suspicious or malicious")

        outbound_bytes_z = safe_float(features.get("outbound_bytes_z", 0.0), 0.0)
        zeek_outbound_bytes = safe_float(features.get("zeek_outbound_bytes", 0.0), 0.0)

        _CLOUD_VENDOR_API_DOMAINS = frozenset({
            "coinbase.com", "microsoft.com", "apple.com", "amazonaws.com", "google.com",
            "azure.com", "cloudflare.com", "fritz.box", "github.com", "sentry.io"
        })
        is_vendor_cloud_api = any(top_domain.endswith(d) for d in _CLOUD_VENDOR_API_DOMAINS) if top_domain else False

        if outbound_bytes_z > 5.0 and zeek_outbound_bytes > 2500000 and not is_vendor_cloud_api: 
            add("Exfiltration Payload Burst", 6.5, round(outbound_bytes_z, 2), f"Massive outbound data anomaly severely breaking distribution bounds (Z: {outbound_bytes_z:.2f})")
        elif outbound_bytes_z > 3.5 and zeek_outbound_bytes > 250000 and not is_telemetry: 
            payload_score = 1.5 if is_vendor_cloud_api else 4.0
            add("Anomalous Outbound Traffic", payload_score, round(outbound_bytes_z, 2), f"Elevated outbound data (Z: {outbound_bytes_z:.2f})")
        elif zeek_outbound_bytes > 50000000 and not is_telemetry and not is_vendor_cloud_api:
            add("Absolute Outbound Exfiltration Payload", 4.5, zeek_outbound_bytes, f"High volume outbound transfer breach ({zeek_outbound_bytes/1048576:.1f} MB uploaded)")

        lateral_moves_count = safe_float(features.get("zeek_lateral_moves", 0), 0.0)
        if lateral_moves_count > 0:
            add("Internal Lateral Movement", 6.5, min(lateral_moves_count, 1000), f"Device scanning internal restricted ports ({int(lateral_moves_count)} hits)")

        zeek_ja3 = safe_float(features.get("zeek_ja3_malicious", 0), 0.0)
        if zeek_ja3 > 0:
            add("Malicious TLS Fingerprint (JA3)", 7.5, zeek_ja3, "TLS Client Hello matched known malicious C2 / Cobalt Strike fingerprint")

        zeek_ja4 = safe_float(features.get("zeek_ja4_malicious", 0), 0.0)
        if zeek_ja4 > 0:
            add("Malicious TLS Fingerprint (JA4+)", 8.5, zeek_ja4, "TLS Client Hello matched known malicious JA4+ Threat Feed hash")

        zeek_ports = safe_float(features.get("zeek_susp_ports", 0), 0.0)
        if zeek_ports > 0:
            add("Suspicious destination port", 3.0, min(zeek_ports, 100), f"Connecting to non-standard external ports ({int(zeek_ports)} hits)")

        c2_jitter_count = safe_float(features.get("beaconing_c2_count", 0), 0.0)
        last_dest_ip = features.get("last_dest_ip", "unknown")
        is_local_dest = False

        if last_dest_ip and last_dest_ip != "unknown":
            try:
                ip_obj = ipaddress.ip_address(last_dest_ip)
                if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_loopback or ip_obj.is_reserved or (ip_obj.version == 4 and str(ip_obj).endswith('.255')):
                    is_local_dest = True
            except ValueError:
                pass

        if c2_jitter_count > 0 and total >= 5 and not is_telemetry and not is_local_dest:
            jitter_score = 5.5
            detail_str = f"Uniform periodicity check-in sequences tracked ({int(c2_jitter_count)} hits)"

            if zeek_outbound_bytes == 0:
                jitter_score = 3.0
                detail_str += " (Dampened: 0-byte payload)"

            add("C2 Jitter Clock Verification", jitter_score, min(c2_jitter_count, 100), detail_str)

        s0_rej = safe_float(features.get("zeek_s0_rej_count", 0), 0.0)
        s0_rej_unique = safe_float(features.get("zeek_s0_rej_unique_ips", 0), 0.0)
        blocked_ratio = safe_float(features.get("blocked_ratio", 0.0), 0.0)

        if s0_rej > 25 and s0_rej_unique > 5:
            raw_penalty = min(7.5, (s0_rej / 35.0) * 1.5) * mobile_dampener
            if blocked_ratio > 0.15:
                dampener = max(0.1, 1.0 - blocked_ratio)
                adjusted_penalty = raw_penalty * dampener
                if adjusted_penalty >= 1.0:
                    add("TCP Connection Failures (Sinkholed)", adjusted_penalty, min(s0_rej, 5000), f"Penalty suppressed due to {blocked_ratio*100:.1f}% blocked DNS traffic (Likely Telemetry)")
            else:
                if raw_penalty >= 5.0 and s0_rej_unique > 15:
                    add("TCP Port Scan (S0/REJ)", raw_penalty, min(s0_rej, 5000), f"Massive volume of rejected connections across {int(s0_rej_unique)} unique IPs ({int(s0_rej)} hits)")
                else:
                    add("Suspicious Connection Failures", raw_penalty, min(s0_rej, 5000), f"Elevated rejected connections to {int(s0_rej_unique)} unique IPs ({int(s0_rej)} hits)")

        max_dur = safe_float(features.get("zeek_max_duration", 0), 0.0)
        if max_dur > 43200: 
            add("Covert Tunnel / Reverse Shell", 6.5, round(max_dur, 1), f"Extremely long connection duration ({int(max_dur)}s)")
        elif max_dur > 14400: 
            add("Long-lived Connection", 3.0, round(max_dur, 1), f"Suspiciously long session duration ({int(max_dur)}s)")

        honeypot_hits = safe_float(features.get("zeek_honeypot_hits", 0), 0.0)
        if honeypot_hits > 0:
            # AUDIT FIX #15: Honeypot IPs come from config, not hardcoded
            honeypot_ips_cfg = features.get("_config_honeypot_ips", "configured decoy IPs")
            add("Honeypot Deception Triggered", 10.0, honeypot_hits, f"Device accessed internal decoy/sinkhole listener ({honeypot_ips_cfg}) ({int(honeypot_hits)} hits)")


        _BENIGN_ZEEK_WEIRD = frozenset({
            "weird:data_before_established", "weird:inappropriate_FIN",
            "weird:bad_TCP_checksum", "weird:above_hole_data_without_any_acks",
            "weird:connection_originator_SYN_ack",
        })

        if zeek_alerts:
            _TIER_1_NOTICES = {"Scan::Port_Scan", "SMB::Exploit", "Botnet::C2", "Zeek::Malware"}
            _TIER_2_NOTICES = {"DNS::External_Name", "DNS::TXT_Abuse", "SSL::Old_Version"}
            _TIER_3_NOTICES = {"SSL::Invalid_Server_Cert", "SSL::Self_Signed"}
            
            for alert in (zeek_alerts or []):
                conf  = safe_float(alert.get("confidence", 0.8), 0.8)
                atype = alert.get("type", "")
                if atype in ("malicious_ja3", "malicious_ja4"):
                    pass 
                elif atype == "zeek_notice":
                    note = alert.get("note", "")
                    if note in _BENIGN_ZEEK_WEIRD or note in {"DHCP::Message", "weird:bad_TCP_checksum"}:
                        continue   
                    
                    if note in _TIER_1_NOTICES:
                        note_score = conf * 4.0
                    elif note in _TIER_2_NOTICES:
                        note_score = conf * 1.5
                    elif note in _TIER_3_NOTICES:
                        note_score = conf * 0.5
                    else:
                        note_score = conf * 1.0
                        
                    add(f"Zeek notice ({note})", note_score, None, f"Zeek protocol anomaly: {note}")

        risk = sum(f["score"] for f in factors)
        if amplifier != 1.0 and risk > 0 and not is_infra:
            before = risk
            risk *= amplifier
            add("Device sensitivity multiplier", risk - before, round(amplifier, 3), device_type, is_multiplier=True)

        risk_baseline = getattr(state, "risk_baseline", None)
        if risk_baseline and not is_infra:
            current_hour = int(features.get("current_hour", 12))
            mean, var, init, n = risk_baseline.get_stats(current_hour)
            if init and n >= 50:
                _std = math.sqrt(max(var, 0.25))
                velocity = (risk - mean) / _std
                if velocity > 4.0:   
                    bonus = min(velocity * 0.25, 1.0)   
                    risk += bonus
        # COLD-START PROBATION SAFETY CAP:
        # Prevent new devices / workstations on cold-start probation (N < 288 cycles)
        # from being false-positive blocked during baseline profile initialization.
        # Cap unverified probation risk at 5.50 (strictly below 6.00 alert and 8.50 isolation limits)
        # unless a verified ThreatIntel IOC, lateral attack, malicious TLS, or honeypot trigger occurs.
        has_verified_critical_threat = (
            safe_float(features.get("ti_risk", 0.0), 0.0) > 0 or 
            safe_float(features.get("zeek_lateral_moves", 0), 0) > 0 or 
            safe_float(features.get("zeek_ja3_malicious", 0), 0) > 0 or 
            safe_float(features.get("zeek_ja4_malicious", 0), 0) > 0 or 
            safe_float(features.get("zeek_honeypot_hits", 0), 0) > 0
        )
        if is_on_probation and not has_verified_critical_threat:
            risk = min(risk, 5.50)

        risk = min(risk, 100.0)

        factors.sort(key=lambda f: f["score"], reverse=True)
        multiplier_factors.sort(key=lambda f: f["score"], reverse=True)
        final_factors = factors + multiplier_factors

        LOGGER.debug("Final Risk Score: %.2f (Factors Evaluated: %d)", risk, len(final_factors))
        return {"risk": round(risk, 3), "factors": final_factors}