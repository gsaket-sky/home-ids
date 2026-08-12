"""
metrics.py - Prometheus metrics registry for Home IDS.

RECENT FIXES:
- FIXED (CARDINALITY BOMB): Stripped unbounded, high-entropy labels from gauges and counters.
  - `ndr_lateral_targets_total` -> `ndr_lateral_events_total` (removed raw IPs/Ports).
  - `ips_queue_status_gauge` (removed `retry_count` label).
  - `ips_dead_letter_gauge` (removed `reason` label).
  - `ips_tarpit_active` (removed raw IP label).
"""
try:
    from prometheus_client import Gauge, Counter
except Exception:
    class _NoopMetric:
        def labels(self, *args, **kwargs): return self
        def set(self, *args, **kwargs): return None
        def inc(self, *args, **kwargs): return None
        def remove(self, *args, **kwargs): return None

    def Gauge(*args, **kwargs): return _NoopMetric()
    def Counter(*args, **kwargs): return _NoopMetric()

_DEV_LABELS = ["device", "hostname", "device_type"]

threat_confidence_metric = Gauge("home_ids_threat_confidence", "Threat Confidence (0.0 to 1.0)", _DEV_LABELS)
anomaly_confidence_metric = Gauge("home_ids_anomaly_confidence", "Anomaly Confidence (0.0 to 1.0)", _DEV_LABELS)
decision_state_metric = Gauge("home_ids_decision_state", "HEE State (0=BENIGN, 1=ANOMALOUS, 2=SUSPICIOUS, 3=HIGH, 4=CRITICAL)", _DEV_LABELS)
query_rate_metric = Gauge("home_ids_query_rate", "DNS queries per minute", _DEV_LABELS)
unique_domains_metric = Gauge("home_ids_unique_domains", "Unique domains queried", _DEV_LABELS)
entropy_metric = Gauge("home_ids_entropy_avg", "Average DNS entropy", _DEV_LABELS)
blocked_ratio_metric = Gauge("home_ids_blocked_ratio", "Blocked DNS ratio", _DEV_LABELS)
nxdomain_ratio_metric = Gauge("home_ids_nxdomain_ratio", "NXDOMAIN ratio", _DEV_LABELS)
suspicious_domains_metric = Gauge("home_ids_suspicious_domains", "Suspicious/DGA-like domains", _DEV_LABELS)


markov_anomaly_metric = Gauge("home_ids_markov_anomaly_score", "Markov chain state transition anomaly score", _DEV_LABELS)
zscore_query_metric = Gauge("home_ids_zscore_query_rate", "Query-rate z-score", _DEV_LABELS)
zscore_entropy_metric = Gauge("home_ids_zscore_entropy", "Entropy z-score", _DEV_LABELS)
zscore_unique_metric = Gauge("home_ids_zscore_unique_domains", "Unique-domain z-score", _DEV_LABELS)

def remove_stale_device_metrics(device_id: str, hostname: str, device_type: str = "unknown") -> None:
    """Removes obsolete label tuples from Prometheus gauges when a device is pruned or IP rebinds."""
    gauges = [
        query_rate_metric, unique_domains_metric, entropy_metric,
        blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
        markov_anomaly_metric, zscore_query_metric,
        zscore_entropy_metric, zscore_unique_metric
    ]
    for g in gauges:
        try:
            g.remove(device_id, hostname, device_type)
        except Exception:
            pass

geo_risk_metric = Gauge("home_ids_geo_risk", "Risk score by geography", ["country", "city", "asn", "org", "continent", "latitude", "longitude"])
geo_hits_metric = Counter("home_ids_geo_hits_total", "Threat hits by geolocation", ["country", "asn"])
asn_risk_metric = Gauge("home_ids_asn_risk_score", "Risk score by ASN", ["asn", "org"])
country_density_metric = Gauge("home_ids_country_threat_density", "Threat density per country", ["country"])
geo_beacon_metric = Counter("home_ids_geo_beaconing_total", "Beaconing detections by geography", ["country", "asn"])
geo_traffic_total = Counter("home_ids_geo_traffic_total", "All DNS traffic by geography", ["country", "city", "continent", "asn", "org", "latitude", "longitude"])
geo_queries_per_minute = Gauge("home_ids_geo_queries_per_minute", "DNS query rate by geography", ["country", "city", "asn", "latitude", "longitude"])
geo_unique_domains = Gauge("home_ids_geo_unique_domains", "Unique domains by geography", ["country", "city", "asn"])
geo_entropy = Gauge("home_ids_geo_entropy", "Entropy score by geography", ["country", "city", "asn"])
geo_device_count = Gauge("home_ids_geo_device_count", "Device count by geography", ["country", "city", "asn"])

collector_lag_metric = Gauge("home_ids_collector_lag_seconds", "Collector processing lag")
alert_queue_metric = Gauge("home_ids_alert_queue_size", "Current alert queue size")
ml_model_loaded_metric = Gauge("home_ids_ml_model_loaded", "ML model loaded state")
events_processed_metric = Counter("home_ids_events_processed_total", "Processed DNS events")
zeek_status_metric = Gauge("home_ids_zeek_status", "Zeek collector operational status")
zeek_events_processed_metric = Counter("home_ids_zeek_events_processed_total", "Total Zeek log events parsed")
alerts_total = Counter("home_ids_alerts_total", "IDS alerts triggered")
integration_status_metric = Gauge("home_ids_integration_status", "Operational status of external integrations (1=active, 0=inactive)", ["integration"])

# 🛡️ Split IPS Architecture Status & Telemetry
ips_pihole_status = Gauge("home_ids_ips_pihole_status", "Pi-hole Mitigation operational state (1=active, 0=bypass)")
ips_router_status = Gauge("home_ids_ips_router_status", "Router WAN Kill-Switch operational state (1=active, 0=bypass)")
ips_tarpit_status = Gauge("home_ids_ips_tarpit_status", "Layer-2 Scapy ARP Tarpit operational state (1=active, 0=bypass)")

ips_pihole_blocks_metric = Counter("home_ids_ips_pihole_blocks_total", "Total automated domain blocks executed", ["device", "hostname", "domain"])
ips_isolations_metric = Counter("home_ids_ips_router_isolations_total", "Total automated network isolation commands triggered", ["device", "hostname", "mac"])
ips_errors_metric = Counter("home_ids_ips_errors_total", "Total failure states encountered during active mitigation runs", ["target_type"])

new_domains_metric = Gauge("home_ids_new_domains", "Domains seen for the first time this window", _DEV_LABELS)
deep_domains_metric = Gauge("home_ids_deep_domains", "Domains with > 5 DNS labels", _DEV_LABELS)
nxdomain_tld_conc_metric = Gauge("home_ids_nxdomain_tld_concentration", "Fraction of traffic under top TLD", _DEV_LABELS)
zscore_nxdomain_metric = Gauge("home_ids_zscore_nxdomain_ratio", "NXDOMAIN ratio z-score", _DEV_LABELS)
zscore_blocked_metric = Gauge("home_ids_zscore_blocked_ratio", "Blocked ratio z-score", _DEV_LABELS)
zscore_dga_metric = Gauge("home_ids_zscore_suspicious_domains", "Suspicious domain count z-score", _DEV_LABELS)
risk_velocity_metric = Gauge("home_ids_risk_velocity", "Risk score z-score vs risk baseline", _DEV_LABELS)
ti_risk_metric = Gauge("home_ids_ti_risk", "Threat intelligence risk contribution", _DEV_LABELS)
ti_match_metric = Gauge("home_ids_ti_match", "Threat intelligence IOC match flag", _DEV_LABELS)
ti_ioc_hits_total = Counter("home_ids_ti_ioc_hits_total", "Total IOC matches from all TI feeds", ["source", "ioc_type"])
safe_device_metric = Gauge("home_ids_safe_device", "Device is on the safe list", _DEV_LABELS)
probation_status_metric = Gauge("home_ids_probation_status", "Device is in cold-start probation", _DEV_LABELS)
baseline_poisoned_metric = Gauge("home_ids_baseline_poisoned", "Baseline update frozen this cycle", _DEV_LABELS)
zeek_conn_count_metric = Gauge("home_ids_zeek_conn_count", "Total TCP/UDP connections seen by Zeek", _DEV_LABELS)
zeek_new_ips_metric = Gauge("home_ids_zeek_new_ips", "Unique destination IPs seen via Zeek", _DEV_LABELS)
zeek_ja3_metric = Gauge("home_ids_zeek_ja3_malicious", "Malicious JA3 TLS fingerprint hits", _DEV_LABELS)
zeek_ja4_metric = Gauge("home_ids_zeek_ja4_malicious", "Malicious JA4+ TLS fingerprint hits", _DEV_LABELS)
zeek_notices_metric = Gauge("home_ids_zeek_notices", "Zeek notice events for this device", _DEV_LABELS)
zeek_susp_ports_metric = Gauge("home_ids_zeek_suspicious_ports", "Outbound connections to suspicious ports", _DEV_LABELS)
query_rate_baseline_mean_metric = Gauge("home_ids_query_rate_baseline_mean", "Per-device query rate moving average baseline", _DEV_LABELS)
query_rate_threshold_limit_metric = Gauge("home_ids_query_rate_threshold_limit", "Per-device dynamic query rate threshold limit", _DEV_LABELS)
ndr_doh_bypass_metric = Gauge("home_ids_zeek_doh_bypass", "Direct DoH queries intercepted", _DEV_LABELS)
ndr_lateral_moves_metric = Gauge("home_ids_zeek_lateral_moves", "Internal security lateral scanning actions", _DEV_LABELS)
ndr_jitter_c2_metric = Gauge("home_ids_beaconing_c2_count", "Highly uniform periodicity C2 channels tracked", _DEV_LABELS)
ndr_delta_exfil_metric = Gauge("home_ids_outbound_bytes_window", "Windowed outbound network payload bytes", _DEV_LABELS)
ndr_exfil_z_metric = Gauge("home_ids_outbound_bytes_zscore", "Payload outbound bytes baseline deviation Z-score", _DEV_LABELS)
abuseipdb_risk_metric = Gauge("home_ids_abuseipdb_risk", "AbuseIPDB reputation hazard severity", _DEV_LABELS)
virustotal_risk_metric = Gauge("home_ids_virustotal_risk", "VirusTotal sandbox analysis hazard severity", _DEV_LABELS)
beaconing_volume_metric = Gauge("home_ids_beaconing_volume_score", "Single-destination traffic concentration score", _DEV_LABELS)
jitter_cv_metric = Gauge("home_ids_jitter_cv_score", "Timing uniformity coefficient of variation", _DEV_LABELS)
ndr_tcp_scan_metric = Gauge("home_ids_zeek_s0_rej_count", "Rejected or unanswered TCP connection attempts (Port Scans)", _DEV_LABELS)
ndr_max_duration_metric = Gauge("home_ids_zeek_max_duration", "Maximum continuous connection session duration in seconds", _DEV_LABELS)
ndr_honeypot_hits_metric = Gauge("home_ids_zeek_honeypot_hits", "Connections to internal deception honeypots", _DEV_LABELS)

# 🎓 Full Transparency & Novice Security Educational Metrics
killchain_phase_metric = Gauge("home_ids_killchain_phase", "Cyber Kill-Chain phase (0=Normal, 1=Recon, 2=C2, 3=Lateral, 4=Exfil)", _DEV_LABELS)
dns_txt_null_ratio_metric = Gauge("home_ids_dns_txt_null_ratio", "Fraction of TXT/NULL/ANY queries (DNS Covert Tunneling Abuse)", _DEV_LABELS)
suspicious_tld_ratio_metric = Gauge("home_ids_suspicious_tld_ratio", "Fraction of queries targeting high-abuse C2 TLDs", _DEV_LABELS)
outbound_bytes_1h_metric = Gauge("home_ids_outbound_bytes_1h", "Cumulative 1-hour outbound payload volume in bytes", _DEV_LABELS)
beaconing_c2_1h_metric = Gauge("home_ids_beaconing_c2_1h", "1-hour low-and-slow periodic C2 beacon count", _DEV_LABELS)
dns_tunneling_domains_metric = Gauge("home_ids_dns_tunneling_domains", "Count of high-entropy DNS tunneling payload domains", _DEV_LABELS)
max_label_length_metric = Gauge("home_ids_max_label_length", "Maximum DNS subdomain label length seen in window", _DEV_LABELS)

# Stripped high-cardinality IP/Port labels. Now tracks strict aggregate event volumes.
ndr_lateral_events_total = Counter("home_ids_zeek_lateral_events_total", "Internal lateral movement events", ["device", "hostname"])

# Real-Time IPS State Gauges for Grafana Transparency
ips_active_blocks_gauge = Gauge(
    "home_ids_ips_active_blocks", 
    "Currently active Pi-hole domain blocks", 
    ["device", "hostname", "domain"]
)
ips_queue_status_gauge = Gauge(
    "home_ids_ips_queue_status", 
    "Domains currently stuck in retry queue", 
    ["device", "hostname", "domain"]
)
ips_dead_letter_gauge = Gauge(
    "home_ids_ips_dead_letter", 
    "Domains permanently failed after max retries", 
    ["device", "hostname", "domain"]
)
ips_tarpit_active = Gauge(
    "home_ids_ips_tarpit_active",
    "Devices actively trapped inside the Layer-2 ARP Blackhole",
    ["device", "hostname", "mac"]
)
ips_router_isolated_active = Gauge(
    "home_ids_ips_router_isolated_active",
    "Devices actively isolated at hardware router WAN level via Fritz!Box Webhook",
    ["device", "hostname", "mac"]
)

# Low-cardinality aggregate counters (audit-safe long-term storage)
ips_pihole_blocks_total = Counter("home_ids_ips_pihole_blocks_aggregate_total", "Total automated domain blocks executed (aggregate)")
ips_router_isolations_total = Counter("home_ids_ips_router_isolations_aggregate_total", "Total automated router isolations executed (aggregate)")
ips_tarpit_activations_total = Counter("home_ids_ips_tarpit_activations_aggregate_total", "Total tarpit activations executed (aggregate)")

# ===========================================================================
# Autonomous False-Positive Elimination Engine (CL-AFPE) Metrics
# ===========================================================================
fp_engine_evaluations_total = Counter("home_ids_fp_evaluations_total", "Total number of alerts evaluated by the Autonomous FP Engine")
fp_engine_suppressed_total = Counter("home_ids_fp_suppressed_total", "Total alerts autonomously classified as False Positive and suppressed")
fp_engine_confirmed_threats_total = Counter("home_ids_fp_confirmed_threats_total", "Total alerts that bypassed FP engine due to hard-stop threat signals")
fp_engine_confidence_score = Gauge("home_ids_fp_confidence_score", "FP Engine confidence score (0=threat, 1=false positive) for latest alert", ["device", "hostname"])
fp_engine_trust_cache_size = Gauge("home_ids_fp_trust_cache_size", "Number of base domains currently in the autonomous dynamic trust cache")
fp_engine_lgbm_model_status = Gauge("home_ids_fp_lgbm_model_status", "LightGBM ONNX classifier model status (1=loaded, 0=unavailable)")
fp_engine_embed_model_status = Gauge("home_ids_fp_embed_model_status", "FastEmbed ONNX vector similarity model status (1=loaded, 0=unavailable)")
fp_engine_stage1_hardstop_hits = Counter("home_ids_fp_stage1_hardstop_hits_total", "Alerts blocked at Stage 1")
fp_engine_stage2_lgbm_hits = Counter("home_ids_fp_stage2_lgbm_hits_total", "Alerts classified FP at Stage 2")
fp_engine_stage3_embed_hits = Counter("home_ids_fp_stage3_embed_hits_total", "Alerts classified FP at Stage 3")
fp_engine_domains_immunized_total = Counter("home_ids_fp_domains_immunized_total", "Total unique eTLD+1 base domains autonomously added to the trust cache")
fp_engine_sigma_shifts_total = Counter("home_ids_fp_sigma_shifts_total", "Total automatic baseline sigma-widening adjustments applied to devices", ["device", "hostname"])