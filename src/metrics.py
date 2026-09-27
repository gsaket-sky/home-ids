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
_DEV_DOMAIN_LABELS = ["device", "hostname", "device_type", "domain"]

top_domain_risk_metric = Gauge("home_ids_device_top_domain_risk", "Threat risk of the top domains for a device", _DEV_DOMAIN_LABELS)

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

# PHASE 18 FIX (CARDINALITY): latitude/longitude removed from every geo label set below.
# Rounded-to-0.1-degree coordinates crossed with country/city/asn/org is effectively
# unbounded over time (a new grid cell + ASN combination for every new IP that ever
# resolves). Geo aggregation now stops at city/country/asn/org, which is what every
# panel actually groups by anyway -- a Grafana geomap can still plot a point per
# country/city via a small static centroid lookup if a map view is ever needed, without
# the metric itself carrying unbounded coordinate labels.
geo_risk_metric = Gauge("home_ids_geo_risk", "Risk score by geography", ["country", "city", "asn", "org", "continent"])
asn_risk_metric = Gauge("home_ids_asn_risk_score", "Risk score by ASN", ["asn", "org"])
country_density_metric = Gauge("home_ids_country_threat_density", "Threat density per country", ["country"])
geo_beacon_metric = Counter("home_ids_geo_beaconing_total", "Beaconing detections by geography", ["country", "asn"])
# PHASE 18 FIX (REDUNDANT): geo_hits_metric used to double-count the same "beaconing
# threat" cross-section as geo_beacon_metric/country_density_metric once latitude/
# longitude stopped differentiating it from geo_traffic_total -- dropped as a duplicate
# label-subset of geo_traffic_total below, not a distinct signal.
geo_traffic_total = Counter("home_ids_geo_traffic_total", "All DNS traffic by geography", ["country", "city", "continent", "asn", "org"])
geo_queries_per_minute = Gauge("home_ids_geo_queries_per_minute", "DNS query rate by geography", ["country", "city", "asn"])
geo_unique_domains = Gauge("home_ids_geo_unique_domains", "Unique domains by geography", ["country", "city", "asn"])
geo_entropy = Gauge("home_ids_geo_entropy", "Entropy score by geography", ["country", "city", "asn"])
geo_device_count = Gauge("home_ids_geo_device_count", "Device count by geography", ["country", "city", "asn"])
# PHASE 18: gives the geomap panel its coordinates back without reintroducing unbounded
# cardinality -- latitude/longitude here come from core/country_centroids.py's static
# ~195-country lookup table, not from any actual resolved IP's coordinates. Bounded at
# ~195 label combinations regardless of traffic volume. Value is the same risk score
# geo_risk_metric carries (set under the identical risk>=alert_threshold gate), so the
# geomap panel can query this one metric alone for both the marker size/color AND its position.
geo_country_marker = Gauge("home_ids_geo_country_marker", "Risk score by country, with static centroid coordinates for geomap plotting", ["country", "latitude", "longitude"])

collector_lag_metric = Gauge("home_ids_collector_lag_seconds", "Collector processing lag")
alert_queue_metric = Gauge("home_ids_alert_queue_size", "Current alert queue size")
ml_model_loaded_metric = Gauge("home_ids_ml_model_loaded", "ML model loaded state")
events_processed_metric = Counter("home_ids_events_processed_total", "Processed DNS events")
zeek_status_metric = Gauge("home_ids_zeek_status", "Zeek collector operational status")
zeek_events_processed_metric = Counter("home_ids_zeek_events_processed_total", "Total Zeek log events parsed")
alerts_total = Counter("home_ids_alerts_total", "IDS alerts triggered", ["device", "hostname", "device_type"])
integration_status_metric = Gauge("home_ids_integration_status", "Operational status of external integrations (1=active, 0=inactive)", ["integration"])

# 🛡️ Split IPS Architecture Status & Telemetry
ips_pihole_status = Gauge("home_ids_ips_pihole_status", "Pi-hole Mitigation operational state (1=active, 0=bypass)")
ips_router_status = Gauge("home_ids_ips_router_status", "Router WAN Kill-Switch operational state (1=active, 0=bypass)")
ips_tarpit_status = Gauge("home_ids_ips_tarpit_status", "Layer-2 Scapy ARP Tarpit operational state (1=active, 0=bypass)")

# PHASE 5 FIX (fail-open visibility): 1 once ThreatIntel has completed at least one
# successful feed refresh, 0 while still cold-starting or if the refresh loop is failing.
# Lookups already fail open (ti_risk=0.0) both when there's genuinely no IOC match AND
# when the engine has no feed data yet loaded — those two cases were previously
# indistinguishable on Grafana. This gauge makes "TI is degraded/not ready" visible
# instead of silently reading as "checked, nothing found."
ti_engine_ready_status = Gauge("home_ids_ti_engine_ready", "1 if ThreatIntel has completed at least one successful feed refresh, 0 if still cold-starting/degraded")

# PHASE 18 FIX (CARDINALITY): dropped the "domain" label -- domains are attacker/DGA
# chosen strings, unbounded, and a per-domain trend Counter isn't needed for anything a
# dashboard actually queries by domain (the currently-blocked *state* is what needs
# per-domain resolution, and that's ips_active_blocks_gauge below, already bounded and
# GC'd). Per-domain detail for any specific block still lives in the Pi-hole comment and
# in alerts.json.
ips_pihole_blocks_metric = Counter("home_ids_ips_pihole_blocks_total", "Total automated domain blocks executed", ["device", "hostname"])
ips_isolations_metric = Counter("home_ids_ips_router_isolations_total", "Total automated network isolation commands triggered", ["device", "hostname", "mac"])
ips_errors_metric = Counter("home_ids_ips_errors_total", "Total failure states encountered during active mitigation runs", ["target_type"])
# PHASE 18: the block-side counter above always had a per-device breakdown; the
# unblock/release side previously had no metric at all -- "block only what's necessary"
# is only verifiable if release activity is as visible as block activity. `reason`
# is a small fixed enum (immunized/manual), never attacker-controlled.
ips_pihole_unblocks_metric = Counter("home_ids_ips_pihole_unblocks_total", "Total automated/manual domain releases executed", ["device", "hostname", "reason"])
ips_router_releases_metric = Counter("home_ids_ips_router_releases_total", "Total router isolation releases executed", ["device", "hostname", "reason"])

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
# PHASE 21-METRICS: ARP host-discovery sweep count and DNS-evasion unexplained-connection
# ratio were computed and fed into detection (threat_signals.py's arp_sweep evidence,
# fp_engine's LightGBM feature 9/10) but had no Prometheus visibility at all -- an
# operator watching Grafana had no way to see either signal for any device, ever.
ndr_arp_sweep_metric = Gauge("home_ids_zeek_arp_sweep_count", "Distinct hosts ARP-requested by this device in the current window (host-discovery sweep signal)", _DEV_LABELS)
ndr_dns_evasion_ratio_metric = Gauge("home_ids_zeek_dns_evasion_ratio", "Most recent reactive-capture blind-spot-audit unexplained-connection ratio [0.0-1.0] for this device", _DEV_LABELS)
# PHASE 18 FIX (CARDINALITY + mislabel): dropped "attacker_ip" -- unbounded, and the
# only call site was actually passing the local device_id there, not a real attacker IP
# (a pre-existing mislabel, independent of the cardinality fix). Detail on which IP
# probed which honeypot belongs in alerts.json/Loki, not a metric label.
honeypot_probes_total = Counter("home_ids_honeypot_probes_total", "Total external probes hitting honeypot IPs", ["dest_port", "protocol"])

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

# PHASE 18 FIX (REDUNDANT): ips_pihole_blocks_total and ips_router_isolations_total
# (both plain "*_aggregate_total" Counters) formerly here were declared but never
# incremented anywhere in the codebase -- dead metrics, always reading zero.
# ips_pihole_blocks_metric/ips_isolations_metric already cover the same ground with a
# real per-device breakdown, summable in Grafana (sum(...) without (device,hostname))
# for the same aggregate view these existed to provide.
#
# ips_tarpit_activations_total was ALSO dead, but unlike the router/pihole case there
# was no non-aggregate replacement to fall back on -- ips_tarpit_active (below) is a
# Gauge of who's *currently* trapped, with no Counter anywhere tracking activations
# over time the way ips_isolations_metric does for router isolation. Real gap, not
# just a naming redundancy -- kept as a proper per-device Counter instead of deleting it.
ips_tarpit_activations_total = Counter("home_ids_ips_tarpit_activations_total", "Total Layer-2 ARP/NDP tarpit activations executed", ["device", "hostname", "mac"])

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
# PHASE 18 FIX (REDUNDANT): fp_engine_stage1_hardstop_hits removed -- every call site
# that incremented it also incremented fp_engine_confirmed_threats_total in the same
# breath, always in lockstep, no code path fires one without the other. Kept the more
# semantically meaningful name.
fp_engine_stage2_lgbm_hits = Counter("home_ids_fp_stage2_lgbm_hits_total", "Alerts classified FP at Stage 2")
fp_engine_stage3_embed_hits = Counter("home_ids_fp_stage3_embed_hits_total", "Alerts classified FP at Stage 3")
# PHASE 18: added a "source" label (autonomous/operator/llm_validated) to both self-
# healing counters below -- this is the direct answer to "how much of the healing is
# autonomous vs human-approved," which the whole self-calibration system exists to grow
# over time. Fixed small enum, safe cardinality.
fp_engine_domains_immunized_total = Counter("home_ids_fp_domains_immunized_total", "Total unique eTLD+1 base domains added to the trust cache", ["source"])
# Dashboard-redesign fix: this counter used to fire identically for BOTH directions of
# _apply_sigma_shift() (widen on confirmed FP, tighten on confirmed threat), making it
# impossible to tell "this device got more lenient" from "this device got stricter" from
# the outside. Added "direction" (widen/tighten) -- backward compatible, existing
# `sum by (source)` queries are unaffected since Prometheus ignores an unreferenced label.
fp_engine_sigma_shifts_total = Counter("home_ids_fp_sigma_shifts_total", "Total automatic baseline sigma adjustments applied to devices (direction=widen: less sensitive after a confirmed FP; direction=tighten: more sensitive after a confirmed threat)", ["device", "hostname", "source", "direction"])

# ===========================================================================
# PHASE 18: Decision-Path Transparency (Brain 1 / HEE)
# ===========================================================================
# Which branch of decision_engine.py's decision order actually resolved each
# evaluation -- the direct "is the system getting smarter over time" signal: watching
# hard_stop/tier5 share shrink and benign share grow across weeks is exactly what
# autonomous healing is supposed to produce. Fixed 9-value enum, safe cardinality.
# tier5_confirmed/tier5_corroborated/tier5_uncorroborated split out 2026-08-29 (Gap 1
# flipped live) -- previously a single tier5_confirmed path covered all tier-5 hits
# regardless of rep.verified_ioc.
decision_path_total = Counter(
    "home_ids_decision_path_total",
    "Which decision-engine branch resolved each evaluation "
    "(hard_stop/tier5_confirmed/tier5_corroborated/tier5_uncorroborated/hypothesis_high/"
    "hypothesis_suspicious/tier4_unconfirmed/ml_anomaly/benign)",
    ["device", "hostname", "path"]
)

# ===========================================================================
# PHASE 18: Autonomous Self-Calibration Transparency
# ===========================================================================
# train_fp_classifier.py runs as a separate cron/thread process with no HTTP server of
# its own -- these are synced into the long-running pipeline process from
# state/autotune_stats.json (see core/metrics_sync.py's sync_relay_metrics()), the same
# relay pattern used for the Ollama and job-health metrics below.
autotune_global_threshold_effective = Gauge("home_ids_autotune_global_threshold_effective", "Live effective global fp_combined_suppress_threshold (config.yaml baseline, or lower if autonomously calibrated)")
autotune_global_threshold_baseline = Gauge("home_ids_autotune_global_threshold_baseline", "config.yaml's own fp_combined_suppress_threshold value, unaffected by any override")
autotune_device_threshold_effective = Gauge("home_ids_autotune_device_threshold_effective", "Live effective per-device suppress threshold, only set for devices with their own calibrated profile", ["device", "hostname"])
autotune_calibration_total = Gauge(
    "home_ids_autotune_calibration_total",
    "Cumulative calibration pass outcomes since state/autotune_stats.json existed "
    "(scope=global/device, outcome=applied/refused_ambiguous/insufficient_samples). "
    "A Gauge, not a Counter, by design -- it's re-synced from a periodic external "
    "snapshot rather than incremented in-process; refusals are as informative as "
    "applications here (proves the system isn't blindly loosening).",
    ["scope", "outcome"]
)
autotune_evidence_count = Gauge("home_ids_autotune_evidence_count", "Pooled correction sample count feeding the next calibration pass", ["scope", "kind"])
# PHASE 21-METRICS: ARP-sweep threshold calibration (train_fp_classifier.py's
# calibrate_arp_sweep_threshold()) is a SEPARATE bidirectional rule from the suppress-
# threshold one above -- kept as its own metrics rather than overloading the existing
# gauges' label shape (which would force every existing suppress-threshold call site to
# also start supplying a new disambiguating label, a bigger and riskier blast radius
# than three small parallel metrics).
autotune_arp_sweep_threshold_effective = Gauge("home_ids_autotune_arp_sweep_threshold_effective", "Live effective per-device arp_sweep_unique_targets_threshold, only set for devices with their own calibrated profile", ["device", "hostname"])
# Dashboard redesign fix: "hostname" added -- metrics_sync.py's sync_relay_metrics()
# already reads dev.get("hostname") into a local variable for the sibling
# arp_sweep_threshold_effective gauge right above, it just wasn't threaded through to
# these two as well. Without it, these couldn't be filtered by the $device dashboard
# variable (whose own values are hostnames, from label_values(home_ids_threat_confidence,
# hostname) -- same as every other per-device panel), only the fleet-wide table shown.
autotune_arp_sweep_calibration_total = Gauge("home_ids_autotune_arp_sweep_calibration_total", "Cumulative arp-sweep-threshold calibration pass outcomes per device (applied/no_change_needed/insufficient_samples)", ["device", "hostname", "outcome"])
autotune_arp_sweep_evidence_count = Gauge("home_ids_autotune_arp_sweep_evidence_count", "Per-device CONNECTION_ABUSE correction/confirmation counts feeding arp-sweep threshold calibration", ["device", "hostname", "kind"])

# ===========================================================================
# PHASE 21-METRICS: Reactive Capture (Fritzbox burst) Transparency
# ===========================================================================
# The whole reactive-capture subsystem (Phase C/D of the reactive-capture plan) had
# ZERO Prometheus visibility before this -- an operator watching Grafana had no way to
# see whether triggers were firing, being deferred by the shared hourly budget,
# succeeding, or failing at any stage.
reactive_capture_bursts_total = Counter(
    "home_ids_reactive_capture_bursts_total",
    "Reactive-capture trigger attempts (outcome=dispatched: budget allowed it and a "
    "burst actually ran in the background; outcome=deferred: shared hourly burst-COUNT "
    "budget was exhausted; outcome=deferred_bytes_budget: shared hourly aggregate-BYTES "
    "budget was exhausted, see Documentation/REACTIVE_CAPTURE_LOAD_ANALYSIS.md; "
    "outcome=deferred_concurrent: a burst was already in flight; outcome=deferred_disk_budget: "
    "the scratch-dir disk budget was exhausted and pruning couldn't recover enough space)",
    ["trigger_reason", "outcome"]
)
reactive_capture_bytes_total = Counter("home_ids_reactive_capture_bytes_total", "Cumulative raw AVM pcap bytes captured per radio", ["radio"])
reactive_capture_errors_total = Counter("home_ids_reactive_capture_errors_total", "Reactive-capture burst failures by stage", ["stage"])
reactive_capture_last_burst_timestamp = Gauge("home_ids_reactive_capture_last_burst_timestamp", "Unix timestamp of the most recently completed reactive-capture burst")
reactive_capture_dns_evasion_findings_total = Counter("home_ids_reactive_capture_dns_evasion_findings_total", "Total dns_evasion_anomaly findings produced across all devices by reactive-capture bursts")
reactive_capture_suricata_findings_total = Counter("home_ids_reactive_capture_suricata_findings_total", "Total suricata_signature_match findings produced across all devices by batch-mode Suricata scans of reactive-capture burst pcaps")
reactive_capture_stale_files_removed_total = Counter("home_ids_reactive_capture_stale_files_removed_total", "Orphaned capture files/directories removed by the periodic disk-safety sweep (process-crash recovery, not the normal per-burst cleanup path)")

# 2026-09-27 (Phase 2 of the autonomy-completion effort): the reactive-capture scratch
# dir had a rate/byte-per-hour limiter (above) but no actual disk-space awareness --
# confirmed via direct grep before writing this: zero uses of disk/statvfs/
# shutil.disk_usage anywhere in fritzbox_capture.py. These give it one: a hard ceiling
# on the scratch dir specifically (reject-when-full after prune-oldest-first fails to
# recover), separate from disk_budget_governor.py's own 20GB whole-stack budget, which
# explicitly treats this directory as monitor-only.
reactive_capture_scratch_bytes = Gauge("home_ids_reactive_capture_scratch_bytes", "Current total size in bytes of the reactive-capture scratch directory")
reactive_capture_scratch_pruned_total = Counter("home_ids_reactive_capture_scratch_pruned_total", "Files removed by the pre-dispatch scratch-dir disk-budget pruner (oldest-first), separate from the stale-file crash-recovery sweep above")
reactive_capture_degraded = Gauge("home_ids_reactive_capture_degraded", "1 if the scratch-dir disk budget is exhausted and pruning could not recover enough space for a new burst, 0 otherwise")

# ===========================================================================
# PHASE 21-METRICS: Local Confirmed-Intel Store Transparency (Phase D3)
# ===========================================================================
local_confirmed_intel_size = Gauge("home_ids_local_confirmed_intel_size", "Current non-expired entry count in the self-growing local confirmed-threat store", ["kind"])
local_confirmed_intel_hits_total = Counter("home_ids_local_confirmed_intel_hits_total", "Stage-1 hard-stops fired by a match against a PREVIOUSLY-confirmed IOC (a different device benefiting from another device's confirmed threat)")

# ===========================================================================
# PHASE 18: Ollama (Brain 3) Run Transparency
# ===========================================================================
# ollama_soc.py is also a separate cron process -- synced from state/ollama_run_stats.json.
ollama_last_run_timestamp = Gauge("home_ids_ollama_last_run_timestamp", "Unix timestamp of the most recently completed ollama_soc.py run")
ollama_calls_last_run = Gauge("home_ids_ollama_calls_last_run", "Fresh LLM calls made in the most recent run")
ollama_cache_hits_last_run = Gauge("home_ids_ollama_cache_hits_last_run", "Verdicts served from the 7-day cache without an LLM call in the most recent run")
ollama_deferred_last_run = Gauge("home_ids_ollama_deferred_last_run", "Patterns deferred to next run after hitting the per-run call cap")
ollama_validated_total = Gauge("home_ids_ollama_validated_total", "Cumulative Ollama verdicts by outcome since state/ollama_run_stats.json existed", ["verdict"])

# ===========================================================================
# PHASE 18: Scheduled-Job Health (all scripts/*.py cron jobs)
# ===========================================================================
# Synced from state/job_health.json, written by each script at the end of a successful
# run. Directly targets the exact class of silent-scheduling-bug already found once in
# this project (a job-key/filename mismatch that ran nothing for months with nothing
# surfacing it beyond a daemon log line nobody was watching) -- turns "is the system
# healthy" from "check state/scheduler.log by hand" into a Grafana staleness panel.
job_last_success_timestamp = Gauge("home_ids_job_last_success_timestamp", "Unix timestamp of each scheduled job's last successful completion", ["job"])
job_last_duration_seconds = Gauge("home_ids_job_last_duration_seconds", "Wall-clock duration of each scheduled job's last run", ["job"])
retro_hunt_findings_total = Gauge("home_ids_retro_hunt_findings_total", "Cumulative retroactive threat-intel matches found by retro_hunter.py since state/job_health.json existed")

# ===========================================================================
# PHASE 30: Two New Per-Device Learned Thresholds (conn_abuse/long_conn)
# ===========================================================================
# Same shape as autotune_arp_sweep_threshold_effective above -- these two thresholds
# (threat_signals.py's zeek_conn_abuse s0_rej_unique check and its zeek_long_conn
# max_duration check) are only ever corrected reactively, in-process, via
# fp_engine.py's mark_false_positive() -- but that function is called from the
# FastAPI webhook subprocess (middleware/routers/pihole_api.py), a SEPARATE process
# from the one running this registry. Synced via the device_fp_profiles.json relay
# in metrics_sync.py, same mtime-skip mechanism as autotune_stats.json/
# ollama_run_stats.json/job_health.json.
autotune_conn_abuse_threshold_effective = Gauge("home_ids_autotune_conn_abuse_threshold_effective", "Live effective per-device conn_abuse_unique_ip_threshold, only set for devices with their own reactively-corrected profile", ["device", "hostname"])
autotune_long_conn_threshold_effective = Gauge("home_ids_autotune_long_conn_threshold_effective", "Live effective per-device long_conn_duration_threshold, only set for devices with their own reactively-corrected profile", ["device", "hostname"])
# Generic per-key correction-count gauge covering EVERY apply_device_fp_profile() key
# (not just the two above) -- closes the "no source label on corrections" gap noted in
# context/metrics_audit_report_2026-08.md Sec.3 for the whole device-profile mechanism
# at once, not just these two thresholds.
# Dashboard redesign fix: "hostname" added, same reasoning as the two arp-sweep gauges
# above -- metrics_sync.py already reads entry.get("hostname") into a local variable for
# the sibling conn_abuse/long_conn gauges right above, just wasn't threaded through here.
autotune_device_profile_correction_total = Gauge("home_ids_autotune_device_profile_correction_total", "Cumulative reactive/calibration corrections applied to a device's learned-threshold profile via apply_device_fp_profile(), by threshold key and correction source", ["device", "hostname", "key", "set_by"])

# ===========================================================================
# Dashboard redesign: full per-device self-healing/self-learning transparency
# ===========================================================================
# Every self-adaptive per-device mechanism in the codebase that previously only
# produced a log line (or none at all) -- an audit found these while investigating why
# the autonomous-behavior dashboards had no true per-device drill-down.
transfer_learning_seeds_total = Counter("home_ids_transfer_learning_seeds_total", "New devices whose starting baselines were seeded from peer devices of the same device_type (cold-start transfer learning)", ["device_type"])
identity_merges_total = Counter("home_ids_identity_merges_total", "Retroactive device-identity merges: a fragmented orphan device_id folded into its canonical identity", ["device", "hostname"])
device_profile_discards_total = Counter("home_ids_device_profile_discards_total", "Per-device FP-calibration profiles discarded, by reason", ["reason"])
identity_reidentify_migrations_total = Counter("home_ids_identity_reidentify_migrations_total", "DHCP/JA4-fingerprint MAC-rotation re-identifications: a device kept its identity across a MAC change", ["device", "hostname"])
identity_reidentify_ambiguous_total = Counter("home_ids_identity_reidentify_ambiguous_total", "Re-identification candidates strong enough to log but below the merge-confidence bar -- a reactive capture is dispatched to try to resolve them", ["device", "hostname"])
baseline_poisoning_transitions_total = Counter("home_ids_baseline_poisoning_transitions_total", "Device baseline poisoning state transitions (direction=entered: risk score crossed the poisoning threshold, baseline ingestion froze; direction=recovered: dropped back below it)", ["device", "hostname", "direction"])
probation_transitions_total = Counter("home_ids_probation_transitions_total", "Device probation state transitions (direction=entered: new/reset baseline below the sample-count floor; direction=graduated: crossed it)", ["device", "hostname", "direction"])
device_type_reclassifications_total = Counter("home_ids_device_type_reclassifications_total", "A device's inferred device_type changed after its very first classification (e.g. the 'laptop' cold-start fallback replaced once a real hostname resolved)", ["device", "hostname", "to_type"])
# These 4 use "device" only (no "hostname") -- DeviceMLEngine (ml_engine.py) only ever
# stores its own device_id, not a hostname, so that's genuinely all that's available at
# the event site. Join against home_ids_threat_confidence's "device" label in Grafana if
# a hostname is needed for display.
ml_warmup_completions_total = Counter("home_ids_ml_warmup_completions_total", "Per-device anomaly model reached its warmup sample threshold and received its first fit", ["device"])
ml_retrain_events_total = Counter("home_ids_ml_retrain_events_total", "Per-device anomaly model retrain cycles (every N new samples past warmup)", ["device"])
ml_poisoning_rejections_total = Counter("home_ids_ml_poisoning_rejections_total", "Training samples rejected from a device's anomaly-model baseline during its post-confirmed-threat anti-poisoning window", ["device"])
ml_model_invalidations_total = Counter("home_ids_ml_model_invalidations_total", "A device's anomaly model was discarded and reset due to feature-shape drift (stale/incompatible model)", ["device"])
baseline_familiarity_entries_total = Gauge("home_ids_baseline_familiarity_entries_total", "Size of a device's learned port/ASN/domain behavioral-familiarity fingerprint (VERSION 11 per-device baseline)", ["device", "hostname"])
retro_hunt_findings_by_device = Gauge("home_ids_retro_hunt_findings_by_device", "Per-device breakdown of cumulative retroactive threat-intel matches found by retro_hunter.py", ["device", "hostname"])

# ===========================================================================
# PHASE 30: Persistence-Escalation Transparency
# ===========================================================================
# pipeline.py can escalate an alert's confidence/severity purely because the SAME
# uncorroborated signal kept recurring (decision["escalated_via_persistence"] = True),
# deliberately capped below every genuinely-corroborated HIGH path and excluded from
# authorizing IPS containment on its own (see pipeline.py's containment_decision_state
# override). No existing metric distinguishes "escalated by persistence alone" from
# "escalated by new independent evidence" -- this is that distinction, graphable.
persistence_escalation_total = Counter("home_ids_persistence_escalation_total", "Cumulative alerts whose confidence/state was escalated by mere signal persistence rather than new corroborating evidence, by device and underlying signature", ["device", "hostname", "signature"])

# ===========================================================================
# PHASE 30: Suricata Live Health
# ===========================================================================
# suricata_binary_health is the one-shot boot-time --build-info smoke test result
# (main.py) -- rarely changes, proves the binary/rules are usable at all.
# suricata_scan_total/suricata_last_success_timestamp are the live signal: every
# actual batch scan a reactive-capture burst dispatches (fritzbox_capture.py),
# turning "we ran Suricata" from a log claim into a graphable success rate over time.
suricata_binary_health = Gauge("home_ids_suricata_binary_health", "1 if Suricata's boot-time --build-info smoke test passed, 0 if it failed. Unset (absent) if reactive_capture_suricata_enabled is false")
suricata_scan_total = Counter("home_ids_suricata_scan_total", "Cumulative live Suricata batch-scan invocations from reactive-capture bursts, by outcome", ["outcome"])
suricata_last_success_timestamp = Gauge("home_ids_suricata_last_success_timestamp", "Unix timestamp of the most recently successful live Suricata batch scan")

# ===========================================================================
# PHASE 30: Pi-hole Gravity-List API Health
# ===========================================================================
# is_pihole_gravity_domain() (threat_intel.py) is queried live for CDN/telemetry
# domain recognition (threat_signals.py) -- previously zero Prometheus visibility,
# same "turn organic usage into a graphable fact" approach as the Suricata metrics
# above rather than a synthetic health ping.
pihole_gravity_queries_total = Counter("home_ids_pihole_gravity_queries_total", "Cumulative Pi-hole gravity-list API lookups by outcome", ["outcome"])
pihole_gravity_last_success_timestamp = Gauge("home_ids_pihole_gravity_last_success_timestamp", "Unix timestamp of the last successful (non-cached) Pi-hole gravity-list API response")
# ===========================================================================
# 2026-09-23: Argus-architecture observability (Documentation/ARGUS_OBSERVABILITY_PLAN.md)
# Every value below is set directly in this process from its real source -- no relay file.
# ===========================================================================
# CL-AFPE (false-positive filter) under cl_afpe_engine=argus. The home_ids_fp_* counters
# above were only ever written inside the legacy intelligence/fp_engine.py, which never
# runs once Argus CL-AFPE is live -- pipeline.py now sets them from the Argus verdict too.
cl_afpe_verdicts_total = Counter("home_ids_cl_afpe_verdicts_total", "Argus CL-AFPE verdicts by the stage that decided and the verdict it reached", ["stage", "verdict"])

# Per-device decision detail from the live Argus decision (same device labels as the
# other per-device gauges, purged with them).
decision_independent_sources_metric = Gauge("home_ids_decision_independent_sources", "Independent evidence sources behind this device's current Argus decision", _DEV_LABELS)
decision_evidence_families_metric = Gauge("home_ids_decision_evidence_families", "Distinct evidence families behind this device's current Argus decision", _DEV_LABELS)
decision_path_code_metric = Gauge("home_ids_decision_path_code", "Which Argus decision path produced this device's current verdict (stable code; see core/metrics_sync.py DECISION_PATH_CODES)", _DEV_LABELS)
reputation_tier_metric = Gauge("home_ids_reputation_tier", "Reputation tier of this device's current destination (intelligence/reputation/classifier.py): 0 local/own network, 1 trusted list, 2 known infrastructure (CDN/cloud), 3 unknown (neutral default), 4 weak/unconfirmed bad signal, 5 confirmed IOC", _DEV_LABELS)

# Health manager -- set in-process by core/health_manager.py every check cycle.
health_component_state = Gauge("home_ids_health_component_state", "Health-manager component state: 0 healthy, 1 degraded, 2 unhealthy, 3 safe mode, 4 recovery failed, -1 retired", ["component"])
health_recovery_attempts = Gauge("home_ids_health_recovery_attempts", "Self-heal attempts in the component's current back-off window", ["component"])
health_pressure_level = Gauge("home_ids_health_pressure_level", "Host resource pressure as classified by the health manager: 0 normal, 1 resource pressure, 2 conservation, 3 critical")

# 2026-09-27 (Phase 7 of the autonomy-completion effort): deterministic shadow
# evaluation -- compares what a still-in-canary autotune candidate would have
# decided against the real, live decision for the same cycle, without ever
# emitting an alert/mitigation action. See argus/shadow/sandbox.py.
shadow_eval_comparisons_total = Counter(
    "home_ids_shadow_eval_comparisons_total",
    "Shadow-vs-real decision comparisons by parameter and agreement outcome",
    ["parameter", "agree"],
)
shadow_eval_errors_total = Counter(
    "home_ids_shadow_eval_errors_total",
    "Shadow evaluation attempts that failed to produce a comparison (best-effort, never blocks the real decision)",
)
shadow_eval_paused = Gauge(
    "home_ids_shadow_eval_paused",
    "1 if shadow evaluation is currently paused (resource pressure), 0 otherwise",
)

# Argus evidence graph -- set by core/argus_metrics.py's read-only background exporter.
argus_alert_events_24h = Gauge("home_ids_argus_alert_events_24h", "Alert events in the last 24h by outcome (FIRED = published to you, SUPPRESSED_AUTONOMOUS = hidden by the false-positive filter, LOGGED_ONLY = recorded below the alert bar)", ["status"])
argus_alert_events_retained = Gauge("home_ids_argus_alert_events_retained", "Alert events currently retained in the evidence graph by outcome (survives restarts)", ["status"])
argus_decisions_24h = Gauge("home_ids_argus_decisions_24h", "Argus decisions in the last 24h by state", ["state"])
argus_incidents_active_24h = Gauge("home_ids_argus_incidents_active_24h", "Incidents with activity in the last 24h")
# The evidence graph stores no device names (only ids) -- per-device series below carry
# the device id only; dashboards attach the live hostname from the engine's own
# per-device metrics (e.g. `* on(device) group_left(hostname) home_ids_decision_state`).
autotune_value = Gauge("home_ids_autotune_value", "Currently promoted autotuned value, by parameter and scope (global / category = device type / device). target = device type for category scope, device id for device scope", ["parameter", "scope", "target"])
autotune_canary_value = Gauge("home_ids_autotune_canary_value", "Proposed autotune value still in its canary window (not yet promoted)", ["parameter", "scope", "target"])
autotune_config_value = Gauge("home_ids_autotune_config_value", "Hand-set config.yaml value an autotuned parameter falls back to", ["parameter"])
autotune_changes = Gauge("home_ids_autotune_changes", "Autotune changes retained in threshold_history by parameter, scope and status (canary / promoted / rolled_back / superseded)", ["parameter", "scope", "status"])
autotune_last_change_timestamp = Gauge("home_ids_autotune_last_change_timestamp", "Unix time of the most recent autotune event of each kind", ["status"])
cl_afpe_trust_entries = Gauge("home_ids_cl_afpe_trust_entries", "Learned CL-AFPE trust entries by destination class", ["destination_class"])
cl_afpe_trust_mean = Gauge("home_ids_cl_afpe_trust_mean", "Mean learned trust value (0..1) by destination class", ["destination_class"])
baseline_models = Gauge("home_ids_baseline_models", "Per-device Bayesian baseline models by kind", ["model_kind"])
population_priors = Gauge("home_ids_population_priors", "Population-prior pools by device type (cold-start baselines for new devices)", ["device_type"])
backtest_last_pass = Gauge("home_ids_backtest_last_pass", "1 if the most recent autotune backtest passed, 0 if it failed")
backtest_last_run_timestamp = Gauge("home_ids_backtest_last_run_timestamp", "Unix time the most recent autotune backtest finished")
containment_actions = Gauge("home_ids_containment_actions", "Containment actions retained in the evidence graph by type and status", ["action_type", "status"])
operator_actions = Gauge("home_ids_operator_actions", "Operator actions retained in the evidence graph by kind", ["action"])
argus_exporter_last_success_timestamp = Gauge("home_ids_argus_exporter_last_success_timestamp", "Unix time the evidence-graph exporter last completed a full pass")
argus_exporter_duration_seconds = Gauge("home_ids_argus_exporter_duration_seconds", "Wall time of the evidence-graph exporter's last pass")
# Per device (Master Threat Ledger), keyed by the graph's canonical device id.
device_alerts_fired_24h = Gauge("home_ids_device_alerts_fired_24h", "Alerts published for this device in the last 24h", ["device"])
device_alerts_suppressed_24h = Gauge("home_ids_device_alerts_suppressed_24h", "Alerts the false-positive filter suppressed for this device in the last 24h", ["device"])
device_learned_trust = Gauge("home_ids_device_learned_trust", "Mean CL-AFPE learned trust (0..1) for this device's own behaviour", ["device"])
device_baseline_regime_shifts = Gauge("home_ids_device_baseline_regime_shifts", "Behaviour regime changes (BOCPD changepoints) detected in this device's baselines", ["device"])
device_sigma_shift = Gauge("home_ids_device_sigma_shift", "Argus CL-AFPE sensitivity shift for this device (positive = more lenient after confirmed false positives)", ["device"])
