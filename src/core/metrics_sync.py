"""
metrics_sync.py - Prometheus Telemetry Exporter & Registry Synchronization.

Isolates Prometheus metric updates from the core business and processing logic.
Handles per-device telemetry label synchronization, GeoIP metrics aggregation,
and pipeline health status metrics.

RECENT FIXES:
- FIXED (NULL ISLAND PREVENTION): Updated `_round_coord` to recognize `"unknown"` or 
  non-numeric coordinate strings and pass them through as `"unknown"` instead of coercing 
  them into `"0.0"`. This ensures unresolvable GeoIP lookups do not pollute Grafana maps.
"""

import logging
import math
from typing import Dict, Any

from metrics import (
    decision_independent_sources_metric, decision_evidence_families_metric,
    decision_path_code_metric, reputation_tier_metric,
    top_domain_risk_metric, threat_confidence_metric, anomaly_confidence_metric, decision_state_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    markov_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_ja4_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    safe_device_metric, probation_status_metric, baseline_poisoned_metric,
    query_rate_baseline_mean_metric, query_rate_threshold_limit_metric,
    ndr_doh_bypass_metric, ndr_lateral_moves_metric, ndr_jitter_c2_metric,
    ndr_exfil_z_metric, ndr_delta_exfil_metric, abuseipdb_risk_metric,
    beaconing_volume_metric, jitter_cv_metric,
    zeek_status_metric, zeek_events_processed_metric, 
    ips_pihole_status, ips_router_status, ips_tarpit_status,
    ips_pihole_blocks_metric, ips_isolations_metric, ips_errors_metric,
    ndr_tcp_scan_metric, ndr_max_duration_metric, ndr_honeypot_hits_metric,
    ndr_arp_sweep_metric, ndr_dns_evasion_ratio_metric,
    ndr_lateral_events_total, geo_risk_metric,
    geo_beacon_metric, asn_risk_metric, country_density_metric,
    geo_traffic_total, geo_queries_per_minute, geo_unique_domains,
    geo_entropy, geo_device_count, collector_lag_metric, alert_queue_metric,
    ml_model_loaded_metric, events_processed_metric,
    killchain_phase_metric, dns_txt_null_ratio_metric, suspicious_tld_ratio_metric,
    outbound_bytes_1h_metric, beaconing_c2_1h_metric, dns_tunneling_domains_metric,
    max_label_length_metric,
    ips_active_blocks_gauge, ips_queue_status_gauge, ips_dead_letter_gauge, ips_tarpit_active,
    ips_router_isolated_active,
    autotune_global_threshold_effective, autotune_global_threshold_baseline,
    autotune_device_threshold_effective, autotune_calibration_total, autotune_evidence_count,
    autotune_arp_sweep_threshold_effective, autotune_arp_sweep_calibration_total,
    autotune_arp_sweep_evidence_count,
    autotune_conn_abuse_threshold_effective, autotune_long_conn_threshold_effective,
    autotune_device_profile_correction_total,
    ollama_last_run_timestamp, ollama_calls_last_run, ollama_cache_hits_last_run,
    ollama_deferred_last_run, ollama_validated_total,
    job_last_success_timestamp, job_last_duration_seconds, retro_hunt_findings_total,
    geo_country_marker,
    baseline_poisoning_transitions_total, probation_transitions_total,
    baseline_familiarity_entries_total, retro_hunt_findings_by_device,
)
from core.country_centroids import country_centroid
import json
from pathlib import Path

LOGGER = logging.getLogger("home_ids.metrics_sync")

_DEVICE_GAUGES = (
    threat_confidence_metric, anomaly_confidence_metric, decision_state_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    markov_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_ja4_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    safe_device_metric, probation_status_metric, baseline_poisoned_metric,
    query_rate_baseline_mean_metric, query_rate_threshold_limit_metric,
    ndr_doh_bypass_metric, ndr_lateral_moves_metric, ndr_jitter_c2_metric,
    ndr_exfil_z_metric, ndr_delta_exfil_metric, abuseipdb_risk_metric,
    beaconing_volume_metric, jitter_cv_metric,
    ndr_tcp_scan_metric, ndr_max_duration_metric, ndr_honeypot_hits_metric,
    ndr_arp_sweep_metric, ndr_dns_evasion_ratio_metric,
    # BUGFIX (live Prometheus snapshot audit): these 7 are set with the identical
    # (dev_id, hostname, device_type) label pattern as every metric above, via the
    # same export_device_telemetry() call (see lines ~309-316) -- but were never
    # added to this tuple, so _purge_stale_device_labels() never cleaned up their
    # old hostname row when a dual/IPv6+IPv4-stack device's identity manager later
    # reassigns it a different IP-as-hostname fallback. Confirmed live: a device
    # showed a SINGLE row in threat_confidence (purged correctly) but THREE rows
    # in killchain_phase for the same device -- one per link-local/ULA/IPv4 address
    # it had been seen under -- purely because killchain_phase_metric was missing
    # from this list, not because of any real state difference.
    killchain_phase_metric, dns_txt_null_ratio_metric, suspicious_tld_ratio_metric,
    outbound_bytes_1h_metric, beaconing_c2_1h_metric, dns_tunneling_domains_metric,
    max_label_length_metric,
    baseline_familiarity_entries_total,
    decision_independent_sources_metric, decision_evidence_families_metric,
    decision_path_code_metric, reputation_tier_metric,
)

# Stable numeric codes for Argus decision paths (argus/decision/engine.py), so the path
# can be a Prometheus gauge value; Grafana value-maps each code back to plain words. New
# paths must be APPENDED (never renumbered) -- the codes are what history is stored as.
DECISION_PATH_CODES = {
    "benign": 0,
    "ml_anomaly": 1,
    "tier4_unconfirmed": 2,
    "hypothesis_suspicious": 3,
    "tier5_uncorroborated": 4,
    "hypothesis_high": 5,
    "geofence_uncorroborated": 6,
    "suricata_uncorroborated": 7,
    "tier5_corroborated": 8,
    "tier5_confirmed": 9,
    "hard_stop": 10,
}
DECISION_PATH_UNKNOWN_CODE = -1


class MetricsExporter:
    """
    Handles exporting and clearing Prometheus metrics for network devices,
    pipeline performance, and GeoIP traffic analysis.
    """

    def __init__(self):
        # mtime per relay file path -- lets sync_relay_metrics() skip re-parsing a file
        # that hasn't changed since the last cycle, mirroring config.py's own live-watcher
        # mtime-check pattern instead of re-reading 3 tiny files every ~2s for nothing.
        self._relay_mtimes: Dict[str, float] = {}
        # In-memory caches for #7/#8's transition-detection (dashboard redesign): the
        # underlying poisoned/probation flags are stateless per-cycle recomputes with no
        # memory of the previous value, so a transition (entered/recovered, entered/
        # graduated) can only be detected here by comparing against the last-seen value.
        # In-memory only (resets on service restart) -- these are informational counters,
        # not security-critical state, so losing one transition across a restart is fine.
        self._last_poisoned: Dict[str, bool] = {}
        self._last_probation: Dict[str, bool] = {}
        # 2026-09-23 (live incident, py-spy-confirmed): _get_metric_keys() calls
        # metric.collect() -- a full scan of EVERY currently-registered label
        # combination for that metric, across every device -- and pipeline.py's
        # _step() calls the *_purge_stale_*() methods below once PER DEVICE,
        # every cycle. That's O(devices) work inside an O(devices) loop: real
        # O(devices^2) work per cycle, times ~50 metrics in _DEVICE_GAUGES,
        # caught live stalling the main detection loop for 15-20s. Caching each
        # metric's collect() result for the duration of one export cycle turns
        # this into one real scan per metric per cycle (O(devices)) instead of
        # one per device (O(devices^2)) -- network/install-agnostic, no
        # assumption about device count or naming. Cleared by
        # begin_metrics_cycle(), which pipeline.py's _step() calls once before
        # the per-device loop starts (not per device) -- so a label that
        # becomes stale mid-cycle is caught on the VERY NEXT cycle (~2s later),
        # never permanently missed the way an incrementally-patched cache
        # (invalidated only on removal, not on every new .labels().set() call
        # scattered across ~50 call sites) could silently regress into exactly
        # the unbounded-label-leak bug this file was already patched for once
        # (see the killchain_phase_metric comment on _DEVICE_GAUGES above).
        self._metric_keys_cache: Dict[int, set] = {}
        self._last_purge_sig: Dict[str, tuple] = {}     # device -> (host, top domains) at its last label purge

    def begin_metrics_cycle(self) -> None:
        """Call once per detection cycle, before exporting any device's
        telemetry -- NOT once per device. See the cache comment in __init__."""
        self._metric_keys_cache = {}

    def _get_metric_keys(self, metric) -> set:
        cached = self._metric_keys_cache.get(id(metric))
        if cached is not None:
            return cached
        # A2 (2026-10-01): a labelled prometheus_client metric keeps its children in `_metrics`, keyed by the
        # label-value tuple in `_labelnames` order -- exactly the key built below from collect(). Reading the keys
        # directly skips building every sample (all buckets of every child), which profiling on .94 showed as a
        # steady share of the engine's CPU. collect() stays as the fallback for anything without that attribute.
        children = getattr(metric, "_metrics", None)
        if isinstance(children, dict):
            lock = getattr(metric, "_lock", None)
            if lock is not None:
                with lock:
                    keys = set(children.keys())
            else:
                keys = set(children.keys())
        else:
            keys = set()
            for mf in metric.collect():
                for sample in mf.samples:
                    keys.add(tuple(sample.labels[l] for l in metric._labelnames))
        self._metric_keys_cache[id(metric)] = keys
        return keys

    def _remove_and_uncache(self, metric, k: tuple) -> None:
        """metric.remove(*k) plus keeping this cycle's cached key set for
        `metric` consistent with the live registry -- without this, a
        removal wouldn't be reflected in _get_metric_keys() for the REST of
        this same cycle (the cache is only refreshed at the next
        begin_metrics_cycle()), so a later caller in the same cycle checking
        the same metric would see a key that's already gone from Prometheus
        itself."""
        try:
            metric.remove(*k)
        except KeyError:
            return
        cached = self._metric_keys_cache.get(id(metric))
        if cached is not None:
            cached.discard(k)

    def remove_device_metric_labels(self, dev_id: str, hostname: str, device_type: str, keep_safe_flag: bool = False) -> None:
        if not dev_id:
            return

        str_id = str(dev_id)

        for metric in _DEVICE_GAUGES:
            if keep_safe_flag and metric is safe_device_metric:
                continue
            try:
                keys_to_remove = [k for k in self._get_metric_keys(metric) if k[0] == str_id]
                for k in keys_to_remove:
                    self._remove_and_uncache(metric, k)
            except Exception as exc:
                LOGGER.debug("Could not purge internal metric label for dev_id %s: %s", str_id, exc)

    def _purge_stale_device_labels(self, str_dev_id: str, current_host: str) -> None:
        if not str_dev_id:
            return
            
        for metric in _DEVICE_GAUGES:
            try:
                stale_keys = [k for k in self._get_metric_keys(metric) if k[0] == str_dev_id and k[1] != current_host]
                for k in stale_keys:
                    self._remove_and_uncache(metric, k)
            except Exception:
                pass

    def _purge_stale_domain_labels(self, str_dev_id: str, current_host: str, active_domains: list) -> None:
        if not str_dev_id:
            return
        try:
            # top_domain_risk_metric has labels: device, hostname, device_type, domain
            stale_keys = [k for k in self._get_metric_keys(top_domain_risk_metric) if k[0] == str_dev_id and (k[1] != current_host or k[3] not in active_domains)]
            for k in stale_keys:
                self._remove_and_uncache(top_domain_risk_metric, k)
        except Exception:
            pass

    def garbage_collect_ips_metrics(self, ips_state: dict) -> None:
        try:
            valid_blocks = set(ips_state.get("blocked_domains", {}).keys())
            stale_blocks = [k for k in self._get_metric_keys(ips_active_blocks_gauge) if k[2] not in valid_blocks]
            for k in stale_blocks:
                self._remove_and_uncache(ips_active_blocks_gauge, k)

            valid_retries = set(ips_state.get("retry_queue", {}).keys())
            stale_retries = [k for k in self._get_metric_keys(ips_queue_status_gauge) if k[2] not in valid_retries]
            for k in stale_retries:
                self._remove_and_uncache(ips_queue_status_gauge, k)

            valid_dead = set(ips_state.get("dead_letter", {}).keys())
            stale_dead = [k for k in self._get_metric_keys(ips_dead_letter_gauge) if k[2] not in valid_dead]
            for k in stale_dead:
                self._remove_and_uncache(ips_dead_letter_gauge, k)

            valid_tarpit_macs = {meta.get("mac") for meta in ips_state.get("tarpit_targets", {}).values()}
            stale_tarpits = [k for k in self._get_metric_keys(ips_tarpit_active) if k[2] not in valid_tarpit_macs]
            for k in stale_tarpits:
                try:
                    ips_tarpit_active.labels(*k).set(0.0)
                except KeyError:
                    pass
                self._remove_and_uncache(ips_tarpit_active, k)

            valid_router_macs = set(ips_state.get("router_isolated_devices", {}).keys())
            stale_routers = [k for k in self._get_metric_keys(ips_router_isolated_active) if k[2] not in valid_router_macs]
            for k in stale_routers:
                try:
                    ips_router_isolated_active.labels(*k).set(0.0)
                    ips_router_isolated_active.remove(*k)
                except KeyError: pass
                
        except Exception as exc:
            LOGGER.debug("Failed to garbage collect IPS metrics: %s", exc)

    def _track_transition(self, cache: Dict[str, bool], device_id: str, hostname: str,
                           current: bool, entered_label: str, exited_label: str, metric) -> None:
        """Shared #7/#8 edge-detection helper. First-ever sighting of a device just seeds
        the cache and does NOT count as a transition -- otherwise every device would
        register a spurious "entered" event on the cycle right after a service restart
        (cache empty) or the moment it's first created."""
        previous = cache.get(device_id)
        cache[device_id] = current
        if previous is None or previous == current:
            return
        metric.labels(device=device_id, hostname=hostname, direction=(entered_label if current else exited_label)).inc()

    def export_device_telemetry(
        self,
        state: Any,
        features: Dict[str, Any],
        risk_score: float,
        ml_score: float,
        ti_risk: float,
        ti_match: int,
        abuse_risk: float,
        vt_risk: float,
        is_safe: bool,
        is_poisoned: bool,
        current_threshold_limit: float,
        decision: Dict[str, Any] = None,
        fp_engine: Any = None,
        reputation_tier: Any = None,
    ) -> None:
        try:
            str_dev_id = str(state.device_id)
            raw_host = str(state.hostname)
            client_ip = getattr(state, "client_ip", "unknown")
            str_type = str(state.device_type)
            current_hour = int(features.get("current_hour", 12))

            if raw_host.count('_') == 3 and all(p.isdigit() for p in raw_host.split('_')):
                raw_host = raw_host.replace('_', '.')

            if raw_host in ("unknown", client_ip):
                str_host = client_ip
            else:
                str_host = raw_host

            # Process top domains for this device
            top_domains = []
            if hasattr(state, "rolling") and hasattr(state.rolling, "domains"):
                top_domains = [domain for domain, count in state.rolling.domains.most_common(3)]
                
            # Stale labels only appear when a device's hostname / top domains change, so the (expensive, scans every
            # gauge's keys) purge runs only then -- not on every device every cycle.
            purge_sig = (str_host, tuple(top_domains))
            last_sig = self._last_purge_sig.get(str_dev_id)
            if last_sig != purge_sig:
                # A2: every device gauge carries the hostname, but only top_domain_risk carries domains -- a
                # chatty device's top-3 domains change most cycles, its hostname almost never.
                if last_sig is None or last_sig[0] != str_host:
                    self._purge_stale_device_labels(str_dev_id, str_host)
                self._purge_stale_domain_labels(str_dev_id, str_host, top_domains)
                if len(self._last_purge_sig) > 10000:
                    self._last_purge_sig.clear()
                self._last_purge_sig[str_dev_id] = purge_sig
            
            for dom in top_domains:
                top_domain_risk_metric.labels(str_dev_id, str_host, str_type, dom).set(ml_score)

            safe_device_metric.labels(str_dev_id, str_host, str_type).set(1.0 if is_safe else 0.0)
            baseline_poisoned_metric.labels(str_dev_id, str_host, str_type).set(1.0 if is_poisoned else 0.0)
            self._track_transition(self._last_poisoned, str_dev_id, str_host, is_poisoned,
                                    "entered", "recovered", baseline_poisoning_transitions_total)

            rate_baseline_n = sum(getattr(state.rate_baseline, "n", [0, 0])) if hasattr(state, "rate_baseline") else 0
            in_probation = rate_baseline_n < 288
            probation_status_metric.labels(str_dev_id, str_host, str_type).set(1.0 if in_probation else 0.0)
            self._track_transition(self._last_probation, str_dev_id, str_host, in_probation,
                                    "entered", "graduated", probation_transitions_total)

            if fp_engine is not None:
                baseline_familiarity_entries_total.labels(str_dev_id, str_host).set(
                    fp_engine.get_baseline_entry_count(str_dev_id)
                )

            if decision:
                threat_confidence_metric.labels(str_dev_id, str_host, str_type).set(decision.get("threat_confidence", 0.0))
                
                state_map = {"BENIGN": 0, "ANOMALOUS": 1, "SUSPICIOUS": 2, "HIGH": 3, "CRITICAL": 4}
                state_val = state_map.get(decision.get("state", "BENIGN"), 0)
                decision_state_metric.labels(str_dev_id, str_host, str_type).set(state_val)
                decision_independent_sources_metric.labels(str_dev_id, str_host, str_type).set(
                    float(decision.get("independent_sources", 0) or 0))
                decision_evidence_families_metric.labels(str_dev_id, str_host, str_type).set(
                    float(len(decision.get("evidence_families") or [])))
                decision_path_code_metric.labels(str_dev_id, str_host, str_type).set(
                    DECISION_PATH_CODES.get(decision.get("decision_path") or "benign", DECISION_PATH_UNKNOWN_CODE))

            if isinstance(reputation_tier, (int, float)):
                reputation_tier_metric.labels(str_dev_id, str_host, str_type).set(float(reputation_tier))

            anomaly_confidence_metric.labels(str_dev_id, str_host, str_type).set(ml_score)
            markov_anomaly_metric.labels(str_dev_id, str_host, str_type).set(features.get("markov_anomaly", 0.0))

            risk_baseline = getattr(state, "risk_baseline", None)
            risk_velocity = 0.0
            if risk_baseline:
                rmean, rvar, rinit, rn = risk_baseline.get_stats(current_hour)
                if rinit and rn >= 50:
                    risk_velocity = max(-10.0, min(10.0, (risk_score - rmean) / math.sqrt(max(rvar, 1e-4))))
            risk_velocity_metric.labels(str_dev_id, str_host, str_type).set(risk_velocity)

            query_rate = features.get("query_rate", 0.0)
            mean_rate, _, _, _ = state.rate_baseline.get_stats(current_hour) if hasattr(state, "rate_baseline") else (0.0, 0, False, 0)
            
            query_rate_metric.labels(str_dev_id, str_host, str_type).set(query_rate)
            query_rate_baseline_mean_metric.labels(str_dev_id, str_host, str_type).set(mean_rate)
            query_rate_threshold_limit_metric.labels(str_dev_id, str_host, str_type).set(current_threshold_limit)

            unique_domains_metric.labels(str_dev_id, str_host, str_type).set(features.get("unique_domains", 0))
            entropy_metric.labels(str_dev_id, str_host, str_type).set(features.get("entropy_avg", 0.0))
            blocked_ratio_metric.labels(str_dev_id, str_host, str_type).set(features.get("blocked_ratio", 0.0))
            nxdomain_ratio_metric.labels(str_dev_id, str_host, str_type).set(features.get("nxdomain_ratio", 0.0))
            suspicious_domains_metric.labels(str_dev_id, str_host, str_type).set(features.get("suspicious_domains", 0))
            new_domains_metric.labels(str_dev_id, str_host, str_type).set(features.get("new_domains", 0.0))
            deep_domains_metric.labels(str_dev_id, str_host, str_type).set(features.get("deep_domains", 0.0))
            nxdomain_tld_conc_metric.labels(str_dev_id, str_host, str_type).set(features.get("nxdomain_tld_conc", 0.0))

            zscore_query_metric.labels(str_dev_id, str_host, str_type).set(features.get("query_rate_z", 0.0))
            zscore_entropy_metric.labels(str_dev_id, str_host, str_type).set(features.get("entropy_avg_z", 0.0))
            zscore_unique_metric.labels(str_dev_id, str_host, str_type).set(features.get("unique_domains_z", 0.0))
            zscore_nxdomain_metric.labels(str_dev_id, str_host, str_type).set(features.get("nxdomain_ratio_z", 0.0))
            zscore_blocked_metric.labels(str_dev_id, str_host, str_type).set(features.get("blocked_ratio_z", 0.0))
            zscore_dga_metric.labels(str_dev_id, str_host, str_type).set(features.get("suspicious_domains_z", 0.0))

            ti_risk_metric.labels(str_dev_id, str_host, str_type).set(ti_risk)
            ti_match_metric.labels(str_dev_id, str_host, str_type).set(ti_match)
            abuseipdb_risk_metric.labels(str_dev_id, str_host, str_type).set(abuse_risk)

            zeek_conn_count_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_conn_count", 0))
            zeek_new_ips_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_new_ips", 0))
            zeek_ja3_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_ja3_malicious", 0))
            zeek_ja4_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_ja4_malicious", 0))
            zeek_notices_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_notices", 0))
            zeek_susp_ports_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_susp_ports", 0))

            ndr_doh_bypass_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_doh_bypass", 0))
            ndr_lateral_moves_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_lateral_moves", 0))
            ndr_jitter_c2_metric.labels(str_dev_id, str_host, str_type).set(features.get("beaconing_c2_count", 0))
            outbound_bytes_z = max(-10.0, min(10.0, features.get("outbound_bytes_z", 0.0)))
            ndr_exfil_z_metric.labels(str_dev_id, str_host, str_type).set(outbound_bytes_z)
            ndr_delta_exfil_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_outbound_bytes", 0.0))
            ndr_tcp_scan_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_s0_rej_count", 0))
            ndr_max_duration_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_max_duration", 0.0))
            ndr_honeypot_hits_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_honeypot_hits", 0))
            ndr_arp_sweep_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_arp_sweep_count", 0))
            ndr_dns_evasion_ratio_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_dns_evasion_ratio", 0.0))

            beaconing_volume_metric.labels(str_dev_id, str_host, str_type).set(features.get("top_domain_ratio", 0.0))
            jitter_cv_metric.labels(str_dev_id, str_host, str_type).set(features.get("min_jitter_cv", 0.0))

            # Map killchain_phase string to numerical gauge (0=NORMAL, 1=RECON, 2=C2, 3=LATERAL, 4=EXFIL).
            # VERSION 11 (P3, review #22): dns_features.py's _determine_killchain_phase()
            # now returns SUSPECTED_-prefixed labels (display-honesty fix, not a
            # detection-threshold change) -- keys here updated to match.
            phase_map = {"NORMAL": 0.0, "SUSPECTED_RECON": 1.0, "SUSPECTED_C2": 2.0, "SUSPECTED_LATERAL": 3.0, "SUSPECTED_EXFIL": 4.0}
            kc_phase_val = phase_map.get(features.get("killchain_phase", "NORMAL"), 0.0)
            killchain_phase_metric.labels(str_dev_id, str_host, str_type).set(kc_phase_val)

            dns_txt_null_ratio_metric.labels(str_dev_id, str_host, str_type).set(features.get("dns_txt_null_ratio", 0.0))
            suspicious_tld_ratio_metric.labels(str_dev_id, str_host, str_type).set(features.get("suspicious_tld_ratio", 0.0))
            outbound_bytes_1h_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_outbound_bytes_1h", 0.0))
            beaconing_c2_1h_metric.labels(str_dev_id, str_host, str_type).set(features.get("beaconing_c2_1h", 0))
            dns_tunneling_domains_metric.labels(str_dev_id, str_host, str_type).set(features.get("dns_tunneling_domains", 0))
            max_label_length_metric.labels(str_dev_id, str_host, str_type).set(features.get("max_label_length", 0))

        except Exception as exc:
            LOGGER.error("Failed to export Prometheus device metrics for %s: %s", getattr(state, "hostname", "unknown"), exc)

    def record_lateral_target(self, dev_id: str, hostname: str, client_ip: str, dst_ip: str, dst_port: int) -> None:
        try:
            ndr_lateral_events_total.labels(str(dev_id), str(hostname)).inc()
        except Exception as exc:
            LOGGER.debug("Could not export lateral target metric: %s", exc)

    def export_geoip_telemetry(self, geo_info: dict, asn_info: dict, risk: float = 0.0, features: dict = None, alert_threshold: float = 5.0) -> None:
        try:
            if not geo_info:
                return

            def _get_val(obj, key, default="UNKNOWN"):
                if isinstance(obj, dict):
                    return str(obj.get(key) or default)
                return str(getattr(obj, key, default))

            def _round_coord(val):
                if val is None or str(val).lower() in ("unknown", "n/a", "none", ""):
                    return "unknown"
                try: 
                    return str(round(float(val), 1))
                except (ValueError, TypeError): 
                    return "unknown"

            country_val = _get_val(geo_info.country, "iso_code") if hasattr(geo_info, "country") else _get_val(geo_info, "country", "UNKNOWN")
            city_val = _get_val(geo_info.city, "name") if hasattr(geo_info, "city") else _get_val(geo_info, "city", "UNKNOWN")
            continent_val = _get_val(geo_info.continent, "code") if hasattr(geo_info, "continent") else _get_val(geo_info, "continent", "UNKNOWN")
            
            lat = "unknown"
            lon = "unknown"
            if hasattr(geo_info, "location"):
                lat = _round_coord(_get_val(geo_info.location, "latitude", "unknown"))
                lon = _round_coord(_get_val(geo_info.location, "longitude", "unknown"))
            elif isinstance(geo_info, dict):
                lat = _round_coord(geo_info.get("latitude", "unknown"))
                lon = _round_coord(geo_info.get("longitude", "unknown"))

            asn_val = _get_val(asn_info, "autonomous_system_number") if asn_info else "UNKNOWN"
            org_val = _get_val(asn_info, "autonomous_system_organization") if asn_info else "UNKNOWN"

            master_labels = {
                "country": country_val,
                "city": city_val,
                "continent": continent_val,
                "asn": asn_val,
                "org": org_val,
                "latitude": lat,
                "longitude": lon
            }

            def _match_labels(metric):
                return {k: master_labels.get(k, "UNKNOWN") for k in metric._labelnames}

            geo_traffic_total.labels(**_match_labels(geo_traffic_total)).inc()
            
            if features:
                geo_queries_per_minute.labels(**_match_labels(geo_queries_per_minute)).set(features.get("query_rate", 0.0))
                geo_unique_domains.labels(**_match_labels(geo_unique_domains)).set(features.get("unique_domains", 0.0))
                geo_entropy.labels(**_match_labels(geo_entropy)).set(features.get("entropy_avg", 0.0))
                geo_device_count.labels(**_match_labels(geo_device_count)).set(1.0)

            if risk >= alert_threshold:  
                geo_risk_metric.labels(**_match_labels(geo_risk_metric)).set(risk)
                asn_risk_metric.labels(**_match_labels(asn_risk_metric)).set(risk)
                country_density_metric.labels(**_match_labels(country_density_metric)).set(risk)
                geo_beacon_metric.labels(**_match_labels(geo_beacon_metric)).inc()

                # PHASE 18: static-centroid coordinates -- deliberately NOT master_labels'
                # own lat/lon (that's the actual resolved IP's rounded-but-still-unbounded
                # coordinates, the exact thing removed from geo_risk_metric for cardinality).
                # country_centroid() returns (None, None) for a code not in the ~195-country
                # table -- skip the marker entirely rather than plot a fabricated point.
                centroid_lat, centroid_lon = country_centroid(country_val)
                if centroid_lat is not None:
                    geo_country_marker.labels(country=country_val, latitude=centroid_lat, longitude=centroid_lon).set(risk)

        except Exception as exc:
            LOGGER.error("Failed to dynamically map and export GeoIP telemetry metric: %s", exc)

    def export_pipeline_health(
        self,
        zeek_online: bool,
        zeek_events_count: int,
        collector_lag: float,
        events_processed: int,
        alert_queue_size: int,
        ml_model_loaded: bool
    ) -> None:
        try:
            zeek_status_metric.set(1.0 if zeek_online else 0.0)
            zeek_events_processed_metric.inc(zeek_events_count)
            collector_lag_metric.set(collector_lag)
            events_processed_metric.inc(events_processed)
            alert_queue_metric.set(alert_queue_size)
            ml_model_loaded_metric.set(1 if ml_model_loaded else 0)
        except Exception as exc:
            LOGGER.error("Failed to export pipeline health metrics: %s", exc)

    def _read_relay_file(self, path: Path) -> dict:
        """Reads a small JSON relay file written by a separate cron process. Returns {}
        if the file is missing, invalid, or unchanged since the last read -- callers
        should treat an empty dict as "nothing new to sync", not "reset to zero"."""
        try:
            mtime = path.stat().st_mtime
        except OSError:
            return {}
        if self._relay_mtimes.get(str(path)) == mtime:
            return {}
        self._relay_mtimes[str(path)] = mtime
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            LOGGER.debug("Failed to parse relay file %s: %s", path, exc)
            return {}

    def sync_relay_metrics(self, state_dir: str) -> None:
        """Syncs Prometheus gauges from the small JSON stats files written by
        ollama_soc.py, train_fp_classifier.py, and every scripts/*.py cron job -- all
        separate short-lived processes with no HTTP server of their own, so this relay
        is how their activity becomes visible to Prometheus at all (they can't just call
        .set() themselves; nothing would ever scrape that process's registry). Cheap to
        call every pipeline cycle -- each file is only re-parsed when its mtime changes.
        """
        base = Path(state_dir)

        autotune = self._read_relay_file(base / "autotune_stats.json")
        if autotune:
            try:
                g = autotune.get("global", {})
                if "effective" in g:
                    autotune_global_threshold_effective.set(g["effective"])
                if "baseline" in g:
                    autotune_global_threshold_baseline.set(g["baseline"])
                for outcome, count in g.get("calibration_outcomes", {}).items():
                    autotune_calibration_total.labels(scope="global", outcome=outcome).set(count)
                for kind, count in g.get("evidence_counts", {}).items():
                    autotune_evidence_count.labels(scope="global", kind=kind).set(count)

                for dev_id, dev in autotune.get("devices", {}).items():
                    hostname = dev.get("hostname", "unknown")
                    if "effective" in dev:
                        autotune_device_threshold_effective.labels(device=dev_id, hostname=hostname).set(dev["effective"])
                    for outcome, count in dev.get("calibration_outcomes", {}).items():
                        autotune_calibration_total.labels(scope="device", outcome=outcome).set(count)
                    for kind, count in dev.get("evidence_counts", {}).items():
                        autotune_evidence_count.labels(scope="device", kind=kind).set(count)
                    # PHASE 21-METRICS: arp_sweep_* keys are separate from the
                    # suppress-threshold fields above (calibrate_arp_sweep_threshold()
                    # is a genuinely different, bidirectional rule -- see
                    # train_fp_classifier.py) and were written into
                    # autotune_stats.json this session but never synced to Prometheus.
                    if "arp_sweep_effective" in dev:
                        autotune_arp_sweep_threshold_effective.labels(device=dev_id, hostname=hostname).set(dev["arp_sweep_effective"])
                    for outcome, count in dev.get("arp_sweep_calibration_outcomes", {}).items():
                        autotune_arp_sweep_calibration_total.labels(device=dev_id, hostname=hostname, outcome=outcome).set(count)
                    for kind, count in dev.get("arp_sweep_evidence_counts", {}).items():
                        autotune_arp_sweep_evidence_count.labels(device=dev_id, hostname=hostname, kind=kind).set(count)
            except Exception as exc:
                LOGGER.debug("Failed to sync autotune relay metrics: %s", exc)

        ollama = self._read_relay_file(base / "ollama_run_stats.json")
        if ollama:
            try:
                if "last_run" in ollama:
                    ollama_last_run_timestamp.set(ollama["last_run"])
                ollama_calls_last_run.set(ollama.get("calls_made", 0))
                ollama_cache_hits_last_run.set(ollama.get("cache_hits", 0))
                ollama_deferred_last_run.set(ollama.get("deferred", 0))
                for verdict, count in ollama.get("validated_totals", {}).items():
                    ollama_validated_total.labels(verdict=verdict).set(count)
            except Exception as exc:
                LOGGER.debug("Failed to sync Ollama relay metrics: %s", exc)

        # PHASE 30: device_fp_profiles.json is fp_engine.py's own write-through file for
        # EVERY per-device learned threshold (written from whichever process calls
        # apply_device_fp_profile() -- the FastAPI webhook subprocess for reactive
        # corrections, or the train_fp_classifier.py/ollama_soc.py cron processes) --
        # only the two newest keys (conn_abuse/long_conn) are synced here since every
        # other key already has its own dedicated, correctly-relayed metric elsewhere
        # (fp_combined_suppress_threshold via autotune_stats.json's "effective" field,
        # arp_sweep_unique_targets_threshold via its "arp_sweep_effective" field above).
        profiles = self._read_relay_file(base / "device_fp_profiles.json")
        if profiles:
            try:
                _profile_key_gauges = {
                    "conn_abuse_unique_ip_threshold": autotune_conn_abuse_threshold_effective,
                    "long_conn_duration_threshold": autotune_long_conn_threshold_effective,
                }
                for dev_id, profile in profiles.items():
                    for key, gauge in _profile_key_gauges.items():
                        entry = profile.get(key)
                        if not entry or "value" not in entry:
                            continue
                        hostname = entry.get("hostname") or "unknown"
                        gauge.labels(device=dev_id, hostname=hostname).set(entry["value"])
                        autotune_device_profile_correction_total.labels(
                            device=dev_id, hostname=hostname, key=key, set_by=entry.get("set_by", "unknown")
                        ).set(entry.get("correction_count", 0))
            except Exception as exc:
                LOGGER.debug("Failed to sync device-FP-profile relay metrics: %s", exc)

        jobs = self._read_relay_file(base / "job_health.json")
        if jobs:
            try:
                for job_name, meta in jobs.items():
                    if "last_success" in meta:
                        job_last_success_timestamp.labels(job=job_name).set(meta["last_success"])
                    if "duration_seconds" in meta:
                        job_last_duration_seconds.labels(job=job_name).set(meta["duration_seconds"])
                    if job_name == "retro_hunter" and "findings_count" in meta:
                        retro_hunt_findings_total.set(meta["findings_count"])
                    if job_name == "retro_hunter" and isinstance(meta.get("findings_by_device"), dict):
                        for dev_id, entry in meta["findings_by_device"].items():
                            if not isinstance(entry, dict) or "count" not in entry:
                                continue
                            retro_hunt_findings_by_device.labels(
                                device=dev_id, hostname=entry.get("hostname", "unknown")
                            ).set(entry["count"])
            except Exception as exc:
                LOGGER.debug("Failed to sync job-health relay metrics: %s", exc)
