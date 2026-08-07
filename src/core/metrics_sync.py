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
    risk_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    ml_anomaly_metric, markov_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_ja4_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    safe_device_metric, probation_status_metric, baseline_poisoned_metric,
    query_rate_baseline_mean_metric, query_rate_threshold_limit_metric,
    ndr_doh_bypass_metric, ndr_lateral_moves_metric, ndr_jitter_c2_metric,
    ndr_exfil_z_metric, ndr_delta_exfil_metric, abuseipdb_risk_metric,
    virustotal_risk_metric, beaconing_volume_metric, jitter_cv_metric,
    zeek_status_metric, zeek_events_processed_metric, 
    ips_pihole_status, ips_router_status, ips_tarpit_status,
    ips_pihole_blocks_metric, ips_isolations_metric, ips_errors_metric,
    ndr_tcp_scan_metric, ndr_max_duration_metric, ndr_honeypot_hits_metric,
    ndr_lateral_events_total, geo_risk_metric, geo_hits_metric,
    geo_beacon_metric, asn_risk_metric, country_density_metric,
    geo_traffic_total, geo_queries_per_minute, geo_unique_domains,
    geo_entropy, geo_device_count, collector_lag_metric, alert_queue_metric,
    ml_model_loaded_metric, events_processed_metric,
    killchain_phase_metric, dns_txt_null_ratio_metric, suspicious_tld_ratio_metric,
    outbound_bytes_1h_metric, beaconing_c2_1h_metric, dns_tunneling_domains_metric,
    max_label_length_metric,
    ips_active_blocks_gauge, ips_queue_status_gauge, ips_dead_letter_gauge, ips_tarpit_active,
    ips_router_isolated_active
)

LOGGER = logging.getLogger("home_ids.metrics_sync")

_DEVICE_GAUGES = (
    risk_metric, query_rate_metric, unique_domains_metric, entropy_metric,
    blocked_ratio_metric, nxdomain_ratio_metric, suspicious_domains_metric,
    ml_anomaly_metric, markov_anomaly_metric, zscore_query_metric, zscore_entropy_metric,
    zscore_unique_metric, new_domains_metric, deep_domains_metric,
    nxdomain_tld_conc_metric, zscore_nxdomain_metric, zscore_blocked_metric,
    zscore_dga_metric, risk_velocity_metric, zeek_conn_count_metric,
    zeek_new_ips_metric, zeek_ja3_metric, zeek_ja4_metric, zeek_notices_metric,
    zeek_susp_ports_metric, ti_risk_metric, ti_match_metric,
    safe_device_metric, probation_status_metric, baseline_poisoned_metric,
    query_rate_baseline_mean_metric, query_rate_threshold_limit_metric,
    ndr_doh_bypass_metric, ndr_lateral_moves_metric, ndr_jitter_c2_metric,
    ndr_exfil_z_metric, ndr_delta_exfil_metric, abuseipdb_risk_metric,
    virustotal_risk_metric, beaconing_volume_metric, jitter_cv_metric,
    ndr_tcp_scan_metric, ndr_max_duration_metric, ndr_honeypot_hits_metric
)


class MetricsExporter:
    """
    Handles exporting and clearing Prometheus metrics for network devices,
    pipeline performance, and GeoIP traffic analysis.
    """

    def remove_device_metric_labels(self, dev_id: str, hostname: str, device_type: str, keep_safe_flag: bool = False) -> None:
        if not dev_id:
            return

        str_id = str(dev_id)

        for metric in _DEVICE_GAUGES:
            if keep_safe_flag and metric is safe_device_metric:
                continue
            try:
                with metric._lock:
                    keys_to_remove = [k for k in metric._metrics.keys() if k[0] == str_id]
                for k in keys_to_remove:
                    try:
                        metric.remove(*k)
                    except KeyError:
                        pass
            except Exception as exc:
                LOGGER.debug("Could not purge internal metric label for dev_id %s: %s", str_id, exc)

    def _purge_stale_device_labels(self, str_dev_id: str, current_host: str) -> None:
        if not str_dev_id:
            return
            
        for metric in _DEVICE_GAUGES:
            try:
                with metric._lock:
                    stale_keys = [k for k in metric._metrics.keys() if k[0] == str_dev_id and k[1] != current_host]
                for k in stale_keys:
                    try:
                        metric.remove(*k)
                    except KeyError:
                        pass
            except Exception:
                pass

    def garbage_collect_ips_metrics(self, ips_state: dict) -> None:
        try:
            valid_blocks = set(ips_state.get("blocked_domains", {}).keys())
            with ips_active_blocks_gauge._lock:
                stale_blocks = [k for k in ips_active_blocks_gauge._metrics.keys() if k[2] not in valid_blocks]
            for k in stale_blocks:
                try: ips_active_blocks_gauge.remove(*k)
                except KeyError: pass

            valid_retries = set(ips_state.get("retry_queue", {}).keys())
            with ips_queue_status_gauge._lock:
                stale_retries = [k for k in ips_queue_status_gauge._metrics.keys() if k[2] not in valid_retries]
            for k in stale_retries:
                try: ips_queue_status_gauge.remove(*k)
                except KeyError: pass

            valid_dead = set(ips_state.get("dead_letter", {}).keys())
            with ips_dead_letter_gauge._lock:
                stale_dead = [k for k in ips_dead_letter_gauge._metrics.keys() if k[2] not in valid_dead]
            for k in stale_dead:
                try: ips_dead_letter_gauge.remove(*k)
                except KeyError: pass
                
            valid_tarpit_macs = {meta.get("mac") for meta in ips_state.get("tarpit_targets", {}).values()}
            with ips_tarpit_active._lock:
                stale_tarpits = [k for k in ips_tarpit_active._metrics.keys() if k[2] not in valid_tarpit_macs]
            for k in stale_tarpits:
                try:
                    ips_tarpit_active.labels(*k).set(0.0)
                    ips_tarpit_active.remove(*k)
                except KeyError: pass

            valid_router_macs = set(ips_state.get("router_isolated_devices", {}).keys())
            with ips_router_isolated_active._lock:
                stale_routers = [k for k in ips_router_isolated_active._metrics.keys() if k[2] not in valid_router_macs]
            for k in stale_routers:
                try:
                    ips_router_isolated_active.labels(*k).set(0.0)
                    ips_router_isolated_active.remove(*k)
                except KeyError: pass
                
        except Exception as exc:
            LOGGER.debug("Failed to garbage collect IPS metrics: %s", exc)

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
        current_threshold_limit: float
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

            self._purge_stale_device_labels(str_dev_id, str_host)

            safe_device_metric.labels(str_dev_id, str_host, str_type).set(1.0 if is_safe else 0.0)
            baseline_poisoned_metric.labels(str_dev_id, str_host, str_type).set(1.0 if is_poisoned else 0.0)
            
            rate_baseline_n = sum(getattr(state.rate_baseline, "n", [0, 0])) if hasattr(state, "rate_baseline") else 0
            probation_status_metric.labels(str_dev_id, str_host, str_type).set(1.0 if rate_baseline_n < 288 else 0.0)

            risk_metric.labels(str_dev_id, str_host, str_type).set(risk_score)
            ml_anomaly_metric.labels(str_dev_id, str_host, str_type).set(ml_score)
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
            virustotal_risk_metric.labels(str_dev_id, str_host, str_type).set(vt_risk)

            zeek_conn_count_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_conn_count", 0))
            zeek_new_ips_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_new_ips", 0))
            zeek_ja3_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_ja3_malicious", 0))
            zeek_ja4_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_ja4_malicious", 0))
            zeek_notices_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_notices", 0))
            zeek_susp_ports_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_susp_ports", 0))

            ndr_doh_bypass_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_doh_bypass", 0))
            ndr_lateral_moves_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_lateral_moves", 0))
            ndr_jitter_c2_metric.labels(str_dev_id, str_host, str_type).set(features.get("beaconing_c2_count", 0))
            ndr_exfil_z_metric.labels(str_dev_id, str_host, str_type).set(features.get("outbound_bytes_z", 0.0))
            ndr_delta_exfil_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_outbound_bytes", 0.0))
            ndr_tcp_scan_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_s0_rej_count", 0))
            ndr_max_duration_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_max_duration", 0.0))
            ndr_honeypot_hits_metric.labels(str_dev_id, str_host, str_type).set(features.get("zeek_honeypot_hits", 0))

            beaconing_volume_metric.labels(str_dev_id, str_host, str_type).set(features.get("top_domain_ratio", 0.0))
            jitter_cv_metric.labels(str_dev_id, str_host, str_type).set(features.get("min_jitter_cv", 0.0))

            # Map killchain_phase string to numerical gauge (0=NORMAL, 1=RECON, 2=C2, 3=LATERAL, 4=EXFIL)
            phase_map = {"NORMAL": 0.0, "RECON": 1.0, "C2": 2.0, "LATERAL": 3.0, "EXFIL": 4.0}
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

            geo_hits_metric.labels(**_match_labels(geo_hits_metric)).inc()
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