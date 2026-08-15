"""
pipeline.py – Core Engine Execution Loop & Component Orchestrator.

RECENT ARCHITECTURAL FIXES:
- FIXED (MEMORY LEAK / GHOST RISK): Added rigorous time-based pruning for `state.rolling.domains` 
  and `state.rolling.events` inside the main execution loop. Prevents extreme risk scores from 
  permanently locking due to historical domains failing to age out.
- ADDED (LOGGING): Debug events tracked at pipeline start, loop cycle, scoring, and metrics export.
- FIXED (ML MIGRATION SYNC): Passed `self.ml_registry` directly into identity processing 
  so machine learning models are flawlessly synchronized whenever statistical baselines 
  are migrated to a new identity anchor.
"""

import logging
import math
import time
from pathlib import Path
from prometheus_client import start_http_server

from utils import sanitize_hostname, is_telemetry_domain, _is_cdn_or_cloud_domain, entropy as compute_entropy
from core.state import BoundedSet
from core.state_guard import StateManager
from core.identity import DeviceIdentityManager
from core.metrics_sync import MetricsExporter
from extractors.dns_features import FeatureExtractor, PiHoleCollector
from extractors.zeek_features import ZeekCollector, ZeekFeatureExtractor
from intelligence.hypotheses.evidence import EvidenceStore, Evidence
from intelligence.reputation.classifier import ReputationClassifier
from intelligence.detectors.dns_behavior import DNSBehaviorDetector
from intelligence.detectors.zeek_network import ZeekNetworkDetector
from core.decision_engine import DecisionEngine, DecisionState
from mitigation.alerts import AlertManager, AlertJSONWriter
from intelligence.ollama_analyzer import OllamaAnalyzer
from mitigation.ips import IPSMitigator
from intelligence.threat_intel import ThreatIntel, AbuseIPDB, VirusTotalClient
from intelligence.geoip import GeoIPEngine
from intelligence.ml_engine import MLRegistry
from intelligence.fp_engine import AutonomousFPEngine  # CL-AFPE: Closed-Loop Autonomous FP Engine

from metrics import alerts_total, ti_ioc_hits_total, ips_pihole_status, ips_router_status, ips_tarpit_status, integration_status_metric, honeypot_probes_total

LOGGER = logging.getLogger("home_ids.pipeline")

# Real DNS status classifications aligned with dns_features.py
BLOCKED_STATUSES = {1, 4, 5, 6, 7, 8, 10}
NXDOMAIN_STATUSES = {3, 12, 13}


def classify_payload_size(bytes_count: int) -> str:
    if bytes_count == 0: return "0 B (Header/Control Ping)"
    elif bytes_count < 128: return f"{bytes_count} B (Standard DNS/Control Packet)"
    elif bytes_count < 1024: return f"{bytes_count} B (Small Payload / API Metadata)"
    elif bytes_count < 1024 * 1024: return f"{bytes_count / 1024.0:.1f} KB (Medium Data Transfer)"
    elif bytes_count < 1024 * 1024 * 1024: return f"{bytes_count / (1024.0 * 1024.0):.2f} MB (Large Payload Transfer)"
    else: return f"{bytes_count / (1024.0 * 1024.0 * 1024.0):.2f} GB (Massive Bulk Exfiltration Risk)"


def classify_service(port: int, proto: str = "TCP") -> str:
    known_ports = {
        53: "DNS", 80: "HTTP", 443: "HTTPS", 137: "NetBIOS Name", 138: "NetBIOS Datagram", 139: "NetBIOS Session",
        445: "SMB", 22: "SSH", 3389: "RDP", 1900: "SSDP / UPnP", 5353: "mDNS", 8080: "HTTP Alternate",
        8443: "HTTPS Alternate", 123: "NTP", 67: "DHCP Server", 68: "DHCP Client", 1883: "MQTT", 853: "DoT",
    }
    return known_ports.get(port, "Control / ICMP Ping" if port == 0 else f"{proto.upper()} Service")


class EnginePipeline:
    def __init__(
        self, config, state_manager: StateManager = None, ti_engine: ThreatIntel = None, 
        ml_registry: MLRegistry = None, geoip_engine: GeoIPEngine = None, 
        ips_mitigator: IPSMitigator = None, pihole_collector: PiHoleCollector = None, 
        shared_alert_writer: AlertJSONWriter = None,
    ):
        self.config = config
        self.running = False

        LOGGER.debug("Activating configuration file live-watcher daemon.")
        if hasattr(self.config, "start_watcher"):
            self.config.start_watcher(interval=10.0)

        state_path = self.config.get("state_path", "state/ids_state.json")
        state_dir = Path(state_path).parent
        state_dir.mkdir(parents=True, exist_ok=True)
        
        self.state_manager = state_manager or StateManager(state_path=state_path, max_devices=int(self.config.get("max_device_states", 5000)))
        if state_manager is None:
            self.state_manager.load_from_disk(alpha=float(self.config.get("baseline_alpha", 0.05)))
            
        self.identity_manager = DeviceIdentityManager(self.state_manager, self.config)

        self.ti_engine = ti_engine
        self.ml_registry = ml_registry
        if self.ml_registry: self.ml_registry.load_models()
        
        self.geoip_engine = geoip_engine or GeoIPEngine(db_path=self.config.get("geoip_db", str(state_dir / "GeoLite2-City.mmdb")), asn_db_path=self.config.get("geoip_asn_db", ""))

        cache_dir = state_dir / "ti_cache"
        abuse_key = self.config.get("abuseipdb_api_key", "")
        self.abuseipdb = AbuseIPDB(api_key=abuse_key, cache_dir=cache_dir, refresh_interval=int(self.config.get("ti_refresh_interval", 3600)))
        self.abuseipdb.start_refresh_thread()
        if abuse_key:
            LOGGER.info("AbuseIPDB integration activated successfully.")
            integration_status_metric.labels("abuseipdb").set(1)
        else:
            integration_status_metric.labels("abuseipdb").set(0)
            
        vt_key = self.config.get("virustotal_api_key", "")
        self.virustotal = VirusTotalClient(api_key=vt_key, cache_dir=cache_dir)
        if vt_key:
            LOGGER.info("VirusTotal integration activated successfully.")
            integration_status_metric.labels("virustotal").set(1)
        else:
            integration_status_metric.labels("virustotal").set(0)
            
        if self.ti_engine and self.ti_engine.otx_api_key:
            LOGGER.info("AlienVault OTX integration activated successfully.")
            integration_status_metric.labels("otx").set(1)
        else:
            integration_status_metric.labels("otx").set(0)

        self.dns_extractor = FeatureExtractor()
        safe_ips = set(self.config.get("safe_ips", []))
        safe_patterns = set(self.config.get("safe_host_patterns", []))

        honeypot_ips = set(self.config.get("honeypot_ips", []))
        if bool(self.config.get("ips_enabled", True)) and not honeypot_ips and bool(self.config.get("ips_router_enabled", False)):
            LOGGER.warning("⚠️ IPS router isolation is enabled but no honeypot IPs are configured. Router isolation will remain inert until honeypot_ips is populated.")
        self.zeek_fx = ZeekFeatureExtractor(
            home_subnets=[self.config.get("home_subnet", "192.168.1.0/24")],
            ti_engine=self.ti_engine, geoip_engine=self.geoip_engine,
            safe_ips=safe_ips, honeypot_ips=honeypot_ips, safe_patterns=safe_patterns,
        )

        self.zeek_collector = ZeekCollector(log_dir=self.config.get("zeek_log_dir", "/opt/zeek/logs/current"), poll_interval=float(self.config.get("poll_interval", 2.0)), state_dir=state_dir)
        self.pihole_collector = pihole_collector or PiHoleCollector(db_path=self.config.get("pihole_db", "/etc/pihole/pihole-FTL.db"), lookback_seconds=int(self.config.get("startup_lookback_seconds", 300)), excluded_ips=safe_ips, excluded_patterns=safe_patterns)

        self.evidence_store = EvidenceStore()
        self.rep_classifier = ReputationClassifier()
        self.dns_detector = DNSBehaviorDetector()
        self.zeek_detector = ZeekNetworkDetector()
        self.decision_engine = DecisionEngine()
        self.alert_writer = shared_alert_writer or AlertJSONWriter(path=self.config.get("alert_json_path", str(state_dir / "alerts.json")), max_bytes=int(self.config.get("alert_json_max_bytes", 1073741824)))
        self.alert_manager = AlertManager(
            token=self.config.get("telegram_token", ""), 
            chat_id=self.config.get("telegram_chat_id", ""), 
            enabled=bool(self.config.get("telegram_enabled", False))
        )

        if self.config.get("telegram_token") and bool(self.config.get("telegram_enabled", False)):
            interactive = "ENABLED" if self.config.get("interactive_blocking_enabled", False) else "DISABLED"
            LOGGER.info(f"Telegram integration activated (Interactive Blocking: {interactive}).")
            integration_status_metric.labels("telegram").set(1)
        else:
            integration_status_metric.labels("telegram").set(0)
        
        self.ips_mitigator = ips_mitigator or IPSMitigator(config=self.config, state_manager=self.state_manager, stream_writer=self.alert_writer)
        self.ips_mitigator.state_manager = self.state_manager
        
        self.metrics_exporter = MetricsExporter()

        self.ollama_analyzer = OllamaAnalyzer(
            ollama_url=self.config.get("ollama_url", ""),
            ollama_model=self.config.get("ollama_model", "llama3"),
            ollama_api_key=self.config.get("ollama_api_key", ""),
            alert_file_logger=self.alert_writer,
            metrics=self.metrics_exporter
        )

        # -----------------------------------------------------------------------
        # Closed-Loop Autonomous FP Engine (CL-AFPE)
        # Instantiated here so it boots its background ML loader threads immediately.
        # The engine runs in the same process but offloads model inference to daemon
        # threads so the pipeline timing is unaffected during cold-start warm-up.
        # -----------------------------------------------------------------------
        LOGGER.info("🤖 Booting Autonomous False-Positive Elimination Engine (CL-AFPE)...")
        self.fp_engine = AutonomousFPEngine(
            config=self.config,
            state_dir=str(state_dir),
        )
        if self.ti_engine:
            self.ti_engine.fp_engine = self.fp_engine

        self._last_flush = time.time()
        self._last_prune = time.time()

        def _on_config_reload(changed_keys):
            LOGGER.info("Dynamic configuration change detected: %s", changed_keys)
            if "safe_ips" in changed_keys:
                new_safe = set(self.config.get("safe_ips", []))
                self.pihole_collector.excluded_ips = new_safe
                self.zeek_fx.safe_ips = new_safe
            if "safe_host_patterns" in changed_keys:
                new_patterns = {str(p).lower().strip() for p in self.config.get("safe_host_patterns", []) if str(p).strip()}
                self.pihole_collector.excluded_patterns = new_patterns
                self.zeek_fx.safe_patterns = new_patterns
            if "ollama_url" in changed_keys or "ollama_model" in changed_keys:
                self.ollama_analyzer.ollama_url = str(self.config.get("ollama_url", "")).strip().rstrip("/")
                self.ollama_analyzer.ollama_model = str(self.config.get("ollama_model", "llama3")).strip()
            if "telegram_enabled" in changed_keys:
                self.alert_manager.enabled = bool(self.config.get("telegram_enabled", False))
            if "home_subnet" in changed_keys:
                self.zeek_fx.set_home_subnets([self.config.get("home_subnet", "192.168.1.0/24")])
            if "honeypot_ips" in changed_keys:
                self.zeek_fx.honeypot_ips = set(self.config.get("honeypot_ips", []))
            if "zeek_log_dir" in changed_keys:
                self.zeek_collector.update_log_dir(self.config.get("zeek_log_dir", "/opt/zeek/logs/current"))

        if hasattr(self.config, "set_notify"):
            self.config.set_notify(_on_config_reload)

    def run(self) -> None:
        metrics_port = int(self.config.get("metrics_port", 9105))
        try:
            start_http_server(metrics_port)
            LOGGER.info("📊 Prometheus metrics server running on port %d", metrics_port)
        except Exception as exc:
            LOGGER.error("Failed to start Prometheus server on port %d: %s", metrics_port, exc)

        if self.config.get("telegram_enabled", False):
            self.alert_manager.send("🚀 *Home IDS Network Security Engine Online*")

        self.running = True
        LOGGER.info("🟢 Pipeline loop active. Ingesting network telemetry...")

        while self.running:
            start_time = time.time()
            try:
                self._step(now=start_time, window_seconds=int(self.config.get("window_seconds", 300)), alert_threshold=float(self.config.get("alert_threshold", 6.0)))
            except Exception as exc:
                LOGGER.error("Unhandled error during pipeline step execution: %s", exc, exc_info=True)
            elapsed = time.time() - start_time
            time.sleep(max(0.05, float(self.config.get("poll_interval", 2.0)) - elapsed))

    def _step(self, now: float, window_seconds: int, alert_threshold: float) -> None:
        LOGGER.debug("Starting pipeline processing step at %f", now)
        ips_pihole_status.set(1.0 if self.config.get("ips_pihole_enabled", True) else 0.0)
        ips_router_status.set(1.0 if self.config.get("ips_router_enabled", False) else 0.0)
        ips_tarpit_status.set(1.0 if self.config.get("ips_tarpit_enabled", True) else 0.0)

        dns_rows = self.pihole_collector.poll()
        zeek_events = self.zeek_collector.poll()

        LOGGER.debug("Polled %d DNS rows, %d Zeek events", len(dns_rows), len(zeek_events))

        for ze_event in zeek_events:
            self.zeek_fx.ingest(ze_event)

        active_ids_dns = self.identity_manager.process_dns_identities(dns_rows, self.zeek_fx, self.ml_registry)
        active_ids_zeek = self.identity_manager.process_zeek_identities(zeek_events, self.zeek_fx, self.ml_registry)
        all_active_ids = set(active_ids_dns + active_ids_zeek)
        LOGGER.debug("Identity mapping complete: %d active devices tracking", len(all_active_ids))

        for row in dns_rows:
            client_ip = str(row.get("client_ip", "")).strip()
            domain = str(row.get("domain", "")).strip()
            ts = float(row.get("timestamp", now))

            raw_hostname = str(row.get("hostname", "unknown")).strip()
            hostname = sanitize_hostname(raw_hostname) or "unknown"
            if hostname == "unknown" and self.zeek_fx:
                zh = self.zeek_fx.get_hostname(client_ip)
                if zh and zh != "unknown": hostname = sanitize_hostname(zh) or "unknown"

            mac_addr = self.zeek_fx.get_mac(client_ip)
            dev_id = self.identity_manager.resolve_device_id(client_ip, mac_addr, hostname)

            if not self.state_manager.has_device(dev_id):
                self.state_manager.get_or_create(dev_id, client_ip, hostname, float(self.config.get("baseline_alpha", 0.05)))

            with self.state_manager.lock_device(dev_id) as state:
                status_code = int(row.get("status", 0))
                qtype = row.get("reply_type", 0)
                state.rolling.events.append((ts, domain, status_code))
                state.rolling.long_events.append((ts, domain, status_code, qtype))
                state.rolling.dns_qtypes[qtype] += 1
                if status_code in BLOCKED_STATUSES:
                    state.rolling.blocked += 1
                if status_code in NXDOMAIN_STATUSES:
                    state.rolling.nxdomain += 1
                state.rolling.domains[domain] += 1
                state.rolling.domain_timestamps[domain].append(ts)

        safe_ips = set(self.config.get("safe_ips", []))
        safe_patterns = {str(p).lower().strip() for p in self.config.get("safe_host_patterns", []) if str(p).strip()}

        for dev_id in self.state_manager.get_all_device_ids():
            # ─── PHASE 1: Snapshot state data (short lock window) ───────────────────
            mitigation_pending = None
            with self.state_manager.lock_device(dev_id) as state:
                client_ip = state.client_ip
                hostname = state.hostname
                mac_addr = getattr(state, "mac_address", "unknown")
                device_type = getattr(state, "device_type", "unknown")
                is_safe = (client_ip in safe_ips) or (bool(hostname) and any(pat in hostname.lower() for pat in safe_patterns if pat))

                # AUDIT FIX #4: Prune rolling.domains to the current window using domain_timestamps.
                # This prevents the Counter from growing unboundedly across the device's lifetime.
                if hasattr(state, "rolling"):
                    cutoff = now - window_seconds
                    stale_domains = [
                        dom for dom, ts_deque in list(state.rolling.domain_timestamps.items())
                        if ts_deque and ts_deque[-1] < cutoff
                    ]
                    for dom in stale_domains:
                        state.rolling.domains.pop(dom, None)
                        del state.rolling.domain_timestamps[dom]

                    if len(state.rolling.domain_timestamps) > 10000:
                        for dom in list(state.rolling.domain_timestamps.keys())[:2000]:
                            state.rolling.domains.pop(dom, None)
                            state.rolling.domain_timestamps.pop(dom, None)

                    # Re-derive blocked/nxdomain counts from the bounded events deque
                    # so they stay accurate as old events age out.
                    state.rolling.blocked = sum(1 for _, _, sc in state.rolling.events if sc in BLOCKED_STATUSES)
                    state.rolling.nxdomain = sum(1 for _, _, sc in state.rolling.events if sc in NXDOMAIN_STATUSES)

                current_hour = int(time.strftime("%H", time.localtime(now)))
                current_minute = int(time.strftime("%M", time.localtime(now)))

                if hasattr(state, "seen_domains") and len(state.seen_domains) > 5000:
                    LOGGER.debug("Device %s exceeded domain capacity limit. Truncating history.", dev_id)
                    state.seen_domains = BoundedSet(max_size=10000, initial=list(state.seen_domains)[-5000:])

                # Snapshot baselines for Z-score computation (used outside lock)
                _rate_bl    = state.rate_baseline
                _ent_bl     = state.entropy_baseline
                _uniq_bl    = state.unique_baseline
                _nx_bl      = state.nxdomain_baseline
                _bl_bl      = state.blocked_baseline
                _dga_bl     = state.dga_baseline
                _ob_bl      = state.outbound_bytes_baseline
                _last_alert_confidence = getattr(state, "last_alert_confidence", 0.0)
                _last_alert_time = getattr(state, "last_alert_time", 0.0)
                _last_alert_sig  = getattr(state, "last_alert_signature", "")
                _last_bl_update  = getattr(state, "last_baseline_update", 0.0)
                # Snapshot rolling domain keys for TI lookups (avoids holding lock during I/O)
                _rolling_domain_keys = list(state.rolling.domains.keys()) if hasattr(state, "rolling") else []
                _killchain_hist = list(getattr(state, "killchain_history", []))

            # ─── PHASE 2: Pre-fetch Zeek data outside the lock ──────────────────────
            # Zeek feature fetching is a pure dict read (no lock needed for zeek_fx).
            # The full DNS feature compute still happens inside the Phase 4 lock below
            # since it needs live state (rolling window, EWMA baselines).
            _zeek_features = {**self.zeek_fx.get_features(client_ip), **self.zeek_fx.get_last_connection_meta(client_ip)}

            # ─── PHASE 3: Compute localized features (re-acquire lock) ──────────────
            mitigation_pending = None
            with self.state_manager.lock_device(dev_id) as state:
                features = {**self.dns_extractor.compute(state, now, window_seconds), **_zeek_features}
                features["sigma_shift"] = self.fp_engine.get_sigma_shift(dev_id)
                features["current_hour"] = current_hour
                features["current_minute"] = current_minute
                # AUDIT FIX #15: Inject honeypot IPs from config so scoring engine doesn't hardcode them
                _honeypot_ips = self.config.get("honeypot_ips", [])
                features["_config_honeypot_ips"] = ", ".join(_honeypot_ips) if _honeypot_ips else "configured decoy IPs"

                def calc_z(val: float, baseline_obj) -> float:
                    mean, var, init, n = baseline_obj.get_stats_interpolated(current_hour, current_minute) if hasattr(baseline_obj, "get_stats_interpolated") else baseline_obj.get_stats(current_hour)
                    if not init or n < 10: return 0.0
                    return max(0.0, (val - mean) / math.sqrt(max(var, 1e-4)))

                features["query_rate_z"]       = calc_z(features.get("query_rate", 0.0), state.rate_baseline)
                features["entropy_z"]           = calc_z(features.get("entropy_avg", 0.0), state.entropy_baseline)
                features["entropy_avg_z"]       = features["entropy_z"]
                features["unique_domains_z"]    = calc_z(features.get("unique_domains", 0.0), state.unique_baseline)
                features["nxdomain_ratio_z"]    = calc_z(features.get("nxdomain_ratio", 0.0), state.nxdomain_baseline)
                features["blocked_ratio_z"]     = calc_z(features.get("blocked_ratio", 0.0), state.blocked_baseline)
                features["suspicious_domains_z"]= calc_z(features.get("suspicious_domains", 0.0), state.dga_baseline)
                features["outbound_bytes_z"]    = calc_z(features.get("zeek_outbound_bytes", 0.0), state.outbound_bytes_baseline)

                target_malicious_domain = self._select_target_domain(state, self.ti_engine)
                top_domain = target_malicious_domain
                dest_ip = features.get("last_dest_ip", "unknown")
                if not dest_ip or dest_ip == "unknown":
                    if top_domain and top_domain != "unknown":
                        try:
                            import socket
                            from concurrent.futures import ThreadPoolExecutor, TimeoutError
                            # Use a temporary thread to enforce a 0.5s timeout on gethostbyname
                            # without breaking global socket timeouts for other threads.
                            with ThreadPoolExecutor(max_workers=1) as executor:
                                future = executor.submit(socket.gethostbyname, top_domain)
                                dest_ip = future.result(timeout=0.5)
                        except Exception:
                            dest_ip = "unknown"
                    else:
                        dest_ip = "unknown"

            # ─── PHASE 4: Expensive I/O outside the lock ────────────────────────────
            ti_risk, ti_match = 0.0, 0
            if self.ti_engine:
                for domain in _rolling_domain_keys:
                    ti_res = self.ti_engine.lookup_domain(domain)
                    if ti_res:
                        cur_risk = float(ti_res.get("confidence", 0.8)) * 4.0
                        ti_risk = max(ti_risk, cur_risk)
                        ti_match = 1
                        ti_ioc_hits_total.labels(source="threat_intel", ioc_type="domain").inc()
                if dest_ip and dest_ip != "unknown":
                    ip_ti_res = self.ti_engine.lookup_ip(dest_ip)
                    if ip_ti_res:
                        ti_risk = max(ti_risk, float(ip_ti_res.get("confidence", 0.8) * 4.0))
                        ti_match = 1
                        ti_ioc_hits_total.labels(source="threat_intel", ioc_type="ip").inc()

            features["ti_risk"] = ti_risk
            features["ti_match"] = ti_match

            abuse_risk = 0.0
            honeypots = self.config.get("honeypot_ips", [])
            
            if dest_ip and dest_ip != "unknown":
                if dest_ip in honeypots:
                    # Target is a honeypot; external client_ip is inherently malicious. Skip API quota waste.
                    abuse_risk = 4.0
                    honeypot_probes_total.labels(attacker_ip=dev_id, dest_port=features.get("last_dest_port", 0), protocol=features.get("dominant_protocol", "TCP")).inc()
                else:
                    self.abuseipdb.enqueue_ip(dest_ip)
                    if self.abuseipdb.lookup(dest_ip):
                        abuse_risk = 4.0
                        ti_ioc_hits_total.labels(source="abuseipdb", ioc_type="ip").inc()
                    else:
                        live_risk = self.abuseipdb.get_live_risk(dest_ip)
                        if live_risk > 0:
                            abuse_risk = live_risk
                            ti_ioc_hits_total.labels(source="abuseipdb", ioc_type="ip").inc()
                        
            features["abuseipdb_risk"] = abuse_risk

            vt_risk = 0.0
            if dest_ip in honeypots:
                # Target is a honeypot; external client_ip is inherently malicious. Skip API quota waste.
                vt_risk = 4.0
            else:
                if dest_ip and dest_ip != "unknown":
                    self.virustotal.enqueue_ip(dest_ip)
                if top_domain:
                    self.virustotal.enqueue_domain(top_domain)
                vt_risk = max(
                    self.virustotal.risk_contribution("ip", dest_ip) if dest_ip else 0.0,
                    self.virustotal.risk_contribution("domain", top_domain) if top_domain else 0.0
                )
                if vt_risk > 0:
                    ti_ioc_hits_total.labels(source="virustotal", ioc_type="mixed").inc()
            features["vt_risk"] = vt_risk

            # ─── PHASE 5: ML scoring + risk computation (re-acquire lock) ──────────
            # --- Version 7 Integration ---
            # 1. Check for Layer-2 ARP Spoofing
            if hasattr(self.zeek_fx, "layer2_spoofs") and client_ip in self.zeek_fx.layer2_spoofs:
                spoof_info = self.zeek_fx.layer2_spoofs[client_ip]
                LOGGER.critical(f"Adding HARD-STOP evidence for ARP Spoofing on {client_ip}")
                self.evidence_store.add(Evidence(type="arp_spoofing", source="zeek", timestamp=now, device=dev_id, value=10.0, confidence=1.0, provenance=f"MAC flip: {spoof_info['old']} -> {spoof_info['new']}"))
                del self.zeek_fx.layer2_spoofs[client_ip]

            mitigation_pending = None
            with self.state_manager.lock_device(dev_id) as state:
                ml_score = 0.0
                if self.ml_registry:
                    ml_score = self.ml_registry.score(dev_id, features)

                # --- Version 7 Integration ---
                # 1. Run Detectors
                dns_ev = self.dns_detector.detect(dev_id, features)
                for ev in dns_ev: self.evidence_store.add(ev)
                
                zeek_ev = self.zeek_detector.detect(dev_id, self.zeek_fx.get_alerts(client_ip))
                for ev in zeek_ev: self.evidence_store.add(ev)
                
                if ml_score > 0.90:
                    self.evidence_store.add(Evidence(type="ml_anomaly", source="ml_engine", timestamp=now, device=dev_id, value=ml_score, confidence=ml_score, independence_group="ml_anomaly", provenance="detector:ml"))
                
                if features.get("zeek_honeypot_hits", 0) > 0:
                    self.evidence_store.add(Evidence(type="honeypot_access", source="zeek", timestamp=now, device=dev_id, value=features["zeek_honeypot_hits"], confidence=1.0, independence_group="honeypot", provenance="detector:honeypot"))
                
                if features.get("zeek_lateral_moves", 0) > 0:
                    self.evidence_store.add(Evidence(type="zeek_lateral_scan", source="zeek", timestamp=now, device=dev_id, value=features["zeek_lateral_moves"], confidence=0.9, independence_group="zeek_network", provenance="detector:zeek:lateral_scan"))
                
                reputation_value = max(ti_risk, abuse_risk, vt_risk)
                if ti_match or abuse_risk > 0.0 or vt_risk > 0.0:
                    self.evidence_store.add(Evidence(
                        type="reputation",
                        source="threat_intel",
                        timestamp=now,
                        device=dev_id,
                        value=reputation_value,
                        confidence=0.95 if reputation_value >= 4.0 else 0.8,
                        independence_group="reputation",
                        provenance="detector:reputation"
                    ))
                
                # 2. Get Reputation
                rep_vector = self.rep_classifier.classify(top_domain, vt_score=vt_risk, afpe_score=0.0, ti_score=ti_risk, abuse_score=abuse_risk)
                
                # 3. Decision Engine
                active_evidence = self.evidence_store.get_for_device(dev_id)
                
                if is_safe:
                    # Hybrid Approach: Exclude ML and DNS behavioral anomalies for infrastructure,
                    # but retain Threat Intel and Honeypot evidence to alert on real threats.
                    noisy_types = {"ml_anomaly", "dns_rate", "dns_entropy", "dns_unique_ratio", "zeek_network"}
                    active_evidence = [ev for ev in active_evidence if ev.type not in noisy_types and ev.independence_group not in noisy_types]

                decision = self.decision_engine.evaluate(active_evidence, rep_vector)
                
                risk = decision["threat_confidence"] * 10.0 # Map to old 0-10 scale temporarily for metrics
                factors = [{"name": decision["explanation"], "score": risk}]
                
                LOGGER.debug("HEE Decision for %s: %s (Confidence: %.2f)", hostname, decision["state"], decision["threat_confidence"])
                
                is_poisoned = state.is_poisoned(risk)

                # H2 FIX: Only train on non-poisoned (benign) observations.
                if self.ml_registry and dev_id in all_active_ids and not is_poisoned:
                    self.ml_registry.learn(dev_id, features)

                if hasattr(state, "rolling") and hasattr(state.rolling, "domains"):
                    for d in state.rolling.domains.keys():
                        state.seen_domains.add(d)

                dest_ips = self.zeek_fx.get_dest_ips(client_ip)
                if self.geoip_engine and dest_ips:
                    for d_ip in dest_ips:
                        should_export = (d_ip not in state.geo_exported_ips) or (risk >= alert_threshold)
                        if should_export:
                            state.geo_exported_ips.add(d_ip)
                            geo_info = self.geoip_engine.lookup(d_ip)
                            asn_info = self.geoip_engine.lookup_asn(d_ip)
                            country_code = None
                            if geo_info:
                                if isinstance(geo_info, dict): country_code = geo_info.get("country")
                                elif hasattr(geo_info, "country") and geo_info.country: country_code = getattr(geo_info.country, "iso_code", None)
                            
                            if country_code:
                                # Feature 3: Geofencing Policy Enforcement
                                if self.config.get("geofencing_enabled", False):
                                    if country_code in self.config.get("geofencing_countries", []):
                                        LOGGER.warning(f"🚫 GEOFENCE VIOLATION: {dev_id} connected to {d_ip} ({country_code})")
                                        # Inject hard-stop evidence into the current active evidence set
                                        active_evidence.append(Evidence(type="geofencing_violation", source="geoip", timestamp=now, device=dev_id, value=10.0, confidence=1.0, provenance=f"Blocklisted Country: {country_code}"))
                                        # Force re-evaluate decision
                                        decision = self.decision_engine.evaluate(active_evidence, rep_vector)
                                        risk = decision["threat_confidence"] * 10.0
                                        factors = [{"name": decision["explanation"], "score": risk}]
                                
                                self.metrics_exporter.export_geoip_telemetry(geo_info, asn_info, risk=risk, features=features, alert_threshold=alert_threshold)

                if not is_poisoned:
                    self.state_manager.update_baselines(state, features, now, window_seconds, current_risk=risk)

                primary_sig = factors[0]["name"] if factors else "Threshold Exceeded"
                risk_delta = abs(risk - getattr(state, "last_alert_confidence", 0.0))
                time_elapsed = now - getattr(state, "last_alert_time", 0.0)

                if decision["state"] in (DecisionState.HIGH, DecisionState.CRITICAL):
                    if time_elapsed > 300 or (time_elapsed > 60 and (risk_delta >= 1.0 or primary_sig != getattr(state, "last_alert_signature", ""))):
                        LOGGER.warning("Alert Triggered for %s! Risk: %.2f, Signature: %s", hostname, risk, primary_sig)
                        state.last_alert_time = now
                        state.last_alert_confidence = risk
                        state.last_alert_signature = primary_sig

                        outbound_bytes = features.get("zeek_outbound_bytes", 0)
                        data_classification = classify_payload_size(outbound_bytes)
                        dest_port = features.get("last_dest_port", 0)
                        dest_proto = features.get("dominant_protocol", "UNKNOWN")
                        service_name = classify_service(dest_port, dest_proto)

                        dns_seq_lines = []
                        if hasattr(state, "rolling") and hasattr(state.rolling, "events"):
                            for ev_ts, ev_dom, ev_status in list(state.rolling.events)[-20:]:
                                status_tag = "🔴 BLOCKED" if ev_status in BLOCKED_STATUSES else "🟡 NXDOMAIN" if ev_status in NXDOMAIN_STATUSES else "🟢 ALLOWED"
                                dns_seq_lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(ev_ts))} | {status_tag} | {ev_dom}")

                        dns_seq_str = "\n".join(dns_seq_lines) if dns_seq_lines else "  No recent DNS events"

                        alert_payload = {
                            "type": "ids_alert",
                            "timestamp": now,
                            "device": {"id": dev_id, "ip": client_ip, "hostname": hostname, "type": state.device_type},
                            "network_context": {
                                "destination_ip": dest_ip, "destination_port": dest_port, "service_name": service_name,
                                "data_type": dest_proto, "payload_size_bytes": outbound_bytes, "payload_classification": data_classification,
                                "queried_domain": target_malicious_domain,
                            },
                            "risk": risk,
                            "signature": primary_sig,
                            "factors": factors,
                            "features": features,
                            "schema": "home_ids_alerts_v3",
                            "evidence_verification_required": decision.get("evidence_verification_required", False),
                            "hypothesis_weight": decision.get("hypothesis_weight", 0.0),
                        }

                        # =============================================================
                        # AUTONOMOUS FALSE-POSITIVE GATE (CL-AFPE)
                        # Before publishing this alert or executing hardware IPS containment,
                        # the 3-stage FP engine evaluates whether this is a real threat.
                        # =============================================================
                        fp_verdict = self.fp_engine.evaluate(
                            alert_payload=alert_payload,
                            features=features,
                            risk_score=risk,
                            ti_engine=self.ti_engine,
                        )

                        # Tightly coupled ML learning & Anti-Poisoning:
                        if self.ml_registry:
                            if fp_verdict["verdict"] == "FALSE_POSITIVE":
                                self.ml_registry.learn_normal(dev_id, features)
                            elif fp_verdict["verdict"] == "CONFIRMED_THREAT":
                                self.ml_registry.reject_threat(dev_id, features)

                        if fp_verdict["suppress"]:
                            LOGGER.info(
                                "✅ [PIPELINE] Alert for %s autonomously suppressed as FALSE POSITIVE "
                                "(confidence=%.3f, stage=%s). Skipping Telegram & Hardware Isolation.",
                                hostname, fp_verdict["confidence"], fp_verdict["stage"]
                            )
                        else:
                            # Real threat or low-confidence alert -> execute IPS containment & publish Telegram
                            containment_status = "🔓 UNBLOCKED / ACTIVE (Monitoring Only)"
                            if self.ips_mitigator:
                                self.ips_mitigator.mitigate(
                                    st=state,
                                    target_domain=target_malicious_domain,
                                    risk_score=risk,
                                    lateral_threat=(features.get("zeek_lateral_moves", 0) > 0 or features.get("zeek_honeypot_hits", 0) > 0),
                                    is_safe=is_safe,
                                    ti_engine=self.ti_engine,
                                    reason=primary_sig,
                                    fp_verdict=fp_verdict
                                )
                                containment_status = self.ips_mitigator.get_containment_status(
                                    client_ip=client_ip,
                                    mac_addr=getattr(state, "mac_address", "unknown"),
                                    domain=target_malicious_domain
                                )
                                
                            if bool(self.config.get("interactive_blocking_enabled", False)) and "UNBLOCKED" in containment_status:
                                containment_status = "⏳ WAITING FOR APPROVAL (Action Required via Inline Buttons below)"

                            self.alert_writer.write(alert_payload)
                            alerts_total.labels(client_ip, getattr(state, "hostname", "unknown"), getattr(state, "device_type", "unknown")).inc()

                            # Extract Application / Process Name & Scanned Ports
                            app_name = self.zeek_fx.get_app_context(client_ip) if self.zeek_fx else "Network Socket"
                            scanned_ports = self.zeek_fx.get_scanned_ports(client_ip) if self.zeek_fx else []

                            # Filter DNS sequence to show only threat-contributing / suspicious queries
                            threat_dns_lines = []
                            omitted_count = 0
                            if hasattr(state, "rolling") and hasattr(state.rolling, "events"):
                                for ev_ts, ev_dom, ev_status in list(state.rolling.events)[-25:]:
                                    # Omit harmless background noise and known safe domains
                                    safe_domains = set(self.config.get("safe_domains", []))
                                    is_trusted = (
                                        is_telemetry_domain(ev_dom) or 
                                        (ev_dom in safe_domains) or 
                                        (self.ti_engine and self.ti_engine.is_allowlisted(ev_dom))
                                    )
                                    if is_trusted and ev_status not in BLOCKED_STATUSES:
                                        omitted_count += 1
                                        continue
                                    
                                    status_tag = "🔴 BLOCKED" if ev_status in BLOCKED_STATUSES else "🟡 NXDOMAIN" if ev_status in NXDOMAIN_STATUSES else "🟢 ALLOWED"
                                    threat_dns_lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(ev_ts))} | {status_tag} | {ev_dom}")

                            threat_dns_str = "\n".join(threat_dns_lines[:10]) if threat_dns_lines else "  No suspicious DNS queries detected"
                            if omitted_count > 0:
                                threat_dns_header = f"🕒 *Threat-Filtered DNS Sequence (Omitted {omitted_count} harmless queries):*"
                            else:
                                threat_dns_header = "🕒 *Threat-Filtered DNS Sequence:*"

                            # Format FP Confidence % and Operator Recommendation
                            fp_pct = int(fp_verdict.get("confidence", 0.0) * 100)
                            threat_pct = 100 - fp_pct

                            if fp_verdict["confidence"] >= 0.75:
                                rec_badge = "🟢 *Recommendation:* Likely False Positive – Safe to ignore."
                            elif fp_verdict["confidence"] >= 0.55:
                                rec_badge = "🟡 *Recommendation:* Low Confidence Alert – Monitor for repeated pattern."
                            else:
                                rec_badge = "🚨 *Recommendation:* High Threat Confidence – Immediate remedy recommended."

                            threat_name = decision.get("hypotheses", {}).get("attack", {}).get("name", "Unknown Threat")
                            threat_conf_pct = int(decision.get('threat_confidence', 0) * 100)

                            alert_msg = (
                                f"🚨 *[ALERT] {hostname} ({client_ip})*\n\n"
                                f"🧠 *THREAT:* {threat_name} ({threat_conf_pct}% Confidence)\n"
                                f"↳ Trigger: `{primary_sig}`\n"
                                f"↳ Risk Score: `{risk:.2f}` (Threshold: `{alert_threshold:.2f}`)\n\n"
                                f"🔍 *CAUSE / EVIDENCE*\n"
                            )
                            
                            self.zeek_fx.reset_client(client_ip)
                            state.rolling.reset()
                            state.last_alert_time = now
                            
                            grouped_evidence = {}
                            for ev in active_evidence:
                                if ev.independence_group not in grouped_evidence or ev.value > grouped_evidence[ev.independence_group].value:
                                    grouped_evidence[ev.independence_group] = ev
                                    
                            for group, ev in grouped_evidence.items():
                                alert_msg += f"- `{group}`: {ev.type} ({ev.value:.1f})\n"
                                
                            active_evidence.clear()
                                
                            target_display = target_malicious_domain if target_malicious_domain and target_malicious_domain != "unknown" else (dest_ip if dest_ip and dest_ip != "unknown" else "unknown")
                            alert_msg += (
                                f"- Target: `{target_display}` ({service_name} / Port {dest_port})\n"
                                f"- Application: `{app_name}`\n"
                            )
                            
                            if scanned_ports:
                                alert_msg += f"- Lateral Scans: `{', '.join(scanned_ports)}`\n"

                            if threat_dns_str and "No suspicious" not in threat_dns_str:
                                alert_msg += f"\n{threat_dns_header}\n{threat_dns_str}\n"

                            alert_msg += (
                                f"\n🛡️ *RESPONSE*\n"
                                f"- Action: `{containment_status}`\n"
                                f"- AI Analysis: `{fp_pct}% FP / {threat_pct}% Threat`\n"
                            )
                            
                            if decision.get("evidence_verification_required", False):
                                alert_msg += "- Verification: `Required` (partial hypothesis support)\n"
                                
                            alert_msg += f"\n{rec_badge}"


                            reply_markup = None
                            if bool(self.config.get("interactive_blocking_enabled", False)):
                                inline_keyboard = [
                                    [
                                        {"text": "🔒 Approve Hardware Isolation", "callback_data": f"block:{client_ip}"},
                                        {"text": "🔓 Release Device", "callback_data": f"unblock:{client_ip}"}
                                    ]
                                ]
                                if target_display and target_display != "unknown":
                                    inline_keyboard.append([
                                        {"text": "🛡️ Immunize FP Domain", "callback_data": f"immunize:{target_display}"}
                                    ])
                                reply_markup = {"inline_keyboard": inline_keyboard}

                            # self.ollama_analyzer.analyze(alert_payload)
                            self.alert_manager.send(alert_msg, raw_payload=alert_payload, reply_markup=reply_markup)

                elif getattr(state, "last_alert_confidence", 0.0) >= alert_threshold and risk <= (alert_threshold - 1.0):
                    LOGGER.debug("Device %s risk subsided below threshold.", hostname)
                    state.last_alert_confidence = 0.0

                # Hardware IPS containment is handled exclusively inside the alert gate above
                # (lines ~404-414), which is already gated on risk >= alert_threshold.
                # Calling mitigate() unconditionally here for every device every 2s cycle was
                # generating 30+ unnecessary Pi-hole API lookups per minute at 30 devices.

                rate_mean, _, _, _ = state.rate_baseline.get_stats(current_hour)
                threshold_limit = rate_mean + (float(self.config.get("threshold_std_dev", 3.0)) * math.sqrt(max(state.rate_baseline.var[current_hour], 1e-4)))

                self.metrics_exporter.export_device_telemetry(
                    state=state, features=features, risk_score=risk, ml_score=ml_score, ti_risk=ti_risk,
                    ti_match=ti_match, abuse_risk=abuse_risk, vt_risk=vt_risk, is_safe=is_safe,
                    is_poisoned=is_poisoned, current_threshold_limit=threshold_limit, decision=decision
                )

                for dst_ip, dst_port in self.zeek_fx.pop_new_lateral_events(client_ip):
                    self.metrics_exporter.record_lateral_target(dev_id, hostname, client_ip, dst_ip, dst_port)
                    
            # --- OUTSIDE THE DEVICE LOCK ---
            if mitigation_pending:
                m = mitigation_pending
                containment_status = "🔓 UNBLOCKED / ACTIVE (Monitoring Only)"
                
                if self.ips_mitigator:
                    self.ips_mitigator.mitigate(
                        st=m["state"],
                        target_domain=m["target_domain"],
                        risk_score=m["risk"],
                        c2_hits=1 if m["risk"] >= 8.0 else 0,
                        dga_burst=(m["features"].get("suspicious_domains_z", 0.0) > 2.0),
                        lateral_threat=(m["features"].get("zeek_lateral_moves", 0) > 0 or m["features"].get("zeek_honeypot_hits", 0) > 0),
                        is_safe=m["is_safe"],
                        ti_engine=self.ti_engine,
                        reason=m["primary_sig"],
                        fp_verdict=m["fp_verdict"]
                    )
                    containment_status = self.ips_mitigator.get_containment_status(
                        client_ip=m["client_ip"],
                        mac_addr=getattr(m["state"], "mac_address", "unknown"),
                        domain=m["target_domain"]
                    )
                    
                if bool(self.config.get("interactive_blocking_enabled", False)) and "UNBLOCKED" in containment_status:
                    containment_status = "⏳ WAITING FOR APPROVAL (Action Required via Inline Buttons below)"

                self.alert_writer.write(m["alert_payload"])
                alerts_total.labels(m["client_ip"], getattr(m["state"], "hostname", "unknown"), getattr(m["state"], "device_type", "unknown")).inc()

                app_name = self.zeek_fx.get_app_context(m["client_ip"]) if self.zeek_fx else "Network Socket"
                scanned_ports = self.zeek_fx.get_scanned_ports(m["client_ip"]) if self.zeek_fx else []

                threat_dns_lines = []
                omitted_count = 0
                if hasattr(m["state"], "rolling") and hasattr(m["state"].rolling, "events"):
                    for ev_ts, ev_dom, ev_status in list(m["state"].rolling.events)[-25:]:
                        safe_domains = set(self.config.get("safe_domains", []))
                        is_trusted = (
                            is_telemetry_domain(ev_dom) or 
                            (ev_dom in safe_domains) or 
                            (self.ti_engine and self.ti_engine.is_allowlisted(ev_dom))
                        )
                        if is_trusted and ev_status not in BLOCKED_STATUSES:
                            omitted_count += 1
                            continue
                        
                        status_tag = "🔴 BLOCKED" if ev_status in BLOCKED_STATUSES else "🟡 NXDOMAIN" if ev_status in NXDOMAIN_STATUSES else "🟢 ALLOWED"
                        threat_dns_lines.append(f"  {time.strftime('%H:%M:%S', time.localtime(ev_ts))} | {status_tag} | {ev_dom}")

                threat_dns_str = "\n".join(threat_dns_lines[:10]) if threat_dns_lines else "  No suspicious DNS queries detected"
                threat_dns_header = f"🕒 *Threat-Filtered DNS Sequence (Omitted {omitted_count} harmless queries):*" if omitted_count > 0 else "🕒 *Threat-Filtered DNS Sequence:*"

                fp_pct = int(m["fp_verdict"].get("confidence", 0.0) * 100)
                threat_pct = 100 - fp_pct

                if m["fp_verdict"]["confidence"] >= 0.75:
                    rec_badge = "🟢 *Recommendation:* Likely False Positive – Safe to ignore."
                elif m["fp_verdict"]["confidence"] >= 0.55:
                    rec_badge = "🟡 *Recommendation:* Low Confidence Alert – Monitor for repeated pattern."
                else:
                    rec_badge = "🚨 *Recommendation:* High Threat Confidence – Immediate remedy recommended."

                alert_msg = (
                    f"🚨 *[ALERT] {m['hostname']} ({m['client_ip']})*\n"
                    f"📊 *Risk:* `{m['risk']:.2f}` (Threshold: `{alert_threshold:.2f}`)\n"
                    f"🏷️ *Primary Trigger:* {m['primary_sig']}\n\n"
                    f"🌐 *DNS Activity (Pi-hole Context)*\n"
                    f"- Target Domain: `{m['target_domain'] or 'None'}`\n"
                    f"{threat_dns_header}\n{threat_dns_str}\n\n"
                    f"🔌 *Network Activity (Zeek Context)*\n"
                    f"- Dominant Outbound: `{m['service_name']}` (Port `{m['dest_port']}` / `{m['dest_proto']}`)\n"
                    f"- App / Process: `{app_name}`\n"
                )
                if scanned_ports:
                    alert_msg += f"- Lateral Scans: `{', '.join(scanned_ports)}` [{len(scanned_ports)} ports]\n\n"
                else:
                    alert_msg += f"- Lateral Scans: None\n\n"

                alert_msg += (
                    f"🛡️ *Mitigation & Confidence*\n"
                    f"- Containment: `{containment_status}`\n"
                    f"- Confidence: `{fp_pct}% FP / {threat_pct}% Threat`\n\n"
                )

                alert_msg += "🧠 *BEST EXPLANATION:* " + m["decision"].get("hypotheses", {}).get("attack", {}).get("name", "Unknown Threat") + "\n"
                alert_msg += f"⚖️ *Threat Confidence:* {int(m['decision'].get('threat_confidence', 0) * 100)}%\n\n"
                alert_msg += "*EVIDENCE GRAPH:*\n"
                
                seen_groups = set()
                for ev in m["active_evidence"]:
                    if ev.independence_group not in seen_groups:
                        seen_groups.add(ev.independence_group)
                        alert_msg += f"✓ {ev.independence_group}: {ev.type} ({ev.value:.1f})\n"
                
                alert_msg += f"\n{rec_badge}"

                reply_markup = None
                if bool(self.config.get("interactive_blocking_enabled", False)):
                    target = m.get('target_domain') if m.get('target_domain') and m.get('target_domain') != 'unknown' else m.get('dest_ip')
                    inline_keyboard = [
                        [
                            {"text": "🔒 Approve Hardware Isolation", "callback_data": f"block:{m['client_ip']}"},
                            {"text": "🔓 Release Device", "callback_data": f"unblock:{m['client_ip']}"}
                        ]
                    ]
                    if target and target != "unknown":
                        inline_keyboard.append([
                            {"text": "🛡️ Immunize FP Domain", "callback_data": f"immunize:{target}"}
                        ])
                    reply_markup = {"inline_keyboard": inline_keyboard}

                # self.ollama_analyzer.analyze(m["alert_payload"])
                self.alert_manager.send(alert_msg, raw_payload=m["alert_payload"], reply_markup=reply_markup)

        self.zeek_fx.prune(now, window_seconds)
        
        self.metrics_exporter.export_pipeline_health(
            zeek_online=self.zeek_collector.available, zeek_events_count=len(zeek_events),
            collector_lag=max(0.0, time.time() - now), events_processed=len(dns_rows),
            alert_queue_size=self.alert_manager.q.qsize(), ml_model_loaded=self.ml_registry.global_warmed_up if self.ml_registry else False
        )
        # Real-time Prometheus gauge cleanup for Grafana dashboard sync
        self.metrics_exporter.garbage_collect_ips_metrics(self.state_manager.get_ips_state())
        
        if now - self._last_prune > 3600.0:  
            pruned_list = self.state_manager.prune_stale_devices(now)
            for e_dev_id, e_hostname, e_dev_type in pruned_list:
                self.metrics_exporter.remove_device_metric_labels(e_dev_id, e_hostname, e_dev_type)
                if hasattr(self, 'evidence_store'): self.evidence_store.clear_device(e_dev_id)
            self._last_prune = now

        # IPC Split-Brain Reconciliation: detect if the Uvicorn IPC endpoints wrote
        # a sentinel file after modifying state from the separate process. If so, pull
        # the updated IPS state (tarpit_targets, router_isolated_devices, blocked_domains) back into live memory
        # before the periodic flush so the latest operator action is not overwritten.
        _sentinel = self.state_manager.state_path.parent / ".ipc_sync_signal"
        if _sentinel.exists():
            try:
                _sentinel.unlink()
                self.state_manager.reconcile_ips_from_disk()
                if self.ips_mitigator:
                    # Sync the live IPSMitigator's in-memory tarpit/router dicts from the reconciled state
                    ips_state = self.state_manager.get_ips_state()
                    with self.ips_mitigator._lock:
                        self.ips_mitigator._tarpit_active_targets = ips_state.get("tarpit_targets", {})
                        self.ips_mitigator._router_isolated_devices = ips_state.get("router_isolated_devices", {})
                        self.ips_mitigator._operator_released_devices = ips_state.get("operator_released_devices", {})
                    LOGGER.info("✅ [IPC SYNC] IPSMitigator in-memory state reconciled after Telegram release.")
            except Exception as _ipc_exc:
                LOGGER.warning("IPC sentinel reconciliation failed: %s", _ipc_exc)

        if now - self._last_flush > 60.0:
            LOGGER.debug("Triggering periodic state/model flush to disk.")
            self.state_manager.flush_to_disk()
            if self.ml_registry: self.ml_registry.save_models()
            self._last_flush = now

        LOGGER.debug("Pipeline step finished.")


    def stop(self) -> None:
        if hasattr(self, "ollama_analyzer"):
            self.ollama_analyzer.stop()
        LOGGER.info("Stopping Engine Pipeline...")
        self.running = False
        if hasattr(self, "state_manager"): self.state_manager.flush_to_disk()
        if hasattr(self, "ml_registry") and self.ml_registry: self.ml_registry.save_models()
        if hasattr(self, "alert_manager"): self.alert_manager.stop()

    def _select_target_domain(self, state, ti_engine) -> str:
        """
        Selects the primary target domain for alert reporting and FP evaluation.
        Prioritizes:
        1. ThreatIntel IOC match
        2. Suspicious / High-Entropy / Non-Allowlisted domain in current window
        3. Fallback: Most frequent domain (top_domain)
        """
        if not hasattr(state, "rolling") or not hasattr(state.rolling, "domains") or not state.rolling.domains:
            return "unknown"

        domains_dict = state.rolling.domains

        # Priority 1: ThreatIntel IOC match
        if ti_engine:
            best_ti_domain = None
            max_ti_score = 0.0
            for dom in domains_dict.keys():
                res = ti_engine.lookup_domain(dom)
                if res:
                    score = float(res.get("confidence", 0.8))
                    if score > max_ti_score:
                        max_ti_score = score
                        best_ti_domain = dom
            if best_ti_domain:
                return best_ti_domain

        # Priority 2: Highest-risk non-allowlisted suspicious domain
        best_susp_domain = None
        max_susp_score = 0.0


        for dom in domains_dict.keys():
            if not dom or dom == "unknown":
                continue
            if is_telemetry_domain(dom) or (ti_engine and ti_engine.is_allowlisted(dom)):
                continue

            first_label = dom.split(".")[0] if dom else ""
            label_len = len(first_label)
            ent = compute_entropy(first_label)

            score = 0.0
            if label_len > 30:
                score += (label_len - 30) * 0.25
            if ent > 3.2:
                score += (ent - 3.2) * 2.0
            if not _is_cdn_or_cloud_domain(dom):
                score += 1.0

            if score > max_susp_score:
                max_susp_score = score
                best_susp_domain = dom

        if best_susp_domain and max_susp_score >= 1.0:
            return best_susp_domain

        # Priority 3: Fallback to most frequent domain
        return max(domains_dict, key=domains_dict.get, default="unknown")