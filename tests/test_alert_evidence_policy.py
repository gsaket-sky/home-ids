"""
Policy tests from the 2026-10-01 Windows-laptop review (open items B1, B4-B8): fingerprint-only evidence is not a verdict,
protocol oddities are context, two Zeek-derived families are one source, one lateral connection / a handful of
NXDOMAINs is not a kill-chain phase.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from argus.decision.engine import _count_independent_sources  # noqa: E402
from extractors.dns_features import FeatureExtractor  # noqa: E402
from intelligence import threat_intel  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from utils import classify_zeek_notice  # noqa: E402


def test_quic_and_unlisted_weirds_are_weak_context():
    assert classify_zeek_notice("weird:QUIC_spurious_short_header_packet_threshold_crossed") == "weak"
    assert classify_zeek_notice("weird:some_new_parser_oddity") == "weak"
    assert classify_zeek_notice("weird:bad_HTTP_request") == "medium"       # explicitly listed
    assert classify_zeek_notice("SSL::Invalid_Server_Cert") == "medium"
    assert classify_zeek_notice("Scan::Port_Scan") == "strong"
    assert classify_zeek_notice("Some::Unknown_Notice") == "medium"          # non-weird unknowns keep the default


def test_zeek_derived_families_count_as_one_source():
    assert _count_independent_sources({"tls_fingerprint", "network_behavior"}) == 1
    assert _count_independent_sources({"tls_fingerprint", "network_behavior", "data_transfer_pattern"}) == 1
    assert _count_independent_sources({"tls_fingerprint", "dns_behavior"}) == 2
    assert _count_independent_sources({"network_behavior", "reputation", "dns_behavior"}) == 3
    assert _count_independent_sources(set()) == 0


def test_one_lateral_connection_is_not_a_lateral_phase():
    fx = FeatureExtractor()
    assert fx._determine_killchain_phase(None, {"zeek_lateral_moves": 1, "zeek_lateral_unique_targets": 1}) == "NORMAL"
    assert fx._determine_killchain_phase(None, {"zeek_lateral_moves": 3, "zeek_lateral_unique_targets": 2}) == "SUSPECTED_LATERAL"


def test_nxdomain_ratio_needs_a_query_floor():
    fx = FeatureExtractor()
    assert fx._determine_killchain_phase(None, {"nxdomain_ratio": 0.6, "total": 5}) == "NORMAL"
    assert fx._determine_killchain_phase(None, {"nxdomain_ratio": 0.6, "total": 40}) == "SUSPECTED_RECON"


def test_old_sslbl_listings_are_ignored():
    now = time.mktime(time.strptime("2026-10-01", "%Y-%m-%d"))
    assert threat_intel._sslbl_listing_is_stale("2021-05-14", now)
    assert not threat_intel._sslbl_listing_is_stale("2026-09-20", now)
    assert not threat_intel._sslbl_listing_is_stale("?", now)      # unparseable -> kept


def _stage1(features):
    import tempfile
    fp = ClAfpeEngine(GraphStore(str(Path(tempfile.mkdtemp()) / "graph.db")))   # no confirmed-intel store
    return fp._stage1_hard_stop(features, "host", "", "203.0.113.9", "")


def test_fingerprint_alone_is_not_a_hard_stop():
    assert not _stage1({"zeek_ja3_malicious": 5})


def test_fingerprint_with_reputation_is_a_hard_stop():
    t = _stage1({"zeek_ja3_malicious": 1, "ti_risk": 0.5})
    assert t and "TLS fingerprint" in t[0]


def test_gateway_mac_is_written_to_the_graph_once_not_per_event():
    from argus.identity.live_manager import LiveIdentityManager

    class _Store:
        def __init__(self):
            self.writes, self.reads = 0, 0

        def update_device_metadata(self, device_id, meta):
            self.writes += 1

        def get_device_metadata(self, device_id):
            self.reads += 1
            return {}

    m = LiveIdentityManager.__new__(LiveIdentityManager)
    m._graph_store = _Store()
    m._trust_anchors = {"gateway": object()}
    m._learned_macs_cache, m._learned_macs_cache_at, m._learned_written = None, 0.0, {}
    for _ in range(500):
        m._learn_anchor_mac("gateway", "aa:bb:cc:dd:ee:ff")
    assert m._graph_store.writes == 1
    for _ in range(500):
        m._get_learned_anchor_macs()
    assert m._graph_store.reads == 1


# --- B9: "ordinary explanations checked" block ---------------------------------------------------------------

def _benign(**kw):
    from core.pipeline import _benign_explanations_checked
    args = dict(target="unknown", app_name="", http_reqs=[], ti_risk=0.0, abuse_risk=0.0,
                asn_owner=None, asn_owner_is_safe=None, families=[])
    args.update(kw)
    return _benign_explanations_checked(**args)


def test_windows_laptop_case_names_cert_checks_telemetry_and_no_reputation():
    # The real 2026-10-01 alert: Windows CryptoAPI fetching CRLs, Microsoft telemetry host, JA3 + Zeek notice.
    lines = _benign(target="ic3.events.data.microsoft.com", app_name="Microsoft-CryptoAPI/10.0",
                    http_reqs=["crl.microsoft.com/pki/crl/products/MicRooCerAut2011_2011_03_22.crl"],
                    families=["tls_fingerprint", "network_behavior"])
    text = "\n".join(lines)
    assert "Microsoft-CryptoAPI" in text
    assert "certificate-revocation" in text
    assert "telemetry" in text
    assert "no threat-intel or AbuseIPDB" in text
    assert "same sensor (Zeek)" in text


def test_a_real_looking_c2_case_says_the_ordinary_explanations_do_not_apply():
    lines = _benign(target="update-check.example-c2.top", app_name="Go-http-client", ti_risk=3.0, abuse_risk=4.0,
                    families=["tls_fingerprint", "reputation"])
    text = "\n".join(lines)
    assert "not a known telemetry, CDN or cloud domain" in text
    assert "has a reputation score" in text
    assert "same sensor" not in text            # reputation is an independent family
    assert not any(l.startswith("⚠️") for l in lines)


def test_ip_destination_uses_the_asn_owner():
    safe = "\n".join(_benign(target="203.0.113.7", asn_owner="Microsoft Corporation", asn_owner_is_safe=True))
    assert "large provider" in safe
    unknown = "\n".join(_benign(target="203.0.113.8", asn_owner="Tiny Hosting LLC", asn_owner_is_safe=False))
    assert "not one of the large providers" in unknown


def test_missing_inputs_never_raise():
    assert _benign(target=None, app_name=None, http_reqs=None, families=None)


# --- A2: action ledger encoded once, not on every flush -------------------------------------------------------

def test_ledger_entries_are_encoded_once_not_on_every_flush(tmp_path, monkeypatch):
    import json as _json
    from core import state_store
    from core.state_guard import StateManager
    import core.state_guard as sg
    sm = StateManager(state_path=str(tmp_path / "ids_state.json"))
    sm.record_action("a1", "published_alert", "x.example", "dev1", extra={"payload": "p" * 100})

    encoded = []
    real_dumps = _json.dumps

    def counting_dumps(obj, *a, **k):
        if isinstance(obj, dict) and obj.get("type") == "published_alert":
            encoded.append(obj["target"])
        return real_dumps(obj, *a, **k)

    monkeypatch.setattr(sg.json, "dumps", counting_dumps)

    assert sm.flush_to_disk() and sm.flush_to_disk()
    assert encoded == ["x.example"]                 # second flush reused the entry's cached JSON
    sm.record_action("a2", "published_alert", "y.example", "dev2")
    assert sm.flush_to_disk()
    assert encoded == ["x.example", "y.example"]    # a new alert encodes only itself
    data = state_store.read_snapshot(tmp_path / "ids_state.json")
    assert data["action_ledger"]["a1"]["extra"]["payload"] == "p" * 100
    assert set(data["action_ledger"]) == {"a1", "a2"}

    sm.revoke_action("a1")                          # in-place mutation must invalidate that entry
    assert sm.flush_to_disk()
    assert encoded[-1] == "x.example"
    data = state_store.read_snapshot(tmp_path / "ids_state.json")
    assert data["action_ledger"]["a1"]["revoked"] is True
    assert set(data) == {"ips_state", "devices", "merge_redirects", "action_ledger"}

    sm.prune_expired_actions(now=10 ** 12)          # a2 expires (a1 is revoked, kept)
    assert sm.flush_to_disk()
    data = state_store.read_snapshot(tmp_path / "ids_state.json")
    assert set(data["action_ledger"]) == {"a1"}

    sm2 = StateManager(state_path=str(tmp_path / "ids_state.json"))
    sm2.load_from_disk()
    assert sm2.get_action("a1")["revoked"] is True


def test_home_ip_check_is_memoised_and_reset_with_the_subnets():
    from extractors.zeek_features import ZeekFeatureExtractor
    z = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
    assert z._is_home_ip("192.168.1.5") and not z._is_home_ip("10.0.0.5") and not z._is_home_ip("not-an-ip")
    assert z._home_ip_memo["192.168.1.5"] is True
    z.set_home_subnets(["10.0.0.0/8"])
    assert not z._is_home_ip("192.168.1.5") and z._is_home_ip("10.0.0.5")


def test_fast_metric_key_read_matches_collect():
    from prometheus_client import CollectorRegistry, Gauge, Histogram
    from core.metrics_sync import MetricsExporter
    reg = CollectorRegistry()
    g = Gauge("t_a2_gauge", "x", ["device", "hostname", "device_type"], registry=reg)
    h = Histogram("t_a2_hist", "x", ["device", "hostname"], registry=reg)
    for i in range(5):
        g.labels(f"d{i}", f"h{i}", "iot").set(i)
        h.labels(f"d{i}", f"h{i}").observe(0.3)
    exp = MetricsExporter.__new__(MetricsExporter)
    for metric in (g, h):
        exp._metric_keys_cache = {}
        fast = exp._get_metric_keys(metric)
        slow = set()
        for mf in metric.collect():
            for s in mf.samples:
                if all(l in s.labels for l in metric._labelnames):
                    slow.add(tuple(s.labels[l] for l in metric._labelnames))
        assert fast == slow and len(fast) == 5


def test_suspicious_tld_count_unchanged_by_the_per_domain_rewrite():
    # Reference: the old per-event loop.
    _SUSPICIOUS_TLDS = frozenset({"top", "xyz"})   # same shape as the local set in FeatureExtractor.compute()
    tld = "top"
    events = [(1.0, f"a.{tld}"), (2.0, f"a.{tld}"), (3.0, "example.com"), (4.0, tld), (5.0, f"b.c.{tld}"),
              (6.0, "localhost"), (7.0, f"x.{tld}.com")]
    old = sum(1 for _, d in events if len(d.split(".")) >= 2 and d.split(".")[-1] in _SUSPICIOUS_TLDS)
    from collections import defaultdict
    by_dom = defaultdict(list)
    for ts, d in events:
        by_dom[d].append(ts)
    new = sum(len(v) for d, v in by_dom.items() if "." in d and d.rpartition(".")[2] in _SUSPICIOUS_TLDS)
    assert old == new == 3


# --- A5 (second pass): the wired-probe trigger ignores infrastructure services and learns during warm-up ------

def _conn(src, dst, port, proto="tcp"):
    import time as _t
    return {"_zeek_type": "conn", "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port, "proto": proto,
            "orig_bytes": 10, "uid": f"C{src}{port}", "ts": _t.time()}


def test_dns_ntp_dhcp_and_ping_to_the_ids_host_are_not_probes():
    from extractors.zeek_features import ZeekFeatureExtractor
    z = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"], wired_probe_ips={"192.168.1.94"})
    for src, port, proto in (("192.168.1.10", 53, "udp"), ("192.168.1.11", 53, "tcp"), ("192.168.1.12", 123, "udp"),
                             ("192.168.1.13", 67, "udp"), ("192.168.1.14", 0, "icmp"), ("192.168.1.15", 5353, "udp")):
        z.ingest(_conn(src, "192.168.1.94", port, proto))
    assert z.pop_new_wired_probe_sources() == []
    z.ingest(_conn("192.168.1.16", "192.168.1.94", 22))          # SSH to the server still counts
    assert z.pop_new_wired_probe_sources() == [("192.168.1.94", "192.168.1.16")]


def test_ignore_services_is_configurable():
    from extractors.zeek_features import ZeekFeatureExtractor
    z = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"], wired_probe_ips={"192.168.1.94"},
                             wired_probe_ignore_services=[443])
    z.ingest(_conn("192.168.1.10", "192.168.1.94", 443))
    z.ingest(_conn("192.168.1.11", "192.168.1.94", 53, "udp"))   # no longer ignored with a custom list
    assert z.pop_new_wired_probe_sources() == [("192.168.1.94", "192.168.1.11")]


def test_sources_seen_during_warmup_are_learned_silently():
    from extractors.zeek_features import ZeekFeatureExtractor
    z = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"], wired_probe_ips={"192.168.1.94"},
                             wired_probe_warmup_seconds=600)
    z.ingest(_conn("192.168.1.20", "192.168.1.94", 22))
    assert z.pop_new_wired_probe_sources() == []                 # restart: existing client, no burst
    z._wired_probe_warmup_until = 0                              # warm-up over
    z.ingest(_conn("192.168.1.20", "192.168.1.94", 22))
    assert z.pop_new_wired_probe_sources() == []                 # already learned
    z.ingest(_conn("192.168.1.21", "192.168.1.94", 22))
    assert z.pop_new_wired_probe_sources() == [("192.168.1.94", "192.168.1.21")]


def test_unchanged_state_is_not_rewritten(tmp_path):
    from core import state_store
    from core.state_guard import StateManager
    path = tmp_path / "ids_state.json"
    db = state_store.db_path_for(path)
    sm = StateManager(state_path=str(path))
    sm.record_action("a1", "published_alert", "x.example", "dev1")
    assert sm.flush_to_disk() and db.exists()
    m1 = state_store.last_modified(path)
    assert sm.flush_to_disk() and sm.flushes_skipped_unchanged == 1 and sm.rows_written_last_flush == 0
    assert state_store.last_modified(path) == m1
    sm.record_action("a2", "published_alert", "y.example", "dev2")
    assert sm.flush_to_disk() and sm.flushes_skipped_unchanged == 1 and sm.rows_written_last_flush == 1
    state_store.close_writers()
    for p in (db, db.with_name(db.name + "-wal"), db.with_name(db.name + "-shm")):
        if p.exists():
            p.unlink()
    assert sm.flush_to_disk() and state_store.exists(path)               # missing database -> everything rewritten
    assert set(state_store.read_snapshot(path)["action_ledger"]) == {"a1", "a2"}
