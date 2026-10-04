"""
W-04: feature keys that detectors read but nothing produced. Covers the four producers added for them and, for each,
the false-positive guards they are built around:

  - everything is novelty-gated through intelligence/local_popularity.is_preexisting(): a name already used on this
    network, an unknown answer (None: young or unreadable history), or no popularity source at all -> no value;
  - thin data never becomes a value (minimum counts per producer);
  - protocol-periodic services, CDN/telemetry names, dead-endpoint retries and direct-IP destinations are left out.

Also the producer/consumer contract that stops this class of bug from coming back: every key a detector reads must be
produced somewhere.
"""
import re
import sqlite3
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from core.state import DeviceState  # noqa: E402
from extractors.dns_features import FeatureExtractor, apply_device_age_gate  # noqa: E402
from intelligence.device_familiarity import DeviceFamiliarity  # noqa: E402
from extractors.zeek_features import ZeekFeatureExtractor  # noqa: E402
from intelligence.detectors.dns_behavior import DNSBehaviorDetector  # noqa: E402
from intelligence.detectors.threat_signals import ThreatSignalDetector  # noqa: E402
from intelligence.local_popularity import LocalPopularity  # noqa: E402
from utils import etld1  # noqa: E402

DAY = 86400.0
_CONSONANTS = "bcdfghjklmnpqrstvwxz"
_MIXED = "a1b2c3d4e5f6g7h8k9mn"


class _Pop:
    """Stand-in popularity source: names in `known` are pre-existing, `unknown` answer None, the rest are new."""

    def __init__(self, known=(), unknown=()):
        self.known, self.unknown = set(known), set(unknown)

    def is_preexisting(self, domain, device_id=None):
        if domain in self.unknown:
            return None
        return domain in self.known or any(domain.endswith("." + k) for k in self.known)


def _algorithmic(i):
    """Distinct (for i < 20), vowel-free, 13 distinct letters: what suspicious_dga() flags."""
    return (_CONSONANTS[i:] + _CONSONANTS[:i])[:13] + ".com"


def _encoded_label(i):
    return _MIXED[i % 20:] + _MIXED[:i % 20] + str(i)   # distinct for every i


# --------------------------------------------------------------------------- LocalPopularity.is_preexisting

def _popularity(tmp_path, now, rows):
    """rows: (name, first_seen, days) -- days an int (that many consecutive days back from today) or a list of
    day offsets (0 = today)."""
    pop = LocalPopularity(tmp_path / "popularity.db", etld1_fn=etld1, now_fn=lambda: now)  # as the pipeline builds it
    with sqlite3.connect(str(tmp_path / "popularity.db")) as db:
        for name, first_seen, days in rows:
            offsets = range(days) if isinstance(days, int) else days
            day_list = ",".join(str(int((now // DAY) - d)) for d in offsets)
            db.execute("INSERT INTO names (name, devices, days, first_seen, last_seen) VALUES (?,?,?,?,?)",
                       (name, "dev1", day_list, first_seen, now))
    pop._rebuild_snapshot()   # what the periodic flush does
    return pop


def test_preexisting_unknown_while_history_is_young(tmp_path):
    now = 1_800_000_000.0
    pop = _popularity(tmp_path, now, [("anchor.example", now - 1 * DAY, 1)])
    assert pop.is_preexisting("brand-new.example") is None


def test_preexisting_unknown_when_history_is_old_but_thin(tmp_path):
    # The unit ran for one afternoon three weeks ago and again today: old by the calendar, 2 active days.
    now = 1_800_000_000.0
    pop = _popularity(tmp_path, now, [("anchor.example", now - 21 * DAY, [21, 0])])
    assert pop.active_days == 2
    assert pop.is_preexisting("brand-new.example") is None


def test_preexisting_true_for_old_name_false_for_new(tmp_path):
    now = 1_800_000_000.0
    pop = _popularity(tmp_path, now, [("anchor.example", now - 10 * DAY, 10),
                                      ("vendor-cloud.example", now - 5 * DAY, 4)])
    assert pop.is_preexisting("vendor-cloud.example") is True
    assert pop.is_preexisting("api.vendor-cloud.example") is True      # covered through its registrable domain
    assert pop.is_preexisting("never-seen-before.example") is False


def test_preexisting_counts_active_days_not_calendar_age(tmp_path):
    now = 1_800_000_000.0
    pop = _popularity(tmp_path, now, [("anchor.example", now - 10 * DAY, 10),
                                      ("one-day-wonder.example", now - 9 * DAY, [9]),         # old, used once
                                      ("two-days.example", now - 30 * DAY, [30, 0]),          # very old, 2 days
                                      ("three-days.example", now - 2 * DAY, 3)])              # young, 3 days
    assert pop.is_preexisting("one-day-wonder.example") is False
    assert pop.is_preexisting("two-days.example") is False
    assert pop.is_preexisting("three-days.example") is True


# --------------------------------------------------------------------------- unique_subdomain_ratio

def _fanout_state(parent, n_children, repeats=1):
    state = DeviceState(device_id="d1", client_ip="192.168.1.50", hostname="h")
    now = time.time()
    for i in range(n_children):
        name = f"{_encoded_label(i)}.{parent}"
        for _ in range(repeats):
            state.rolling.events.append((now, name, 2))
            state.rolling.domains[name] += 1
            state.rolling.domain_timestamps[name].append(now)
    return state, now


def _extractor(pop):
    fx = FeatureExtractor()
    fx.popularity = pop
    return fx


def test_unique_ratio_produced_for_new_high_entropy_fanout():
    state, now = _fanout_state("tunnel-example.net", 25)
    feats = _extractor(_Pop()).compute(state, now, 300)
    assert feats["unique_subdomain_ratio"] == pytest.approx(1.0)
    assert feats["unique_subdomain_ratio_domain"] == "tunnel-example.net"


@pytest.mark.parametrize("pop", [None, _Pop(known={"tunnel-example.net"}), _Pop(unknown={"tunnel-example.net"})])
def test_unique_ratio_silent_without_novelty(pop):
    state, now = _fanout_state("tunnel-example.net", 25)
    assert _extractor(pop).compute(state, now, 300)["unique_subdomain_ratio"] == 0.0


def test_unique_ratio_silent_on_thin_fanout():
    state, now = _fanout_state("tunnel-example.net", 12)
    assert _extractor(_Pop()).compute(state, now, 300)["unique_subdomain_ratio"] == 0.0


def test_unique_ratio_silent_for_readable_subdomains():
    # A multi-tenant SaaS shape: many customer names, low label entropy.
    state = DeviceState(device_id="d1", client_ip="192.168.1.50", hostname="h")
    now = time.time()
    for i in range(30):
        name = f"customer{i}.saas-example.net"
        state.rolling.events.append((now, name, 2))
        state.rolling.domains[name] += 1
        state.rolling.domain_timestamps[name].append(now)
    assert _extractor(_Pop()).compute(state, now, 300)["unique_subdomain_ratio"] == 0.0


# --------------------------------------------------------------------------- dga_score

def _nx_state(names, reply_type=2):
    state = DeviceState(device_id="d1", client_ip="192.168.1.50", hostname="h")
    now = time.time()
    for n in names:
        state.rolling.long_events.append((now - 60, n, 3, reply_type))
    return state, now


def test_dga_score_produced_for_many_new_algorithmic_nxdomains():
    names = [_algorithmic(i) for i in range(12)]
    state, now = _nx_state(names)
    feats = _extractor(_Pop()).compute(state, now, 300)
    assert feats["dga_score"] > 0.40
    assert len(feats["dga_score_examples"]) == 3


@pytest.mark.parametrize("pop", [None, _Pop(unknown={_algorithmic(i) for i in range(12)})])
def test_dga_score_silent_without_novelty(pop):
    state, now = _nx_state([_algorithmic(i) for i in range(12)])
    assert _extractor(pop).compute(state, now, 300)["dga_score"] == 0.0


def test_dga_score_silent_when_names_already_used_here():
    names = [_algorithmic(i) for i in range(12)]
    state, now = _nx_state(names)
    assert _extractor(_Pop(known=set(names[:6]))).compute(state, now, 300)["dga_score"] == 0.0


def test_dga_score_ignores_answered_queries_and_single_labels():
    answered, _ = _nx_state([_algorithmic(i) for i in range(12)], reply_type=4)     # answered, not NXDOMAIN
    assert _extractor(_Pop()).compute(answered, time.time(), 300)["dga_score"] == 0.0
    probes, now = _nx_state([_CONSONANTS[i:] + _CONSONANTS[:i] for i in range(12)])  # intranet probes, no dot
    assert _extractor(_Pop()).compute(probes, now, 300)["dga_score"] == 0.0


def test_dga_score_silent_on_thin_data():
    state, now = _nx_state([_algorithmic(i) for i in range(7)])
    assert _extractor(_Pop()).compute(state, now, 300)["dga_score"] == 0.0


# --------------------------------------------------------------------------- beacon_tdr / beacon_total

SRC, DST, NAME = "192.168.1.50", "93.184.216.34", "c2-example.net"


def _zeek(pop=_Pop(), name=NAME):
    z = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
    z.popularity = pop
    if name:
        z._wire_dns_resolutions[name] = DST
    return z


def _feed(z, n=20, period=60.0, jitter=None, port=443, state="SF", size=512, start=None):
    t = start if start is not None else time.time() - n * period
    for i in range(n):
        dt = jitter[i % len(jitter)] if jitter else 0.0
        z._process_conn(SRC, {"id.resp_h": DST, "id.resp_p": port, "proto": "tcp", "orig_bytes": size,
                              "uid": f"u{i}", "ts": t + i * period + dt, "conn_state": state})


def test_beacon_reported_for_regular_series_to_new_destination():
    z = _zeek()
    _feed(z)
    f = z.get_features([SRC])
    assert f["beacon_tdr"] > 0.75 and f["beacon_total"] == 20
    assert f["beacon_domain"] == NAME


def test_beacon_survives_one_skipped_checkin():
    z = _zeek()
    t = time.time() - 30 * 60
    for i in [k for k in range(22) if k != 10]:
        z._process_conn(SRC, {"id.resp_h": DST, "id.resp_p": 443, "orig_bytes": 512, "uid": f"u{i}",
                              "ts": t + i * 60.0, "conn_state": "SF"})
    assert z.get_features([SRC]).get("beacon_tdr", 0) > 0.75


@pytest.mark.parametrize("pop", [None, _Pop(known={NAME}), _Pop(unknown={NAME})])
def test_beacon_silent_without_novelty(pop):
    z = _zeek(pop=pop)
    _feed(z)
    assert "beacon_tdr" not in z.get_features([SRC])


@pytest.mark.parametrize("kwargs", [
    {"port": 123},                                  # NTP: periodic by protocol
    {"state": "S0"},                                # retries to a dead endpoint
    {"size": 0},                                    # no payload
    {"n": 10},                                      # fewer than 15 observations
    {"period": 5.0},                                # keepalive/streaming speed
    {"jitter": [0.0, 25.0, -20.0, 18.0, -24.0]},    # irregular
])
def test_beacon_guards(kwargs):
    z = _zeek()
    _feed(z, **kwargs)
    assert "beacon_tdr" not in z.get_features([SRC])


def test_beacon_silent_for_direct_ip_and_cdn_names():
    direct = _zeek(name=None)
    _feed(direct)
    assert "beacon_tdr" not in direct.get_features([SRC])
    cdn = _zeek(name="edge.cloudfront.net")
    _feed(cdn)
    assert "beacon_tdr" not in cdn.get_features([SRC])


def test_beacon_pairs_are_bounded_per_device():
    z = _zeek()
    t = time.time()
    for i in range(200):
        z._process_conn(SRC, {"id.resp_h": f"93.184.{i // 200}.{i % 200 + 1}", "id.resp_p": 443, "orig_bytes": 10,
                              "uid": f"x{i}", "ts": t + i, "conn_state": "SF"})
    assert len(z._beacon_pairs[SRC]) <= 64


def test_outbound_bytes_1h_counts_only_the_last_hour():
    z = _zeek()
    now = time.time()
    for ts, size in ((now - 2 * 3600, 1000), (now - 30 * 60, 300), (now - 60, 200)):
        z._process_conn(SRC, {"id.resp_h": DST, "id.resp_p": 443, "orig_bytes": size, "uid": str(ts),
                              "ts": ts, "conn_state": "SF"})
    assert z.get_features([SRC])["zeek_outbound_bytes_1h"] == 500


# --------------------------------------------------------------------------- device-age gate

def test_young_device_gets_no_novelty_features():
    feats = {"unique_subdomain_ratio": 1.0, "unique_subdomain_ratio_domain": "t.net", "dga_score": 0.9,
             "dga_score_examples": ["x.com"], "beacon_tdr": 0.9, "beacon_total": 20.0, "beacon_domain": NAME,
             "beacon_dest_ip": DST, "query_rate": 5.0}
    assert apply_device_age_gate(feats, 2, 40) is True
    assert feats["unique_subdomain_ratio"] == 0.0 and feats["dga_score"] == 0.0
    assert not any(k.startswith("beacon_") for k in feats)
    assert feats["query_rate"] == 5.0          # other features untouched


@pytest.mark.parametrize("days,hours,cleared", [
    (7, 24, False),    # enough of both
    (14, 12, True),    # many short sessions: not enough observed hours
    (6, 144, True),    # six long days: not a full week of distinct days
])
def test_device_gate_needs_active_days_and_hours(days, hours, cleared):
    feats = {"dga_score": 0.9, "beacon_tdr": 0.9}
    assert apply_device_age_gate(feats, days, hours) is cleared


def _observe(fam, device, ts):
    fam.record_device_baseline_observation(device, domain_base="example.com", now=ts)


def test_activity_is_observed_time_not_calendar_time():
    # On for one hour a week ago, back online now: 2 active days, 2 active hours -- not "a week old".
    fam = DeviceFamiliarity()
    now = 1_800_000_000.0
    for minute in range(0, 60, 5):
        _observe(fam, "cam", now - 7 * DAY + minute * 60)
    _observe(fam, "cam", now)
    assert fam.learned_activity("cam") == (2, 2)
    feats = {"beacon_tdr": 0.9}
    assert apply_device_age_gate(feats, *fam.learned_activity("cam")) is True


def test_activity_of_an_always_on_device_opens_the_gate():
    fam = DeviceFamiliarity()
    start = 1_800_000_000.0 - 7 * DAY
    for h in range(7 * 24):
        _observe(fam, "nas", start + h * 3600)
    days, hours = fam.learned_activity("nas")
    assert days >= 7 and hours >= 24
    assert apply_device_age_gate({"beacon_tdr": 0.9}, days, hours) is False


def test_activity_unknown_for_history_without_bookkeeping():
    fam = DeviceFamiliarity()
    fam._data["old"] = {"domain_bases": {"example.com": {"count": 99, "first_seen": 1.0, "last_seen": 2.0}}}
    assert fam.learned_activity("old") == (0, 0)


# --------------------------------------------------------------------------- detectors use the produced values

def test_detectors_attach_the_produced_domains():
    feats = {"beacon_tdr": 0.9, "beacon_total": 20.0, "beacon_domain": NAME,
             "dga_score": 0.6, "dga_score_examples": ["bcdfghjklmnpq.com"]}
    ev = ThreatSignalDetector().detect("d1", feats)
    beacons = [e for e in ev if e.type == "zeek_beaconing"]
    assert beacons and beacons[0].domain == NAME
    dga = [e for e in ev if e.type == "dns_dga_burst"]
    assert dga and dga[0].domain == "bcdfghjklmnpq.com"


def test_dns_rate_reads_the_5min_average_only():
    ev = DNSBehaviorDetector().detect("d1", {"dns_rate_last_60s": 900, "query_rate": 20})
    assert not [e for e in ev if e.type == "dns_rate"]


# --------------------------------------------------------------------------- contract: every read key is produced

_CONSUMERS = [
    "intelligence/detectors/threat_signals.py", "intelligence/detectors/dns_behavior.py",
    "intelligence/detectors/zeek_network.py", "intelligence/ml_engine.py", "argus/cl_afpe/engine.py",
    "core/metrics_sync.py",
]


def test_every_feature_key_a_detector_reads_is_produced():
    consumers = {SRC_DIR / c for c in _CONSUMERS}
    read = set()
    for path in consumers:
        text = path.read_text(encoding="utf-8")
        read |= set(re.findall(r'features\.get\(\s*"([a-zA-Z0-9_]+)"', text))
        read |= set(re.findall(r'features\[\s*"([a-zA-Z0-9_]+)"\s*\]', text))
    producers = "".join(p.read_text(encoding="utf-8", errors="ignore")
                        for p in SRC_DIR.rglob("*.py") if p not in consumers)
    missing = sorted(k for k in read
                     if not re.search(r'["\']%s["\']\s*:' % re.escape(k), producers)
                     and not re.search(r'features\[\s*["\']%s["\']\s*\]\s*=' % re.escape(k), producers))
    assert missing == [], f"read by a detector but produced nowhere: {missing}"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
