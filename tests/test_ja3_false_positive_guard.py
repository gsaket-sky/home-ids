"""
Guards against "malicious JA3" false positives (found live 2026-10-01: a Windows 11 laptop was reported as a
HIGH network intrusion "matched a known-bad signature directly" because its stock TLS stack hashes to
6a5d235ee78c6aede6a61448b4e9ff1e -- the hash of ET sid 2058288, which only means something together with the SNI
barefootinc.com.au). A JA3 names a client LIBRARY, not a malware family.

Covers: the per-device "one stack, many servers" self-check, the hard-coded list, the alert's WHY text (hash +
listing source + caveat), and that a cached ET index from before the parser fix is rebuilt, not reused.
"""
import gzip
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from extractors.zeek_features import ZeekFeatureExtractor  # noqa: E402
from intelligence import ja3_provenance  # noqa: E402
from intelligence.et_open_fetch import ETOpenUpdater  # noqa: E402
from intelligence.hypotheses.evidence import Evidence  # noqa: E402
from core import pipeline  # noqa: E402

WIN11 = "6a5d235ee78c6aede6a61448b4e9ff1e"
WIN10_2019 = "3b5074b1b5d032e5620f69f9159a2983"
BAD = "e7d705a3286e19ea42f587b6207263db"   # stands in for a hash a live feed lists


class _TI:
    dynamic_ja3 = frozenset([WIN11, BAD])


def _ssl(z, src, ja3, server):
    z._process_ssl(src, {"ja3": ja3, "ja4": "", "server_name": server, "ts": 1.0,
                         "id.resp_p": 443, "id.resp_h": "203.0.113.5"})


def test_no_unattributed_hashes_are_hard_coded():
    assert not ZeekFeatureExtractor._MALICIOUS_JA3


def test_a_listed_hash_to_one_server_still_counts():
    z = ZeekFeatureExtractor(ti_engine=_TI())
    _ssl(z, "10.0.0.5", BAD, "c2.example.net")
    assert len(z._ja3_hits["10.0.0.5"]) == 1


def test_one_stack_reaching_many_servers_is_not_malware_evidence():
    z = ZeekFeatureExtractor(ti_engine=_TI())
    for server in ("chatgpt.com", "ab.chatgpt.com", "ic3.events.data.microsoft.com", "teams.microsoft.com"):
        _ssl(z, "10.0.0.7", WIN11, server)
    assert len(z._ja3_hits["10.0.0.7"]) == 4          # below the threshold: still reported
    _ssl(z, "10.0.0.7", WIN11, "www.example.org")      # 5th distinct server: it is the device's own TLS library
    assert len(z._ja3_hits["10.0.0.7"]) == 0           # earlier hits withdrawn
    _ssl(z, "10.0.0.7", WIN11, "chatgpt.com")
    assert len(z._ja3_hits["10.0.0.7"]) == 0           # and later ones are ignored


def test_the_same_hash_on_another_device_is_judged_separately():
    z = ZeekFeatureExtractor(ti_engine=_TI())
    for server in ("a.example", "b.example", "c.example", "d.example", "e.example"):
        _ssl(z, "10.0.0.7", WIN11, server)
    _ssl(z, "10.0.0.8", WIN11, "only-one.example")
    assert len(z._ja3_hits["10.0.0.8"]) == 1


def test_repeated_connections_to_the_same_server_do_not_trip_the_self_check():
    z = ZeekFeatureExtractor(ti_engine=_TI())
    for _ in range(50):
        _ssl(z, "10.0.0.9", BAD, "c2.example.net")
    assert len(z._ja3_hits["10.0.0.9"]) == 50


def test_alert_text_shows_hash_source_and_caveat():
    ja3_provenance.set_source("et_open", {WIN11: "ET Open rule sid 2028302"})
    ev = Evidence(type="malicious_ja3", source="zeek", timestamp=1.0, device="d", value=1.0, confidence=0.95,
                  independence_group="zeek_network", provenance=f"detector:zeek:malicious_ja3:{WIN11}",
                  domain="ic3.events.data.microsoft.com")
    text = pipeline._describe_evidence(ev)
    assert "ic3.events.data.microsoft.com" in text
    assert WIN11[:12] in text
    assert "ET Open rule sid 2028302" in text
    assert "not proof of malware" in text
    ja3_provenance.clear()


def test_alert_text_without_a_registered_source_still_shows_the_hash():
    ja3_provenance.clear()
    ev = Evidence(type="malicious_ja3", source="zeek", timestamp=1.0, device="d", value=1.0,
                  provenance=f"detector:zeek:malicious_ja3:{BAD}", domain=None)
    text = pipeline._describe_evidence(ev)
    assert BAD[:12] in text and "not proof of malware" in text


def test_cached_et_index_from_before_the_fix_is_rebuilt_not_reused(tmp_path):
    old = {"schema": 1, "source": "et_open", "source_version": "11300", "fetched_at": 1.0,
           "counts": {}, "ips": {}, "cidrs": [], "domains": {}, "ja3": {WIN11: {"sid": 2058288}}}
    (tmp_path / ETOpenUpdater.INDEX_FILE).write_bytes(gzip.compress(json.dumps(old).encode()))
    (tmp_path / ETOpenUpdater.STATE_FILE).write_text(json.dumps(
        {"version": "11300", "etag": "x", "next_due": 9e18, "last_success": 1.0}))
    up = ETOpenUpdater(tmp_path)
    assert up.load_current() is None            # the old schema is rejected ...
    assert up.due() is True                     # ... so the updater treats it as missing and re-downloads,
    assert up._index_usable() is False          # instead of answering "version 11300 already installed"
