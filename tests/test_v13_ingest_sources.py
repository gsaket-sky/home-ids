"""
Standalone runtime test for v13's live ingestion module (src/v13/ingest/sources.py,
Phase 7 wiring -- Documentation/V13_REMAINING_WORK.md items A2/A3).

Covers: ZeekLogSource's cursor persistence/resume, partial-line safety, rotation
(inode-change) detection; build_zeek_sources' file-to-event-type mapping;
poll_all's cross-source aggregation; and run_detection_cycle's A2 fix -- that
zeek_exfiltration/zeek_beaconing evidence gets a real fallback_context
(features["last_dest_ip"]) while every other evidence type does not, and that
ZeekFeatureExtractor's own "unknown" no-data sentinel is never mistaken for a
real destination.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_ingest_sources.py`
"""
import json
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path as _PathForSysPath
from typing import Optional

sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.ingest.sources import (  # noqa: E402
    ZeekLogSource, ZEEK_LOG_FILES, build_zeek_sources, poll_all,
    _build_fallback_context, run_detection_cycle,
    PiHoleLogSource, PiHoleFeatureStore,
    _STATUS_BLOCKED, _STATUS_ALLOWED, _STATUS_NXDOMAIN,
)
from v13.evidence.model import NO_DESTINATION  # noqa: E402


# --- ZeekLogSource: basic tailing + callback ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    log_path = tmp_path / "conn.log"
    cursor_dir = tmp_path / "cursors"

    log_path.write_text('{"ts": 1.0, "id.orig_h": "1.2.3.4"}\n', encoding="utf-8")
    source = ZeekLogSource(log_path, "conn", cursor_dir)
    # A source constructed against an EXISTING file seeks to EOF at construction
    # (matches zeek_features.py's own ZeekLogTailer -- never replays history that
    # predates the tailer starting, only genuinely new lines).
    seen = []
    n = source.poll(lambda etype, ev: seen.append((etype, ev)))
    check("fresh source seeks to EOF, does not replay pre-existing content", n == 0 and seen == [])

    with open(log_path, "a", encoding="utf-8") as f:
        f.write('{"ts": 2.0, "id.orig_h": "1.2.3.5"}\n')
    n = source.poll(lambda etype, ev: seen.append((etype, ev)))
    check("poll() picks up a newly-appended complete line", n == 1 and len(seen) == 1)
    check("callback receives (event_type, parsed dict)", seen[0][0] == "conn" and seen[0][1]["id.orig_h"] == "1.2.3.5")
    check("ZeekLogSource stamps _zeek_type on the event", seen[0][1].get("_zeek_type") == "conn")

    # --- partial line safety: an unflushed trailing write must not be consumed ---
    with open(log_path, "a", encoding="utf-8") as f:
        f.write('{"ts": 3.0, "id.orig_h": "1.2.3.6"}')  # no trailing newline
    n = source.poll(lambda etype, ev: seen.append((etype, ev)))
    check("a not-yet-newline-terminated line is left for the next poll, not consumed", n == 0 and len(seen) == 1)

    with open(log_path, "a", encoding="utf-8") as f:
        f.write("\n")
    n = source.poll(lambda etype, ev: seen.append((etype, ev)))
    check("the same line is picked up once its newline actually arrives", n == 1 and len(seen) == 2)

    # --- cursor persistence across a fresh instance (simulates a process restart) ---
    source2 = ZeekLogSource(log_path, "conn", cursor_dir)
    with open(log_path, "a", encoding="utf-8") as f:
        f.write('{"ts": 4.0, "id.orig_h": "1.2.3.7"}\n')
    seen2 = []
    n = source2.poll(lambda etype, ev: seen2.append((etype, ev)))
    check("a new instance resumes from the saved cursor, not from EOF or position 0",
          n == 1 and seen2[0][1]["id.orig_h"] == "1.2.3.7")

    # --- rotation: file replaced with a new inode and shorter content ---
    log_path.unlink()
    log_path.write_text('{"ts": 5.0, "id.orig_h": "1.2.3.8"}\n', encoding="utf-8")
    seen3 = []
    n = source2.poll(lambda etype, ev: seen3.append((etype, ev)))
    check("a rotated (replaced) log file is detected and re-read from position 0, not skipped",
          n == 1 and seen3[0][1]["id.orig_h"] == "1.2.3.8")

    # --- malformed JSON line does not crash or block subsequent lines ---
    with open(log_path, "a", encoding="utf-8") as f:
        f.write("not valid json at all\n")
        f.write('{"ts": 6.0, "id.orig_h": "1.2.3.9"}\n')
    seen4 = []
    n = source2.poll(lambda etype, ev: seen4.append((etype, ev)))
    check("a malformed JSON line is skipped, not fatal, and later lines still process",
          n == 1 and seen4[0][1]["id.orig_h"] == "1.2.3.9")

    # --- build_zeek_sources / poll_all ---
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()
    (mount_dir / "dns.log").write_text("", encoding="utf-8")
    (mount_dir / "conn.log").write_text("", encoding="utf-8")
    sources = build_zeek_sources(mount_dir, tmp_path / "cursors2")
    check("build_zeek_sources creates one source per configured log file", len(sources) == len(ZEEK_LOG_FILES))
    check("event types are derived from filenames (no .log suffix)", "dns" in sources and "conn" in sources)

    with open(mount_dir / "dns.log", "a", encoding="utf-8") as f:
        f.write('{"ts": 1.0, "id.orig_h": "9.9.9.9", "query": "example.com"}\n')

    class _FakeExtractor:
        def __init__(self):
            self.ingested = []

        def ingest(self, event):
            self.ingested.append(event)

    fake_extractor = _FakeExtractor()
    total = poll_all(sources, fake_extractor)
    check("poll_all aggregates counts across all sources", total == 1)
    check("poll_all feeds events into extractor.ingest()", len(fake_extractor.ingested) == 1)
    check("missing/empty log files (e.g. arp.log with no zeek_scripts loaded) are silently zero, not an error",
          sources["arp"].path.exists() is False)


# --- _build_fallback_context: the A2 fix itself ---
check("zeek_exfiltration gets a fallback_context from a real last_dest_ip",
      _build_fallback_context("zeek_exfiltration", {"last_dest_ip": "5.6.7.8"}) == {"dest_ip": "5.6.7.8"})
check("zeek_beaconing gets a fallback_context from a real last_dest_ip",
      _build_fallback_context("zeek_beaconing", {"last_dest_ip": "5.6.7.8"}) == {"dest_ip": "5.6.7.8"})
check("an evidence type outside the known gap gets no fallback_context",
      _build_fallback_context("zeek_notice", {"last_dest_ip": "5.6.7.8"}) is None)
check("ZeekFeatureExtractor's own 'unknown' no-data sentinel is never treated as a real destination",
      _build_fallback_context("zeek_exfiltration", {"last_dest_ip": "unknown"}) is None)
check("a missing last_dest_ip key produces no fallback_context (not a crash)",
      _build_fallback_context("zeek_exfiltration", {}) is None)


# --- run_detection_cycle: end-to-end with a real ThreatSignalDetector-shaped fake ---
@dataclass
class _FakeV1Evidence:
    type: str
    source: str
    timestamp: float
    device: str
    value: float
    confidence: float = 1.0
    baseline: Optional[float] = None
    independence_group: str = "general"
    provenance: str = ""
    domain: Optional[str] = None


class _FakeDetector:
    """Mimics ThreatSignalDetector.detect()'s real signature/return shape without
    needing the full feature dict every one of its many branches reads -- this
    test is about run_detection_cycle's OWN wiring (does it call detect() with
    the right args, does it split/attach fallback_context correctly), not about
    re-testing threat_signals.py's detection logic itself (already covered by
    that module's own tests in the main suite)."""

    def __init__(self):
        self.last_call_kwargs = None

    def detect(self, device, features, top_domain=None, arp_sweep_threshold=8,
               conn_abuse_unique_ip_threshold=5, long_conn_duration_threshold=14400.0,
               ti_engine=None):
        self.last_call_kwargs = dict(
            device=device, top_domain=top_domain, arp_sweep_threshold=arp_sweep_threshold,
            conn_abuse_unique_ip_threshold=conn_abuse_unique_ip_threshold,
            long_conn_duration_threshold=long_conn_duration_threshold, ti_engine=ti_engine,
        )
        return [
            _FakeV1Evidence(type="zeek_exfiltration", source="threat_signals", timestamp=1.0,
                              device=device, value=6.0, confidence=0.9, independence_group="zeek_network"),
            _FakeV1Evidence(type="zeek_beaconing", source="threat_signals", timestamp=1.0,
                              device=device, value=0.8, confidence=0.7, independence_group="zeek_network"),
            _FakeV1Evidence(type="zeek_notice", source="threat_signals", timestamp=1.0,
                              device=device, value=1.0, confidence=0.75, independence_group="zeek_network"),
        ]


class _FakeExtractor2:
    def get_features(self, device_ip):
        return {"last_dest_ip": "10.0.0.99", "zeek_outbound_bytes": 3000000}


results = run_detection_cycle(_FakeExtractor2(), _FakeDetector(), "192.168.1.50")
by_type = {ev.evidence_type: ev for ev in results}
check("run_detection_cycle returns v13 Evidence v2 objects for every v1 item", len(results) == 3)
check("zeek_exfiltration gets destination_id from the fallback (A2 closed)",
      by_type["zeek_exfiltration"].destination_id == "10.0.0.99")
check("zeek_beaconing gets destination_id from the fallback (A2 closed)",
      by_type["zeek_beaconing"].destination_id == "10.0.0.99")
check("zeek_notice (no gap) is left as NO_DESTINATION, not given a misleading fallback",
      by_type["zeek_notice"].destination_id == NO_DESTINATION)
check("independence_family is populated from INDEPENDENCE_FAMILY_MAP, not left defaulted",
      not by_type["zeek_exfiltration"].features.get("independence_family_defaulted", False))

class _FakeExtractorUnknownDest:
    def get_features(self, device_ip):
        return {"last_dest_ip": "unknown"}


detector_with_no_dest = _FakeDetector()
results_no_dest = run_detection_cycle(_FakeExtractorUnknownDest(), detector_with_no_dest, "192.168.1.51")
by_type_nd = {ev.evidence_type: ev for ev in results_no_dest}
check("when last_dest_ip is the 'unknown' sentinel, zeek_exfiltration correctly falls back to NO_DESTINATION",
      by_type_nd["zeek_exfiltration"].destination_id == NO_DESTINATION)


class _EmptyDetector:
    def detect(self, *a, **kw):
        return []


check("run_detection_cycle returns an empty list, not an error, when detect() finds nothing",
      run_detection_cycle(_FakeExtractor2(), _EmptyDetector(), "192.168.1.52") == [])


# --- run_detection_cycle: dns_features merge (A5) ---
class _MergeCheckDetector:
    def __init__(self):
        self.seen_features = None

    def detect(self, device, features, **kw):
        self.seen_features = features
        return []


merge_detector = _MergeCheckDetector()
run_detection_cycle(_FakeExtractor2(), merge_detector, "192.168.1.53",
                      dns_features={"suspicious_domains": 20, "entropy_avg": 4.1})
check("dns_features are merged into the features dict passed to detect()",
      merge_detector.seen_features is not None
      and merge_detector.seen_features.get("suspicious_domains") == 20
      and merge_detector.seen_features.get("entropy_avg") == 4.1)
check("Zeek-derived features survive the merge alongside dns_features",
      merge_detector.seen_features.get("last_dest_ip") == "10.0.0.99")

merge_detector2 = _MergeCheckDetector()
run_detection_cycle(_FakeExtractor2(), merge_detector2, "192.168.1.54")
check("omitting dns_features leaves behavior unchanged (no merge attempted)",
      "suspicious_domains" not in merge_detector2.seen_features)


# --- PiHoleLogSource: dnsmasq text-log parsing (A5) ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    log_path = tmp_path / "pihole.log"
    cursor_dir = tmp_path / "cursors"

    log_path.write_text("", encoding="utf-8")
    source = PiHoleLogSource(log_path, cursor_dir)

    events = []

    def _cb(ts, domain, client_ip, status, qtype):
        events.append((domain, client_ip, status, qtype))

    def _write(lines):
        with open(log_path, "a", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")

    # gravity-blocked query -> BLOCKED
    _write([
        "Sep  6 00:38:15 dnsmasq[1146]: query[A] ichnaea.netflix.com from 192.168.77.85",
        "Sep  6 00:38:15 dnsmasq[1146]: gravity blocked ichnaea.netflix.com is 0.0.0.0",
    ])
    n = source.poll(_cb)
    check("a gravity-blocked query is emitted once, classified BLOCKED", n == 1 and events[-1] == ("ichnaea.netflix.com", "192.168.77.85", _STATUS_BLOCKED, "A"))

    # dnsmasq's own anti-WPAD-hijack denial -> BLOCKED
    _write([
        "Sep  6 00:26:49 dnsmasq[1146]: query[A] wpad.fritz.box from 192.168.77.20",
        "Sep  6 00:26:49 dnsmasq[1146]: exactly denied wpad.fritz.box is 0.0.0.0",
    ])
    source.poll(_cb)
    check("an 'exactly denied' resolution is classified BLOCKED", events[-1][2] == _STATUS_BLOCKED)

    # a real answer via a CNAME chain -> only the top-level queried domain
    # correlates; the chain's intermediate hops (never their own `query...from`
    # line) are silently skipped, not misattributed.
    _write([
        "Sep  6 00:38:15 dnsmasq[1146]: query[A] cdn-0.nflximg.com from 192.168.77.85",
        "Sep  6 00:38:15 dnsmasq[1146]: cached cdn-0.nflximg.com is <CNAME>",
        "Sep  6 00:38:15 dnsmasq[1146]: cached dscg.netflix.com.edgesuite.net is <CNAME>",
        "Sep  6 00:38:15 dnsmasq[1146]: forwarded cdn-0.nflximg.com to 127.0.0.1#5335",
        "Sep  6 00:38:15 dnsmasq[1146]: reply cdn-0.nflximg.com is <CNAME>",
    ])
    before = len(events)
    n = source.poll(_cb)
    check("a CNAME chain emits exactly one event, for the originally-queried domain only",
          n == 1 and len(events) == before + 1 and events[-1][0] == "cdn-0.nflximg.com")
    check("a real resolved answer (not NXDOMAIN, not blocked) is classified ALLOWED",
          events[-1][2] == _STATUS_ALLOWED)

    # an NXDOMAIN answer, regardless of which verb carries it
    _write([
        "Sep  6 00:27:06 dnsmasq[1146]: query[AAAA] sky.fritz.box from 192.168.77.30",
        "Sep  6 00:27:06 dnsmasq[1146]: cached sky.fritz.box is NXDOMAIN",
    ])
    source.poll(_cb)
    check("an NXDOMAIN answer is classified NXDOMAIN regardless of verb", events[-1] == ("sky.fritz.box", "192.168.77.30", _STATUS_NXDOMAIN, "AAAA"))

    # an intermediate 'forwarded ... to ...' line alone (no matching 'is' line yet)
    # must not be treated as terminal
    before = len(events)
    _write(["Sep  6 00:40:00 dnsmasq[1146]: forwarded standalone.example.com to 127.0.0.1#5335"])
    n = source.poll(_cb)
    check("a bare 'forwarded ... to ...' line with no 'is' clause is not treated as terminal", n == 0 and len(events) == before)

    # a resolution line with no preceding query line has nothing to correlate against
    before = len(events)
    _write(["Sep  6 00:41:00 dnsmasq[1146]: cached orphan.example.com is 1.2.3.4"])
    n = source.poll(_cb)
    check("a resolution line with no pending query is silently skipped, not misattributed", n == 0 and len(events) == before)

    # non-dnsmasq / malformed lines are ignored, not fatal
    before = len(events)
    _write(["Sep  6 00:42:00 systemd[1]: some unrelated service log line"])
    n = source.poll(_cb)
    check("a non-dnsmasq syslog line is ignored, not fatal", n == 0 and len(events) == before)

    # --- cursor persistence across a fresh instance ---
    source2 = PiHoleLogSource(log_path, cursor_dir)
    _write([
        "Sep  6 00:43:00 dnsmasq[1146]: query[A] resumed.example.com from 192.168.77.40",
        "Sep  6 00:43:00 dnsmasq[1146]: cached resumed.example.com is 5.6.7.8",
    ])
    events2 = []
    n = source2.poll(lambda ts, d, c, s, q: events2.append((d, c, s, q)))
    check("a new PiHoleLogSource instance resumes from the saved cursor, not from EOF or 0",
          n == 1 and events2[0][0] == "resumed.example.com")

    # --- rotation clears pending state too (a query pending before rotation
    # can never be legitimately resolved by lines from a DIFFERENT file) ---
    log_path.unlink()
    log_path.write_text(
        "Sep  6 00:44:00 dnsmasq[1146]: query[A] postrotate.example.com from 192.168.77.50\n"
        "Sep  6 00:44:00 dnsmasq[1146]: cached postrotate.example.com is 9.9.9.9\n",
        encoding="utf-8",
    )
    events3 = []
    n = source2.poll(lambda ts, d, c, s, q: events3.append((d, c, s, q)))
    check("a rotated log file is detected, re-read from position 0", n == 1 and events3[0][0] == "postrotate.example.com")


# --- PiHoleFeatureStore: real RollingWindow + real FeatureExtractor.compute() ---
store = PiHoleFeatureStore()
check("an unseen device returns zero features, not an error",
      store.compute_features("192.168.1.99")["total"] == 0)

now = time.time()
for i in range(20):
    store.ingest_query(now, f"a{i}b{i}c{i}d{i}e{i}f{i}g{i}h{i}xyz{i}.evil-tunnel-domain.example", "192.168.1.60", _STATUS_ALLOWED, "TXT")
feats = store.compute_features("192.168.1.60", now=now, window_seconds=300)
check("PiHoleFeatureStore produces real dns_tunneling-shaped signal from many long, high-entropy labels",
      feats["dns_tunneling_domains"] > 0 or feats["max_label_length"] > 28)
check("dns_qtypes is fed the real DNS query type, not left empty", sum(store._states["192.168.1.60"].rolling.dns_qtypes.values()) == 20)

blocked_store = PiHoleFeatureStore()
for i in range(10):
    blocked_store.ingest_query(now, f"blocked{i}.example.com", "192.168.1.61", _STATUS_BLOCKED, "A")
blocked_feats = blocked_store.compute_features("192.168.1.61", now=now, window_seconds=300)
check("a device with only blocked queries shows blocked_ratio == 1.0", blocked_feats["blocked_ratio"] == 1.0)


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 ingest-sources checks PASSED.")
