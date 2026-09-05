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


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 ingest-sources checks PASSED.")
