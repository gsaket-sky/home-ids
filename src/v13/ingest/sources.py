"""
v13 live ingestion from .94's mounted raw sources (Phase 7 wiring --
Documentation/V13_REMAINING_WORK.md items A2/A3).

Reuses v-current's real sensor/detector code (extractors/zeek_features.py's
ZeekFeatureExtractor, intelligence/detectors/threat_signals.py's
ThreatSignalDetector) UNCHANGED against a read-only SMB-mounted copy of .94's
Zeek logs on .19 -- per the plan's own module map, these are "sensors, reused
not forked," not part of the v13 redesign itself. This module's only new code
is the log tailer (ported from zeek_features.py's own ZeekLogTailer, same
inode+byte-offset cursor design, generalized to point at a mount instead of
/opt/zeek/logs/current) and the orchestration that threads a real fallback_context
into the v13 ingest adapter for the two detectors that never set .domain
themselves.

CONFIRMED THIS SESSION (direct inspection of .19's live mounts, 2026-09-06),
correcting the plan's original "Zeek logs, Suricata eve.json, Pi-hole/unbound
query logs" framing:

  - Zeek logs ARE JSON-lines (not TSV) and ARE live-tailable over the mount --
    /mnt/v13-zeek/*.log grows continuously (dns.log alone is 200MB+ and
    climbing). This is what this module actually wires up.

  - Pi-hole's FTL sqlite DB (what PiHoleCollector in dns_features.py reads) is
    NOT part of the v13-pihole share at all -- only Pi-hole's own text logs
    (pihole.log, FTL.log) are shared. Even if the DB were shared, SQLite's own
    documentation says WAL mode (which pihole-FTL.db uses) is unreliable over
    a network filesystem -- a real reason beyond "it's just not mounted" not
    to go that route. Reconstructing PiHoleCollector's structured
    (domain, client, status) output from pihole.log's free-text dnsmasq lines
    needs its own parser (query/gravity-blocked/cached/forwarded/reply line
    correlation) -- NOT built in this pass. Consequence: this module does not
    yet produce any DNS-behavior evidence (dns_dga_burst, dns_tunnel_v2,
    blindspot_audit) -- only Zeek-derived evidence. Tracked as a new, separate
    open item (not silently dropped) -- see V13_REMAINING_WORK.md.

  - Suricata is NOT a continuous log stream in this deployment at all --
    intelligence/detectors/suricata_scan.py runs it in short BATCH invocations
    against reactively-captured pcap bursts (extractors/fritzbox_capture.py's
    ReactiveCaptureDispatcher), triggered a handful of times per hour, writing
    to a per-invocation scratch eve.json that doesn't persist. This is why the
    shared /mnt/v13-suricata/eve.json is 0 bytes on a live, working install --
    it is not a bug in the mount, it is not the real integration point.
    Replicating this needs the whole reactive-capture trigger/dispatch
    subsystem, not a log tailer -- an honest, separate scope cut, matching the
    CL-AFPE/retro-hunter precedent of not re-implementing an entire unresearched
    subsystem in passing. NOT attempted here.

A2 (zeek_exfiltration/zeek_beaconing never set .domain, threat_signals.py:247-274):
CLOSED for evidence produced by this module. Both detectors' own code already
computes features["last_dest_ip"] (via ZeekFeatureExtractor's
_last_connection_meta) and reads it internally for their own confidence/scoring
logic -- it was simply never threaded into Evidence.domain at creation time.
run_detection_cycle() below supplies it as the v13 ingest adapter's
fallback_context, using data the detector already had, not a new guess.
"""
import json
import logging
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from v13.evidence.ingest import convert_list
from v13.hypotheses.independence import INDEPENDENCE_FAMILY_MAP

LOGGER = logging.getLogger("v13.ingest.sources")

# Evidence types whose v-current detector (threat_signals.py:247-274) computes a
# real destination internally (features["last_dest_ip"]) but never attaches it to
# the Evidence it creates -- see A2 above. Kept as an explicit, named set (not
# "just always pass fallback_context") so it's visible which two types this is
# actually fixing, and a future detector without the same gap doesn't silently
# get an unnecessary/misleading fallback attached.
_NEEDS_LAST_DEST_IP_FALLBACK = frozenset({"zeek_exfiltration", "zeek_beaconing"})

# ZeekFeatureExtractor._last_connection_meta's own "no data yet" sentinel
# (zeek_features.py:394) -- never a real destination, must not be attached as one.
_NO_DEST_SENTINEL = "unknown"


class ZeekLogSource:
    """Tails one Zeek JSON-lines log file, resuming by (inode, byte offset) across
    restarts. Ports extractors/zeek_features.py's ZeekLogTailer logic verbatim
    (same partial-line-safety and rotation-detection behavior, confirmed via direct
    read of that class) rather than importing it directly, because that class is
    constructed as part of ZeekCollector's own /opt/zeek/logs/current-specific
    wiring (state_dir defaults, a fixed _LOG_FILES table) -- this v13 copy is
    intentionally the same cursor algorithm pointed at an arbitrary mounted
    directory and an independent cursor store, not a fork of new detection logic.

    KNOWN OPEN QUESTION (not resolved this session): .19's CIFS mounts use the
    `serverino` option, so inode numbers are server-assigned (more stable across
    remounts than client-generated ones) -- but whether they survive a real .94
    Samba restart or an actual .19 remount was not tested here (would have
    required disrupting a live mount). Worst case on an inode change is a full
    reprocess of that log file from position 0, not corruption or a crash (same
    "resync, don't corrupt" fallback zeek_features.py's own tailer already has)."""

    def __init__(self, path: Path, event_type: str, cursor_dir: Path):
        self.path = Path(path)
        self.event_type = event_type
        self._pos = 0
        self._inode: Optional[int] = None
        self.cursor_path = Path(cursor_dir) / f"v13_zeek_cursor_{event_type}.json"
        self._load_cursor()
        if self._inode is None:
            self._seek_to_end()

    def _load_cursor(self) -> None:
        if not self.cursor_path.exists():
            return
        try:
            data = json.loads(self.cursor_path.read_text())
            if self.path.exists() and self.path.stat().st_ino == data.get("inode"):
                self._inode = data["inode"]
                self._pos = data["pos"]
        except Exception:
            pass

    def _save_cursor(self) -> None:
        if self._inode is None:
            return
        try:
            self.cursor_path.parent.mkdir(parents=True, exist_ok=True)
            self.cursor_path.write_text(json.dumps({"inode": self._inode, "pos": self._pos}))
        except Exception:
            pass

    def _seek_to_end(self) -> None:
        if not self.path.exists():
            return
        try:
            stat = self.path.stat()
            self._inode = stat.st_ino
            self._pos = stat.st_size
        except OSError:
            pass

    def poll(self, callback: Callable[[str, dict], None]) -> int:
        """Reads any newly-appended, complete JSON lines since the last poll and
        calls callback(event_type, parsed_dict) for each. Returns the count
        processed. A partial (not yet newline-terminated) trailing line is left
        for the next poll, matching zeek_features.py's own crash-avoidance fix."""
        count = 0
        if not self.path.exists():
            return 0
        try:
            stat = self.path.stat()
            if stat.st_ino != self._inode or stat.st_size < self._pos:
                self._pos = 0
                self._inode = stat.st_ino
            if stat.st_size <= self._pos:
                return 0

            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._pos)
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n"):
                        break
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#"):
                        self._pos = f.tell()
                        continue
                    try:
                        event = json.loads(clean_line)
                        event["_zeek_type"] = self.event_type
                        callback(self.event_type, event)
                        count += 1
                    except json.JSONDecodeError:
                        LOGGER.debug("Skipping malformed Zeek JSON line in %s", self.path)
                    self._pos = f.tell()
                self._save_cursor()
        except OSError as exc:
            LOGGER.debug("Zeek log %s unreadable this poll: %s", self.path, exc)
        return count


# Log files this module wires up, matching zeek_features.py's own _LOG_FILES table
# (arp.log requires zeek_scripts/local-arp-log.zeek to be loaded on .94, same
# deployment dependency v-current itself already documents -- silently produces
# nothing if absent, not an error).
ZEEK_LOG_FILES = ("conn.log", "dns.log", "http.log", "ssl.log", "notice.log",
                    "weird.log", "dhcp.log", "arp.log")


def build_zeek_sources(mount_dir: Path, cursor_dir: Path) -> Dict[str, ZeekLogSource]:
    """One ZeekLogSource per file in ZEEK_LOG_FILES, keyed by event type
    (conn/dns/http/ssl/notice/weird/dhcp/arp -- weird.log shares the "weird"
    type, matching ZeekFeatureExtractor.ingest()'s own etype dispatch)."""
    mount_dir = Path(mount_dir)
    sources = {}
    for filename in ZEEK_LOG_FILES:
        event_type = filename[:-len(".log")]
        sources[event_type] = ZeekLogSource(mount_dir / filename, event_type, cursor_dir)
    return sources


def poll_all(sources: Dict[str, ZeekLogSource], extractor) -> int:
    """Feeds every newly-tailed event from every source into extractor.ingest()
    (extractors/zeek_features.py's real ZeekFeatureExtractor, imported and used
    unmodified by the caller) -- extractor does its own etype dispatch via
    event["_zeek_type"], set by ZeekLogSource.poll() above."""
    total = 0
    for source in sources.values():
        total += source.poll(lambda _etype, event: extractor.ingest(event))
    return total


def _build_fallback_context(evidence_type: str, features: dict) -> Optional[Dict[str, str]]:
    """A2: only for the two known-gap evidence types, and only when
    features["last_dest_ip"] is a genuine destination, not
    ZeekFeatureExtractor's own "no connection seen yet" sentinel."""
    if evidence_type not in _NEEDS_LAST_DEST_IP_FALLBACK:
        return None
    dest_ip = str(features.get("last_dest_ip", "") or "")
    if not dest_ip or dest_ip == _NO_DEST_SENTINEL:
        return None
    return {"dest_ip": dest_ip}


def run_detection_cycle(extractor, detector, device_ip, ti_engine=None,
                          arp_sweep_threshold: int = 8,
                          conn_abuse_unique_ip_threshold: int = 5,
                          long_conn_duration_threshold: float = 14400.0,
                          now: Optional[float] = None):
    """Runs v-current's real ThreatSignalDetector.detect() against v-current's
    real ZeekFeatureExtractor.get_features() output for one device, then converts
    the resulting v1 Evidence into v13 Evidence v2, closing A2 for the two
    evidence types that need it.

    HONEST SCOPE NOTE: features here is Zeek-derived only (this module doesn't
    wire dns_features.py's Pi-hole-derived stats -- see the module docstring),
    so detect()'s DNS-behavior branches (dns_dga_burst, dns_tunnel_v2, and the
    is_telemetry/top_domain-gated branches) will not fire from this call --
    every key they read defaults to 0.0/None via features.get(...), which is
    the same safe default detect() already falls back to for a device with no
    data for that signal, not a new failure mode. Zeek-native evidence types
    (zeek_exfiltration, zeek_beaconing, malicious_ja3/ja4, zeek_notice,
    zeek_lateral_scan/conn_abuse, arp_sweep) DO fire correctly from this call.

    Returns a list of v13 Evidence v2 objects, ready for GraphStore.insert_evidence().
    """
    features = extractor.get_features(device_ip)
    v1_evidence = detector.detect(
        device_ip, features, top_domain=None,
        arp_sweep_threshold=arp_sweep_threshold,
        conn_abuse_unique_ip_threshold=conn_abuse_unique_ip_threshold,
        long_conn_duration_threshold=long_conn_duration_threshold,
        ti_engine=ti_engine,
    )
    if not v1_evidence:
        return []

    # detect() can return a mix of evidence types in one call, but convert_list()
    # applies a single fallback_context to the whole batch -- split by whether
    # each item actually needs the last-dest-ip fallback so a zeek_notice item
    # (which has no gap) never gets a misleading destination attached alongside
    # a zeek_exfiltration item that does.
    needs_fallback = [ev for ev in v1_evidence if ev.type in _NEEDS_LAST_DEST_IP_FALLBACK]
    no_fallback_needed = [ev for ev in v1_evidence if ev.type not in _NEEDS_LAST_DEST_IP_FALLBACK]

    out = []
    if no_fallback_needed:
        out.extend(convert_list(no_fallback_needed, INDEPENDENCE_FAMILY_MAP))
    if needs_fallback:
        # All items in this sub-batch share the same evidence-type set gate above,
        # and features (hence last_dest_ip) is identical for every item from this
        # single detect() call -- one fallback_context genuinely applies to all of them.
        fallback_context = _build_fallback_context(needs_fallback[0].type, features)
        out.extend(convert_list(needs_fallback, INDEPENDENCE_FAMILY_MAP, fallback_context=fallback_context))
    return out
