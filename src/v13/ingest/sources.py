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

A5 (V13_REMAINING_WORK.md -- Pi-hole/DNS-behavior evidence, added 2026-09-06):
PiHoleLogSource/PiHoleFeatureStore below close this. Pi-hole's FTL sqlite DB
still isn't mount-accessible (see above), so this reconstructs
PiHoleCollector's (domain, client, status) triples from pihole.log's own
dnsmasq-format text lines instead -- a NEW parser, not a port of existing
code, because no existing v-current code reads this text format at all (only
the sqlite DB). Once reconstructed, feature COMPUTATION itself is still fully
reused: core/state.py's real RollingWindow + extractors/dns_features.py's
real FeatureExtractor.compute(), both imported unmodified. See
PiHoleLogSource's own docstring for the exact dnsmasq log grammar this
targets (confirmed via direct grep against .19's live pihole.log, not
assumed) and its documented correlation limitations.

A11 (found 2026-09-06 while root-causing a real divergence flagged on the
live comparator dashboard): run_detection_cycle() below originally called
ONLY ThreatSignalDetector.detect() -- but pipeline.py's own real per-cycle
loop (pipeline.py:990,994) ALSO runs two more detectors every cycle that
this module never wired in at all: ZeekNetworkDetector (malicious_ja3/
malicious_ja4/zeek_notice, sourced from ZeekFeatureExtractor.get_alerts()'s
raw event list -- a genuinely SEPARATE data path from get_features()'s
aggregate counters, not a subset of it) and DNSBehaviorDetector (dns_rate/
dns_entropy/dns_unique_ratio, from the same features dict). CONCRETE IMPACT
CONFIRMED, not theoretical: a real device (192.168.77.46) had v-current
reach HIGH/INTERNAL_RECONNAISSANCE (2 independent sources: arp_sweep +
zeek_notice) while v13 reached only SUSPICIOUS for the IDENTICAL attack
hypothesis and score (INTERNAL_RECONNAISSANCE, 3.0) -- v13's own graph had
ONLY EVER recorded arp_sweep for this device, ever. This was NOT a genuine
independence-family-grouping disagreement (the actual question A10/#7 is
about) -- it was v13 simply never having produced zeek_notice evidence at
all, an entirely different, more basic coverage gap. Left unfixed, this
would have confounded every future divergence-comparison run: DIFFERENT_PATH/
V13_ONLY findings would mix real family-grouping questions with this
unrelated evidence-coverage gap, made worse the longer it went unnoticed
(more accumulated data to discard/re-derive once found). Both detectors are
tiny (51 and 56 lines), dependency-free, real v-current classes -- reused
here unmodified, not new detection logic, just wiring that was missing.
"""
import json
import logging
import re
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from collections import deque

from core.state import BoundedSet, RollingWindow
from intelligence.reputation.classifier import ReputationClassifier
from v13.decision.engine import DecisionEngine
from v13.graph.store import GraphStore
from v13.graph.window import RollingWindowView
from extractors.dns_features import FeatureExtractor
from intelligence.detectors.dns_behavior import DNSBehaviorDetector
from intelligence.detectors.zeek_network import ZeekNetworkDetector
from v13.evidence.ingest import convert_list
from v13.evidence.model import NO_DESTINATION
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

# A11: both classes are stateless (ZeekNetworkDetector has no __init__ state at
# all; DNSBehaviorDetector's is `pass`) -- module-level singletons, not
# reconstructed every run_detection_cycle() call.
_ZEEK_NETWORK_DETECTOR = ZeekNetworkDetector()
_DNS_BEHAVIOR_DETECTOR = DNSBehaviorDetector()


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
                          now: Optional[float] = None,
                          dns_features: Optional[dict] = None):
    """Runs v-current's real ThreatSignalDetector.detect() against v-current's
    real ZeekFeatureExtractor.get_features() output for one device, then converts
    the resulting v1 Evidence into v13 Evidence v2, closing A2 for the two
    evidence types that need it.

    dns_features (A5, optional): the dict PiHoleFeatureStore.compute_features()
    returns for this device -- merged into the Zeek-derived features before
    calling detect(), so DNS-behavior branches (dns_dga_burst, dns_tunnel_v2)
    can fire from real Pi-hole-derived data too. No key collisions between the
    two sources (Zeek's own keys are all zeek_*-prefixed or connection-meta;
    DNS's are dns_features.py's own compute()/_zero_features() key set) --
    confirmed by direct comparison of both dicts' keys, not assumed. When
    omitted (the default), behavior is unchanged from before A5: DNS-behavior
    branches simply don't fire (every key they read defaults via
    features.get(key, 0.0/None), the same "no signal" default a real device
    with no data produces, not a new failure mode).

    top_domain is still not wired (stays None) even with dns_features supplied
    -- a real, flagged simplification: detect()'s is_telemetry/
    is_vendor_cloud_api dampening (which needs a "most notable domain this
    cycle" value neither compute() nor this module currently derives) won't
    suppress telemetry-heavy devices' DNS evidence the way v-current's live
    behavior does. The two domain-EXAMPLE branches (dns_dga_burst's specific-
    domain paths) are unaffected -- they already exclude telemetry domains at
    the source (dns_features.py's own compute()), matching #17's whole point.

    Returns a list of v13 Evidence v2 objects, ready for GraphStore.insert_evidence().
    """
    features = extractor.get_features(device_ip)
    if dns_features:
        features = {**features, **dns_features}
    v1_evidence = list(detector.detect(
        device_ip, features, top_domain=None,
        arp_sweep_threshold=arp_sweep_threshold,
        conn_abuse_unique_ip_threshold=conn_abuse_unique_ip_threshold,
        long_conn_duration_threshold=long_conn_duration_threshold,
        ti_engine=ti_engine,
    ))

    # A11 (found 2026-09-06 while investigating a real, misleading divergence
    # on the live comparator dashboard -- see V13_REMAINING_WORK.md): pipeline.py
    # runs TWO MORE detectors alongside ThreatSignalDetector every real cycle
    # (pipeline.py:990,994) that this function never called at all --
    # ZeekNetworkDetector (malicious_ja3/malicious_ja4/zeek_notice, from
    # ZeekFeatureExtractor.get_alerts()'s raw event list, a completely separate
    # data path from get_features()'s aggregate counters) and
    # DNSBehaviorDetector (dns_rate/dns_entropy/dns_unique_ratio, from the same
    # features dict). Both are tiny, dependency-free, real v-current classes,
    # reused here unmodified -- not new detection logic, just wiring that was
    # missing. ZeekNetworkDetector already sets its own Evidence.domain
    # directly (unlike zeek_exfiltration/beaconing), so neither of these two
    # need fallback_context.
    v1_evidence.extend(_ZEEK_NETWORK_DETECTOR.detect(device_ip, extractor.get_alerts(device_ip)))
    v1_evidence.extend(_DNS_BEHAVIOR_DETECTOR.detect(device_ip, features))

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


# --- A5: Pi-hole DNS-behavior ingestion (pihole.log text parsing) --------------

# dns_features.py's BLOCKED/NXDOMAIN frozensets check STATUS CODE membership,
# not any specific code's meaning -- so this module is free to pick its own
# representative codes as long as they land in the right bucket. 1 and 3 are
# chosen to match real Pi-hole FTL codes for "gravity blocked" and "NXDOMAIN"
# respectively (both already members of BLOCKED/NXDOMAIN in dns_features.py),
# so a reader cross-checking against real Pi-hole documentation isn't misled
# by an arbitrary made-up number; 2 (a real Pi-hole "forwarded/allowed" code)
# is used for everything else, since neither frozenset contains it.
_STATUS_BLOCKED = 1
_STATUS_ALLOWED = 2
_STATUS_NXDOMAIN = 3

# Verb phrases confirmed via direct grep against .19's live pihole.log
# (2026-09-06) that mean "this query was refused an answer": Pi-hole's own
# gravity/blacklist block, and dnsmasq's own built-in anti-WPAD-hijack refusal
# (--stop-dns-rebind-style exact-domain denial, seen live for wpad.fritz.box).
# NOT exhaustively researched against dnsmasq's full source -- a verb this
# deployment hasn't produced yet (e.g. a regex-list block, which needs a
# regex blocklist actually configured to ever appear) would silently fall
# through to _STATUS_ALLOWED instead of _STATUS_BLOCKED, an honest, bounded
# gap, not a crash risk.
_PIHOLE_BLOCKED_VERBS = frozenset({"gravity blocked", "exactly denied"})

_QUERY_LINE_RE = re.compile(r"^query\[(\S+)\]\s+(\S+)\s+from\s+(\S+)$")
_SYSLOG_PREFIX_RE = re.compile(r"^\S+\s+\d+\s+\d+:\d+:\d+\s+dnsmasq\[\d+\]:\s*(.*)$")


class PiHoleLogSource:
    """Tails Pi-hole's dnsmasq-format text log (pihole.log), reconstructing
    (timestamp, domain, client_ip, status_code, qtype) query events -- the
    same shape core/pipeline.py's own PiHoleCollector.poll()-consuming loop
    builds from the FTL sqlite DB (state.py:664-675), just derived from text
    instead of a DB row, since the DB isn't mount-accessible (see this
    module's own top docstring, A5).

    GRAMMAR (confirmed via direct grep against .19's live pihole.log,
    2026-09-06, not assumed from generic dnsmasq documentation): each query
    is logged as a `query[TYPE] domain from client_ip` line, immediately
    followed by one or more resolution lines of the shape
    `<verb> <domain> is <value>` (`gravity blocked`, `exactly denied`,
    `cached`, `cached-stale`, `reply`, `config`, `special domain`, or a
    literal blocklist-file path like `/etc/pihole/hosts/custom.list`) -- an
    intermediate `forwarded <domain> to <resolver>` line (no `is`) is not
    terminal and is skipped. A CNAME chain produces resolution lines for
    domains that never had their OWN `query[...] from` line (the chain's
    intermediate hops) -- those have no pending entry to correlate against
    and are correctly, silently skipped, not misattributed.

    KNOWN, DOCUMENTED LIMITATION: resolution lines carry no client identifier
    of their own -- correlation is by domain name against the most recent
    unresolved query for that exact domain. Two different devices querying
    the EXACT SAME domain within the same unresolved window (rare but
    possible) could have the second query's resolution wrongly attributed to
    the first device. Bounded, not silent: worth revisiting only if real
    divergence data ever traces back to it.

    Timestamps use the TAILING side's wall-clock read time (time.time()), not
    a parsed syslog timestamp -- syslog's classic `%b %d %H:%M:%S` format
    carries no year and no explicit timezone, genuinely ambiguous to parse
    correctly, whereas Zeek's JSON logs (ZeekLogSource above) carry a precise
    epoch `ts` field directly and don't have this problem. A small
    write-to-poll latency skew is an acceptable trade against a wrong-year
    silent misparse."""

    def __init__(self, path: Path, cursor_dir: Path):
        self.path = Path(path)
        self._pos = 0
        self._inode: Optional[int] = None
        self.cursor_path = Path(cursor_dir) / "v13_pihole_cursor.json"
        self._pending: Dict[str, Tuple[float, str, str]] = {}
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

    @staticmethod
    def _classify(verb: str, value: str) -> int:
        if verb in _PIHOLE_BLOCKED_VERBS:
            return _STATUS_BLOCKED
        if value.strip() == "NXDOMAIN":
            return _STATUS_NXDOMAIN
        return _STATUS_ALLOWED

    def _process_message(self, msg: str) -> Optional[Tuple[float, str, str, int, str]]:
        m = _QUERY_LINE_RE.match(msg)
        if m:
            qtype, domain, client_ip = m.groups()
            self._pending[domain] = (time.time(), client_ip, qtype)
            return None

        if " is " not in msg:
            return None  # e.g. "forwarded X to Y" -- intermediate, not terminal
        prefix, _, value = msg.rpartition(" is ")
        if " " not in prefix:
            return None
        verb, _, domain = prefix.rpartition(" ")
        pending = self._pending.pop(domain, None)
        if pending is None:
            return None
        ts, client_ip, qtype = pending
        status_code = self._classify(verb, value)
        return (ts, domain, client_ip, status_code, qtype)

    def poll(self, callback: Callable[[float, str, str, int, str], None]) -> int:
        """Reads any newly-appended, complete lines since the last poll,
        calling callback(ts, domain, client_ip, status_code, qtype) for each
        fully-correlated query event. Returns the count processed."""
        count = 0
        if not self.path.exists():
            return 0
        try:
            stat = self.path.stat()
            if stat.st_ino != self._inode or stat.st_size < self._pos:
                self._pos = 0
                self._inode = stat.st_ino
                self._pending.clear()
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
                    raw = line.rstrip("\n")
                    self._pos = f.tell()
                    m = _SYSLOG_PREFIX_RE.match(raw)
                    if not m:
                        continue
                    result = self._process_message(m.group(1))
                    if result is not None:
                        callback(*result)
                        count += 1
                self._save_cursor()
        except OSError as exc:
            LOGGER.debug("Pi-hole log %s unreadable this poll: %s", self.path, exc)
        return count


class PiHoleFeatureStore:
    """Per-device DNS rolling state + feature computation, reusing
    core/state.py's real RollingWindow and extractors/dns_features.py's real
    FeatureExtractor.compute() UNCHANGED -- this class's only job is
    populating RollingWindow the same way core/pipeline.py itself does
    (state.py:664-675, confirmed via direct read) from PiHoleLogSource's
    events instead of a live PiHoleCollector.poll() row."""

    class _RollingOnlyState:
        """The minimal shape FeatureExtractor.compute() actually reads --
        confirmed exhaustively via `grep -oE 'state\\.[a-zA-Z_]+' ` against
        compute()'s own body (lines 254-511), not assumed or discovered one
        AttributeError at a time: `.rolling`, `.seen_domains` (a BoundedSet),
        and `.killchain_history` (a deque(maxlen=5), matching core/state.py's
        own DeviceState field exactly). NOT a fork of DeviceState itself,
        which carries substantially more (baselines, identity, mitigation
        flags) that compute() never touches."""
        __slots__ = ("rolling", "seen_domains", "killchain_history")

        def __init__(self) -> None:
            self.rolling = RollingWindow()
            self.seen_domains = BoundedSet(max_size=10000)
            self.killchain_history = deque(maxlen=5)

    def __init__(self) -> None:
        self._states: Dict[str, "PiHoleFeatureStore._RollingOnlyState"] = {}
        self._extractor = FeatureExtractor()

    def ingest_query(self, ts: float, domain: str, client_ip: str,
                       status_code: int, qtype: str) -> None:
        """Mirrors core/pipeline.py's own RollingWindow population exactly
        (state.py:667-675): events/long_events append, blocked/nxdomain
        counters, domains Counter, domain_timestamps. dns_qtypes is fed the
        REAL DNS query type string (from pihole.log's own `query[TYPE]`
        line) rather than v-current's `row.get("reply_type", 0)` (a Pi-hole
        FTL reply-type DB column unavailable from text logs) -- a deliberate,
        flagged divergence: this field's own comment in state.py says it
        "Tracks DNS qtypes (A, AAAA, TXT, NULL, ANY, MX)," which the real
        query type actually matches; reply_type's numeric FTL code does not."""
        state = self._states.setdefault(client_ip, self._RollingOnlyState())
        rw = state.rolling
        rw.events.append((ts, domain, status_code))
        rw.long_events.append((ts, domain, status_code, qtype))
        rw.dns_qtypes[qtype] += 1
        if status_code == _STATUS_BLOCKED:
            rw.blocked += 1
        if status_code == _STATUS_NXDOMAIN:
            rw.nxdomain += 1
        rw.domains[domain] += 1
        rw.domain_timestamps[domain].append(ts)

    def compute_features(self, device_ip: str, now: Optional[float] = None,
                           window_seconds: int = 300) -> dict:
        """Returns dns_features.py's real compute() output for one device --
        _zero_features() (all zeros/empties) for a device this store has
        never seen a query for, matching compute()'s own no-data behavior.

        Mirrors core/pipeline.py's own post-compute step exactly
        (pipeline.py:1270-1272): after computing this cycle's "new_domains"
        count (which needs seen_domains to still reflect ONLY prior cycles,
        not this one), this cycle's domains are folded into seen_domains for
        next time -- done here, not inside compute() itself, matching where
        v-current does it."""
        state = self._states.get(device_ip)
        if state is None:
            return self._extractor._zero_features()
        features = self._extractor.compute(state, now if now is not None else time.time(), window_seconds)
        for domain in state.rolling.domains.keys():
            state.seen_domains.add(domain)
        return features


# --- A7: v13 decision computation (prerequisite for the automated flip monitor) ---
#
# HONEST GAP, found while wiring this (2026-09-06): the plan's own "Automated
# incremental flips" section describes gap_monitor.py evaluating DIVERGENCE
# DATA between v13 and v-current -- but until now, nothing on .19 ever
# computed a v13 DECISION at all; run_detection_cycle() (above) only ever
# produced and stored EVIDENCE. There was no verdict to diverge from anything.
# This section closes that gap using v13's own already-built, already-tested
# HypothesisEngine + DecisionEngine (Phase 3) -- genuinely new WIRING, not new
# detection logic.
#
# Reputation is real but deliberately partial: ReputationClassifier
# (intelligence/reputation/classifier.py) is reused UNCHANGED, but called with
# every external score (vt_score/ti_score/abuse_score) at its zero default --
# no live VirusTotal/AbuseIPDB/ThreatIntel API wiring exists on .19. This means
# tier can reach 0/1/2/3 (static known-domain/ASN-based classification, all
# real) but never 4/5 (which need a real external signal) from this path alone
# -- a real, bounded limitation, not fake data standing in for real data.


def compute_decision(store: GraphStore, device_id: str,
                       decision_engine: Optional[DecisionEngine] = None,
                       reputation_classifier: Optional[ReputationClassifier] = None,
                       window_seconds: float = RollingWindowView.LONG_WINDOW_SECONDS,
                       now: Optional[float] = None,
                       only_persist_if_changed_from: Optional[Tuple[str, str]] = None
                       ) -> Optional[Tuple[dict, Optional[str]]]:
    """Queries this device's accumulated graph evidence (a fresh snapshot each
    call, via RollingWindowView -- never a mutated cross-cycle object, matching
    every other v13 module's pure-per-cycle evaluation model), classifies a
    representative destination's reputation, and runs the real DecisionEngine.
    Returns (decision_dict, decision_id), or None if this device has no
    evidence in the window yet (nothing to decide).

    only_persist_if_changed_from, if given, is the caller's own
    (state, decision_path) from this device's last PERSISTED decision -- if
    the freshly-computed decision matches it exactly, nothing is written to
    the decisions table and decision_id comes back None (the decision is
    still fully computed and returned either way, so a caller re-evaluating
    every cycle -- matching v-current's own re-evaluate-every-poll pattern --
    doesn't have to call this twice). Without it, every call persists
    unconditionally, matching this function's original behavior. This exists
    because a live daemon calling compute_decision() every poll interval for
    every active device would otherwise write a near-identical row every
    cycle forever, turning the decisions table (meant as a bounded audit
    trail for Phase 7's divergence comparator) into an unbounded, mostly-
    redundant log -- the same "don't re-alert on unchanged state" discipline
    this codebase already applies elsewhere (e.g. reset_client() after an
    alert)."""
    now = now if now is not None else time.time()
    decision_engine = decision_engine or DecisionEngine()
    reputation_classifier = reputation_classifier or ReputationClassifier()

    window = RollingWindowView(store)
    evidence_list = window.evidence_in_window(device_id, window_seconds, now=now)
    if not evidence_list:
        return None

    # The most recently-observed real destination stands in for "the
    # destination this cycle's decision is about" -- matches this codebase's
    # own established preference (pipeline.py's target-selection logic, and
    # v13's own evidence/ingest.py fallback_context) for "most recent known
    # attribution" when no single canonical target is otherwise obvious.
    target_domain = ""
    for ev in reversed(evidence_list):
        if ev.destination_id != NO_DESTINATION:
            target_domain = ev.destination_id
            break
    rep = reputation_classifier.classify(target_domain)

    decision = decision_engine.evaluate(evidence_list, rep, now=now)

    if only_persist_if_changed_from is not None:
        current_key = (decision["state"], decision["decision_path"])
        if current_key == only_persist_if_changed_from:
            return decision, None

    decision_id = store.insert_decision(
        device_id=device_id,
        timestamp=now,
        state=decision["state"],
        decision_path=decision["decision_path"],
        confidence=float(decision.get("threat_confidence", 0.0) or 0.0),
        risk_score=float(decision.get("hypotheses", {}).get("attack", {}).get("score", 0.0) or 0.0),
        raw_payload=decision,
    )
    return decision, decision_id
