"""
v13 live ingestion daemon (Phase 7 wiring -- Documentation/V13_REMAINING_WORK.md
item A3). The long-running process src/v13/ingest/sources.py's own docstring
said didn't exist yet: wraps ZeekLogSource/run_detection_cycle (sources.py) into
a continuous poll loop, running v-current's real ZeekFeatureExtractor +
ThreatSignalDetector (imported, unmodified) against .19's SMB-mounted copy of
.94's Zeek logs, and writes the resulting v13 Evidence into a GraphStore.

Deliberately separate from sources.py itself: sources.py is tested, dependency-
injected library code (a fake extractor/detector in its own test file, no real
I/O); this module is the untested-by-nature orchestration shell around it (real
file paths, real signal handling, a real sleep loop) -- keeping that boundary
means sources.py's actual detection-adapter logic stays fully unit-testable,
matching every other v13 module's "pure logic vs. thin runnable wrapper" split
(e.g. retro_hunter.py's hunt() vs. its own __main__ block).

Run: `python3 src/v13/ingest/daemon.py [path/to/config_v13.yaml]`
Config: see config_v13.example.yaml's `ingest:` section and `network.subnets`.
If no real config_v13.yaml is found, falls back to config_v13.example.yaml's
own dummy subnets (192.168.1.0/24, 192.168.50.0/24) -- LOUDLY, via a startup
CRITICAL log line, not silently, since a real deployment running against the
wrong home_subnets would quietly classify all real LAN traffic as "not home"
and produce degraded evidence without any crash to notice by. Matches
config.yaml's own real-vs-.example split and its 2026-08-29 incident note
(Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md) -- same failure shape, same
fix: never hardcode the real subnet into committed code, but make a missing
real config loud, not silent.
"""
import logging
import signal
import sys
import time
from pathlib import Path
from typing import Set

import yaml

_SRC_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_SRC_DIR))

from extractors.zeek_features import ZeekFeatureExtractor  # noqa: E402
from intelligence.detectors.threat_signals import ThreatSignalDetector  # noqa: E402
from v13.graph.store import GraphStore, DEFAULT_EVIDENCE_RETENTION_DAYS  # noqa: E402
from v13.ingest.sources import build_zeek_sources, run_detection_cycle  # noqa: E402

LOGGER = logging.getLogger("v13.ingest.daemon")

_EXAMPLE_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config_v13.example.yaml"
_DEFAULT_REAL_CONFIG_PATH = _SRC_DIR.parent / "config_v13.yaml"


def load_config(explicit_path: str = None) -> dict:
    """Loads config_v13.yaml (real, gitignored -- same split as config.yaml vs
    config.yaml.example) if present; otherwise falls back to the committed
    .example file's dummy values, logging CRITICAL so a real deployment missing
    its real config doesn't fail silently -- see module docstring."""
    candidate = Path(explicit_path) if explicit_path else _DEFAULT_REAL_CONFIG_PATH
    if candidate.exists():
        LOGGER.info("Loaded real config from %s", candidate)
        return yaml.safe_load(candidate.read_text()) or {}

    LOGGER.critical(
        "No real config found at %s -- falling back to %s's DUMMY example subnets "
        "(192.168.1.0/24, 192.168.50.0/24). Real LAN traffic will be misclassified "
        "as non-home until a real config_v13.yaml is created. This is intentional "
        "fail-loud behavior, not a crash -- see daemon.py's module docstring.",
        candidate, _EXAMPLE_CONFIG_PATH,
    )
    return yaml.safe_load(_EXAMPLE_CONFIG_PATH.read_text()) or {}


class IngestDaemon:
    def __init__(self, config: dict):
        ingest_cfg = config.get("ingest", {})
        network_cfg = config.get("network", {})

        self.poll_interval = float(ingest_cfg.get("poll_interval_seconds", 2.0))
        self.prune_interval = float(ingest_cfg.get("prune_interval_seconds", 3600))
        self.retention_days = float(ingest_cfg.get("evidence_retention_days",
                                                       DEFAULT_EVIDENCE_RETENTION_DAYS))

        mount_dir = Path(ingest_cfg.get("zeek_mount_dir", "/mnt/v13-zeek"))
        cursor_dir = Path(ingest_cfg.get("cursor_dir", "state/v13_ingest_cursors"))
        graph_db_path = Path(ingest_cfg.get("graph_db_path", "state/v13_graph.db"))
        graph_db_path.parent.mkdir(parents=True, exist_ok=True)

        subnets = network_cfg.get("subnets", ["192.168.1.0/24", "192.168.50.0/24"])

        self.extractor = ZeekFeatureExtractor(home_subnets=subnets)
        self.detector = ThreatSignalDetector()
        self.store = GraphStore(str(graph_db_path))
        self.sources = build_zeek_sources(mount_dir, cursor_dir)

        self._running = True
        self._last_prune = time.time()

        LOGGER.info(
            "IngestDaemon initialized: mount=%s cursor_dir=%s graph_db=%s "
            "poll_interval=%.1fs subnets=%s",
            mount_dir, cursor_dir, graph_db_path, self.poll_interval, subnets,
        )

    def stop(self, *_args) -> None:
        LOGGER.info("Shutdown signal received -- finishing current cycle then exiting.")
        self._running = False

    def _poll_once(self) -> Set[str]:
        """Polls every Zeek source, feeds events into the extractor, and returns
        the set of device (source) IPs seen this cycle -- run_detection_cycle()
        needs one call per device, not one call per raw event, since
        ThreatSignalDetector.detect() operates on a device's AGGREGATE features,
        not a single event."""
        devices_seen: Set[str] = set()

        def _callback(_event_type: str, event: dict) -> None:
            self.extractor.ingest(event)
            src = event.get("id.orig_h") or event.get("orig_h") or event.get("spa")
            if src:
                devices_seen.add(src)

        for source in self.sources.values():
            source.poll(_callback)
        return devices_seen

    def _run_cycle(self) -> int:
        devices = self._poll_once()
        total_evidence = 0
        for device_ip in devices:
            evidence_items = run_detection_cycle(self.extractor, self.detector, device_ip)
            for ev in evidence_items:
                self.store.insert_evidence(ev)
            total_evidence += len(evidence_items)

        now = time.time()
        if now - self._last_prune >= self.prune_interval:
            deleted = self.store.prune_evidence(older_than_days=self.retention_days, now=now)
            if deleted:
                LOGGER.info("Pruned %d evidence rows older than %.0f days.", deleted, self.retention_days)
            self._last_prune = now

        return total_evidence

    def run(self) -> None:
        LOGGER.info("IngestDaemon starting main loop (poll_interval=%.1fs).", self.poll_interval)
        cycles = 0
        while self._running:
            cycle_start = time.time()
            try:
                evidence_count = self._run_cycle()
                if evidence_count:
                    LOGGER.info("Cycle %d: %d new evidence item(s) written.", cycles, evidence_count)
            except Exception:
                LOGGER.exception("Unhandled error in ingest cycle %d -- continuing, not crashing "
                                   "(matches this codebase's own detector-resilience convention: "
                                   "one bad cycle must not take the whole daemon down).", cycles)
            cycles += 1
            elapsed = time.time() - cycle_start
            time.sleep(max(0.05, self.poll_interval - elapsed))
        LOGGER.info("IngestDaemon stopped cleanly after %d cycles.", cycles)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    explicit_path = sys.argv[1] if len(sys.argv) > 1 else None
    config = load_config(explicit_path)
    daemon = IngestDaemon(config)
    signal.signal(signal.SIGTERM, daemon.stop)
    signal.signal(signal.SIGINT, daemon.stop)
    daemon.run()


if __name__ == "__main__":
    main()
