"""
Standalone runtime test for v13's live ingestion daemon (src/v13/ingest/daemon.py,
Phase 7 wiring -- Documentation/V13_REMAINING_WORK.md item A3).

Covers: load_config()'s real-config-vs-example-fallback split (and that the
fallback is genuinely loud, not silent); IngestDaemon construction (sources
built, graph db directory created); _poll_once()'s per-device aggregation
across event types including arp's spa field; and _run_cycle()'s end-to-end
wiring -- a real massive-outbound-burst Zeek event, through the REAL (not
mocked) ZeekFeatureExtractor + ThreatSignalDetector, lands as real Evidence
in a real GraphStore with a genuine destination_id (the same live behavior
already spot-checked manually while building sources.py, now pinned as a
regression test).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_v13_ingest_daemon.py`
"""
import logging
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath

sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from v13.ingest.daemon import load_config, IngestDaemon, _EXAMPLE_CONFIG_PATH  # noqa: E402


# --- load_config: explicit real path ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    real_config_path = tmp_path / "config_v13.yaml"
    real_config_path.write_text(
        "network:\n  subnets:\n    - 10.0.0.0/24\ningest:\n  poll_interval_seconds: 5.0\n",
        encoding="utf-8",
    )
    cfg = load_config(str(real_config_path))
    check("load_config reads a real, explicitly-given config file",
          cfg.get("network", {}).get("subnets") == ["10.0.0.0/24"])
    check("real config values are used as given, not merged with example defaults",
          cfg.get("ingest", {}).get("poll_interval_seconds") == 5.0)

    # --- load_config: missing path falls back to the example, loudly ---
    missing_path = tmp_path / "does_not_exist.yaml"

    class _CaptureHandler(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record)

    capture = _CaptureHandler()
    logging.getLogger("v13.ingest.daemon").addHandler(capture)
    logging.getLogger("v13.ingest.daemon").setLevel(logging.CRITICAL)
    cfg_fallback = load_config(str(missing_path))
    logging.getLogger("v13.ingest.daemon").removeHandler(capture)

    check("a missing real config falls back to the committed example config's subnets",
          cfg_fallback.get("network", {}).get("subnets") == ["192.168.1.0/24", "192.168.50.0/24"])
    check("falling back to the example config logs a CRITICAL line, not a silent default",
          any(r.levelno == logging.CRITICAL for r in capture.records))
    check(".example config file this falls back to actually exists on disk",
          _EXAMPLE_CONFIG_PATH.exists())


# --- IngestDaemon construction ---
with tempfile.TemporaryDirectory() as tmp:
    tmp_path = _PathForSysPath(tmp)
    mount_dir = tmp_path / "mount"
    mount_dir.mkdir()
    graph_db_path = tmp_path / "nested" / "v13_graph.db"
    pihole_log_path = tmp_path / "pihole.log"
    pihole_log_path.write_text("", encoding="utf-8")

    config = {
        "network": {"subnets": ["192.168.77.0/24"]},
        "ingest": {
            "zeek_mount_dir": str(mount_dir),
            "pihole_log_path": str(pihole_log_path),
            "cursor_dir": str(tmp_path / "cursors"),
            "graph_db_path": str(graph_db_path),
            "poll_interval_seconds": 0.01,
            "prune_interval_seconds": 3600,
        },
    }
    daemon = IngestDaemon(config)
    check("IngestDaemon builds one Zeek source per configured log file", len(daemon.sources) > 0)
    check("IngestDaemon builds a Pi-hole log source and DNS feature store (A5)",
          daemon.pihole_source is not None and daemon.pihole_store is not None)
    check("IngestDaemon creates the graph db's parent directory if missing", graph_db_path.parent.exists())
    check("IngestDaemon opens a real GraphStore", daemon.store is not None)

    # --- _poll_once: device aggregation across event types, including arp's spa ---
    with open(mount_dir / "conn.log", "a", encoding="utf-8") as f:
        f.write('{"ts": 1.0, "id.orig_h": "192.168.77.10", "id.resp_h": "8.8.8.8", '
                 '"id.resp_p": 443, "proto": "tcp", "orig_bytes": 100}\n')
    with open(mount_dir / "arp.log", "a", encoding="utf-8") as f:
        f.write('{"ts": 1.0, "operation": "REQUEST", "spa": "192.168.77.11", "tpa": "192.168.77.1"}\n')

    devices = daemon._poll_once()
    check("_poll_once picks up a device from conn.log's id.orig_h", "192.168.77.10" in devices)
    check("_poll_once picks up a device from arp.log's spa field", "192.168.77.11" in devices)

    # --- _run_cycle: end-to-end with a real massive-outbound-burst pattern ---
    now = time.time()
    # Feed enough real conn events + a synthetic outbound-bytes history (mirroring
    # this session's own manual live sanity check while building sources.py) to
    # cross threat_signals.py's real zeek_exfiltration threshold.
    with open(mount_dir / "conn.log", "a", encoding="utf-8") as f:
        f.write(f'{{"ts": {now}, "id.orig_h": "192.168.77.50", "id.resp_h": "8.8.4.4", '
                 f'"id.resp_p": 443, "proto": "tcp", "orig_bytes": 60000000, '
                 f'"duration": 5.0, "conn_state": "SF"}}\n')
    # Pre-seed extra outbound-byte history BEFORE _run_cycle() does its own single
    # poll+detect pass -- _run_cycle() calls _poll_once() internally exactly once,
    # so the burst line above must still be unread at this point (no separate
    # manual _poll_once() call here) or _run_cycle()'s own poll would see zero
    # new devices and never call run_detection_cycle() for this device at all.
    for _ in range(20):
        daemon.extractor._outbound_bytes["192.168.77.50"].append((now, 60000000))

    evidence_count = daemon._run_cycle()
    check("_run_cycle processes every device seen and reports a nonzero evidence count",
          evidence_count > 0)

    stored = daemon.store.get_evidence_for_device("192.168.77.50")
    exfil_rows = [e for e in stored if e.evidence_type == "zeek_exfiltration"]
    check("a real massive-outbound-burst pattern lands as zeek_exfiltration evidence in the graph store",
          len(exfil_rows) > 0)
    if exfil_rows:
        check("that evidence carries a real destination_id (A2's fix, exercised end-to-end via the daemon)",
              exfil_rows[0].destination_id == "8.8.4.4")

    # --- A5: a device seen ONLY via DNS traffic (no Zeek conn/arp event this
    # cycle) is still picked up and evaluated ---
    with open(pihole_log_path, "a", encoding="utf-8") as f:
        f.write("Sep  6 00:38:15 dnsmasq[1146]: query[A] quiet-device-lookup.example from 192.168.77.70\n")
        f.write("Sep  6 00:38:15 dnsmasq[1146]: cached quiet-device-lookup.example is 1.2.3.4\n")
    devices_dns_only = daemon._poll_once()
    check("_poll_once picks up a device seen only via Pi-hole/DNS traffic, not just Zeek",
          "192.168.77.70" in devices_dns_only)

    # --- A5: a real DNS-tunneling-shaped query (single-label > 55 chars,
    # high entropy) produces real dns_tunnel_v2 evidence via the full daemon,
    # not just at the PiHoleFeatureStore unit-test level (sources.py's own
    # test) ---
    tunneling_label = "b4f19e2a7c3d8f01b4f19e2a7c3d8f01b4f19e2a7c3d8f01b4f19e2a7c3d8f01"  # 64 chars
    tunneling_domain = f"{tunneling_label}.dns-tunnel-test.example"
    with open(pihole_log_path, "a", encoding="utf-8") as f:
        f.write(f"Sep  6 00:39:00 dnsmasq[1146]: query[A] {tunneling_domain} from 192.168.77.71\n")
        f.write(f"Sep  6 00:39:00 dnsmasq[1146]: cached {tunneling_domain} is <CNAME>\n")
    tunnel_evidence_count = daemon._run_cycle()
    check("_run_cycle processes the DNS-tunneling-shaped device and reports evidence",
          tunnel_evidence_count > 0)
    stored_tunnel = daemon.store.get_evidence_for_device("192.168.77.71")
    tunnel_rows = [e for e in stored_tunnel if e.evidence_type == "dns_tunnel_v2"]
    check("a real long, high-entropy DNS label lands as dns_tunnel_v2 evidence via the full daemon (A5)",
          len(tunnel_rows) > 0)

    # --- A7: real decision computation, wired into the daemon, with dedup ---
    decisions_after_first = daemon.store._conn.execute(
        "SELECT COUNT(*) c FROM decisions WHERE device_id = '192.168.77.71'").fetchone()["c"]
    check("_run_cycle produces at least one persisted decision for the tunneling device (A7)",
          decisions_after_first >= 1)
    check("the tunneling device's decision key is cached for next cycle's dedup check",
          "192.168.77.71" in daemon._last_decision_key)

    # A second cycle where this device is re-evaluated (a new, unrelated benign
    # query keeps it in devices_seen) but its cumulative evidence hasn't
    # meaningfully changed should re-compute the SAME verdict without writing
    # a second, redundant decision row.
    with open(pihole_log_path, "a", encoding="utf-8") as f:
        f.write("Sep  6 00:39:05 dnsmasq[1146]: query[A] harmless-followup.example from 192.168.77.71\n")
        f.write("Sep  6 00:39:05 dnsmasq[1146]: cached harmless-followup.example is 1.1.1.1\n")
    daemon._run_cycle()
    decisions_after_second = daemon.store._conn.execute(
        "SELECT COUNT(*) c FROM decisions WHERE device_id = '192.168.77.71'").fetchone()["c"]
    check("an unchanged verdict on a later cycle does NOT write a redundant decision row",
          decisions_after_second == decisions_after_first)

    # --- pruning is time-gated, not run every cycle ---
    last_prune_before = daemon._last_prune
    daemon._run_cycle()
    check("prune_evidence is NOT re-run on every cycle (only after prune_interval_seconds elapses)",
          daemon._last_prune == last_prune_before)

    daemon.store.close()


print(f"\n{'='*60}")
if FAILURES:
    print(f"FAILED: {len(FAILURES)} check(s) failed: {FAILURES}")
    sys.exit(1)
else:
    print("All v13 ingest-daemon checks PASSED.")
