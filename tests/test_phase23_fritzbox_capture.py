"""
Standalone runtime test for Phase 23 (Fritzbox reactive capture client). Not part of
the pytest suite -- run directly: `python3 test_phase23_fritzbox_capture.py`.

What's covered here vs. what was verified live and can't be re-run in an automated
suite:
  - avm_pcap_to_standard(): fully covered here, including a regression check against a
    REAL capture file from this session's live Fritzbox testing (fritzbox-iad-if-lan_*
    .eth in the repo root) -- converts it and confirms scapy can parse the entire
    output end-to-end, not just a synthetic fixture.
  - ingest_zeek_logs(): covered here with synthetic Zeek JSON-lines log files, proving
    the _zeek_type tagging/dispatch matches ZeekLogTailer's live convention.
  - reprocess_with_zeek()'s error path (missing zeek binary): covered here. The
    success path (real `zeek -r` producing real logs) needs an actual Zeek install and
    was NOT re-verified in this pass -- this dev environment has no Zeek binary; that
    piece needs live verification on the actual Ubuntu deployment.
  - login()/run_burst() (network calls against the real router): deliberately NOT
    covered here -- these were verified with a real live capture earlier this session
    (10s burst on ath0, confirmed valid AVM pcap magic in the output) and re-running
    live network calls in a routine test pass isn't appropriate. If the router's login
    flow or capture_notimeout endpoint changes, that would need a fresh live check,
    not a unit test against a mock.
"""
import json
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import shutil
import struct
import time
import tempfile

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from extractors.fritzbox_capture import (
    avm_pcap_to_standard, ingest_zeek_logs, reprocess_with_zeek,
    FritzboxCaptureError, _AVM_MAGIC, _STANDARD_MAGIC,
)
from extractors.zeek_features import ZeekFeatureExtractor

TMP = _PathForSysPath(tempfile.mkdtemp(prefix="phase23_"))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: avm_pcap_to_standard -- synthetic fixture (exact byte-layout regression)
# ═══════════════════════════════════════════════════════════════════════════════════
def build_synthetic_avm_pcap(path, n_records=3):
    global_hdr = struct.pack("<IHHiIII", _AVM_MAGIC, 2, 4, 0, 0, 2048, 1)
    body = bytearray()
    # A minimal valid Ethernet/ARP-ish frame is enough here -- this section tests the
    # container format (headers/offsets), not payload semantics.
    frame = bytes.fromhex("ffffffffffff") + bytes.fromhex("844709aabbcc") + bytes.fromhex("0806") + b"\x00" * 42
    for i in range(n_records):
        ts_sec, ts_usec, incl_len, orig_len = 1700000000 + i, i * 1000, len(frame), len(frame)
        record_hdr_16 = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        extra_8 = bytes([0x0A, 0, 0, 0, 0, 0, i, 0])  # arbitrary AVM-specific bytes, must be stripped
        body += record_hdr_16 + extra_8 + frame
    path.write_bytes(global_hdr + bytes(body))

synthetic_avm = TMP / "synthetic.avm.pcap"
synthetic_std = TMP / "synthetic.std.pcap"
build_synthetic_avm_pcap(synthetic_avm, n_records=3)

n = avm_pcap_to_standard(synthetic_avm, synthetic_std)
check("converts the expected number of synthetic records", n == 3, f"got {n}")

out_bytes = synthetic_std.read_bytes()
magic = struct.unpack("<I", out_bytes[:4])[0]
check("output file has the STANDARD pcap magic, not the AVM one", magic == _STANDARD_MAGIC,
      f"got 0x{magic:08x}")

# Walk the output as a real standard pcap and confirm record count/sizes/no leftover
# AVM extra-bytes contamination.
offset = 24
parsed = 0
while offset + 16 <= len(out_bytes):
    ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", out_bytes[offset:offset + 16])
    pkt = out_bytes[offset + 16: offset + 16 + incl_len]
    check(f"record {parsed}: packet starts with the real frame's destination MAC (extra AVM bytes stripped)",
          pkt[:6] == bytes.fromhex("ffffffffffff"), f"got {pkt[:6].hex()}")
    offset += 16 + incl_len
    parsed += 1
check("standard-pcap walk found exactly 3 records (input record count preserved)", parsed == 3, f"got {parsed}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A2: avm_pcap_to_standard -- REAL capture file regression (not synthetic)
# ═══════════════════════════════════════════════════════════════════════════════════
real_avm_candidates = list(_PathForSysPath(__file__).resolve().parent.parent.glob("fritzbox-iad-if-*.eth"))
if real_avm_candidates:
    real_avm = real_avm_candidates[0]
    real_std = TMP / "real_converted.std.pcap"
    real_n = avm_pcap_to_standard(real_avm, real_std)
    check(f"real capture file ({real_avm.name}) converts without error", real_n > 0, f"got {real_n} records")
    try:
        from scapy.all import rdpcap, Ether
        pkts = rdpcap(str(real_std))
        check("scapy can fully parse the converted real-capture output (no format errors)",
              len(pkts) == real_n, f"scapy read {len(pkts)}, converter reported {real_n}")
        with_ether = sum(1 for p in pkts if p.haslayer(Ether))
        ratio = with_ether / len(pkts) if pkts else 0
        check("the overwhelming majority of converted real packets parse as valid Ethernet frames",
              ratio > 0.95, f"only {ratio:.1%} had a valid Ether layer")
    except ImportError:
        print("[SKIP] scapy not available -- skipping the scapy cross-validation sub-checks")
else:
    print("[SKIP] no real fritzbox-iad-if-*.eth capture file found in repo root -- "
          "skipping the real-data regression check (synthetic coverage above still applies)")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: avm_pcap_to_standard -- error paths
# ═══════════════════════════════════════════════════════════════════════════════════
wrong_magic_path = TMP / "wrong_magic.pcap"
wrong_magic_path.write_bytes(struct.pack("<IHHiIII", 0xDEADBEEF, 2, 4, 0, 0, 2048, 1) + b"\x00" * 100)
try:
    avm_pcap_to_standard(wrong_magic_path, TMP / "should_not_exist.pcap")
    check("wrong magic number raises FritzboxCaptureError", False, "did not raise")
except FritzboxCaptureError:
    check("wrong magic number raises FritzboxCaptureError", True)

too_short_path = TMP / "too_short.pcap"
too_short_path.write_bytes(b"\x00" * 10)
try:
    avm_pcap_to_standard(too_short_path, TMP / "should_not_exist2.pcap")
    check("truncated global header raises FritzboxCaptureError", False, "did not raise")
except FritzboxCaptureError:
    check("truncated global header raises FritzboxCaptureError", True)

empty_records_path = TMP / "empty_records.pcap"
empty_records_path.write_bytes(struct.pack("<IHHiIII", _AVM_MAGIC, 2, 4, 0, 0, 2048, 1))
try:
    avm_pcap_to_standard(empty_records_path, TMP / "should_not_exist3.pcap")
    check("a capture with zero records raises FritzboxCaptureError (not a silently empty output)", False, "did not raise")
except FritzboxCaptureError:
    check("a capture with zero records raises FritzboxCaptureError (not a silently empty output)", True)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: reprocess_with_zeek -- missing-binary error path (no live Zeek available here)
# ═══════════════════════════════════════════════════════════════════════════════════
try:
    reprocess_with_zeek(synthetic_std, TMP / "scratch_missing_zeek", zeek_bin="/definitely/not/a/real/zeek/binary")
    check("missing zeek binary raises FritzboxCaptureError", False, "did not raise")
except FritzboxCaptureError:
    check("missing zeek binary raises FritzboxCaptureError", True)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: ingest_zeek_logs -- dispatch convention matches ZeekLogTailer's live path
# ═══════════════════════════════════════════════════════════════════════════════════
log_dir = TMP / "zeek_logs"
log_dir.mkdir()

conn_event = {"id.orig_h": "192.168.1.60", "id.resp_h": "93.184.216.34", "id.resp_p": 443,
              "proto": "tcp", "orig_bytes": 500, "uid": "Cxxxxxxxxxxxxx9", "ts": 1700000000.0}
dns_event = {"id.orig_h": "192.168.1.60", "query": "example.com", "ts": 1700000001.0}

(log_dir / "conn.log").write_text(json.dumps(conn_event) + "\n" + "# this comment line should be skipped\n")
(log_dir / "dns.log").write_text("\n" + json.dumps(dns_event) + "\n")
(log_dir / "not_json.log").write_text("this is not valid json\n{also not valid}\n")

zfx = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
counts = ingest_zeek_logs(log_dir, zfx)

check("conn.log event is ingested (comment/blank lines correctly skipped)",
      counts.get("conn") == 1, f"got counts={counts}")
check("dns.log event is ingested", counts.get("dns") == 1, f"got counts={counts}")
check("malformed JSON lines are skipped without raising, and produce zero successful ingests",
      "not_json" not in counts, f"got counts={counts}")

feats = zfx.get_features("192.168.1.60")
check("THE CORE INTEGRATION: an event ingested via ingest_zeek_logs() is visible through "
      "the SAME get_features() call live traffic uses (proves reprocessed-burst data reaches "
      "the real feature pipeline, not a side channel)",
      feats.get("zeek_conn_count", 0) >= 1 or feats.get("zeek_outbound_bytes", 0) > 0,
      f"got features={feats}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E (added later this session): run_dns_evasion_audit() -- the wiring gap fix.
# dns_evasion.py's blind-spot audit (Phase C2) was fully built and tested but NEVER
# actually invoked from capture_and_ingest() -- found while scoping a LightGBM feature
# extension. Real StateManager + real ZeekFeatureExtractor + real EvidenceStore, no
# mocks -- proves a burst's findings actually reach the live evidence store, not just
# that the standalone dns_evasion functions work in isolation (already covered by
# test_phase24).
# ═══════════════════════════════════════════════════════════════════════════════════
from core.state_guard import StateManager
from intelligence.hypotheses.evidence import EvidenceStore
from extractors.fritzbox_capture import run_dns_evasion_audit

with open(_PathForSysPath(__file__).resolve().parent.parent / "src" / "extractors" / "fritzbox_capture.py",
          "r", encoding="utf-8") as f:
    _CAPTURE_SRC = f.read()

class _FakeGeoIPForAudit:
    """Minimal stand-in matching dns_evasion.py's expected interface (reverse_dns,
    lookup_asn) -- without SOME geoip_engine, _reverse_dns_explains()/_vpn_explains()
    can never mark anything as explained at all (both immediately return False when
    geoip_engine is None), so a genuine "explained, no evidence" case needs a real
    (fake) engine, not just an absent one."""
    def reverse_dns(self, ip):
        return {"1.1.1.1": "server.example.com"}.get(ip)

    def lookup_asn(self, ip):
        return None


EVASIVE_IP = "192.168.1.70"
CLEAN_IP = "192.168.1.71"

sm = StateManager()
sm.get_or_create("dev_evasive", EVASIVE_IP, "evasive-host", alpha=0.05)
sm.get_or_create("dev_clean", CLEAN_IP, "clean-host", alpha=0.05)
with sm.lock_device("dev_clean") as st:
    st.rolling.domain_timestamps["example.com"].append(time.time())

zfx2 = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
# The evasive device has a real connection to an IP with no matching DNS history.
zfx2.ingest({"_zeek_type": "conn", "id.orig_h": EVASIVE_IP, "id.resp_h": "9.9.9.9",
             "id.resp_p": 443, "proto": "tcp", "orig_bytes": 100, "uid": "CX1", "ts": time.time()})
# The clean device's connection resolves (via reverse-DNS) to a host under the same
# base domain it queried -- genuinely explained.
zfx2.ingest({"_zeek_type": "conn", "id.orig_h": CLEAN_IP, "id.resp_h": "1.1.1.1",
             "id.resp_p": 443, "proto": "tcp", "orig_bytes": 100, "uid": "CX2", "ts": time.time()})

es = EvidenceStore()
counts = run_dns_evasion_audit(zfx2, sm, es, burst_source_ips={EVASIVE_IP, CLEAN_IP},
                                capture_ts=time.time(), geoip_engine=_FakeGeoIPForAudit())

check("THE CORE FIX: run_dns_evasion_audit() finds the evasive device and produces evidence",
      counts.get("dev_evasive", 0) >= 1, f"got counts={counts}")
check("the evidence actually lands in the live EvidenceStore, retrievable by device_id "
      "(proves the wiring reaches evaluate()'s real input, not a side channel)",
      any(e.type == "dns_evasion_anomaly" for e in es.get_for_device("dev_evasive")),
      f"got={es.get_for_device('dev_evasive')}")
check("a device with no unexplained connections produces NO evidence (no false positive "
      "just from being included in the scan)",
      "dev_clean" not in counts or counts.get("dev_clean", 0) == 0, f"got counts={counts}")

check("THE POINT OF THIS WIRING: the evasive device's unexplained ratio actually lands "
      "on zeek_fx, where LightGBM's feature extraction can read it via get_features() "
      "(the whole reason this gap mattered for the LightGBM feature-vector extension)",
      zfx2.get_features(EVASIVE_IP)["zeek_dns_evasion_ratio"] > 0.0,
      f"got={zfx2.get_features(EVASIVE_IP)}")
check("the clean device's ratio is explicitly 0.0, not just absent",
      zfx2.get_features(CLEAN_IP)["zeek_dns_evasion_ratio"] == 0.0)

check("a device whose client_ip is NOT in burst_source_ips is skipped entirely",
      run_dns_evasion_audit(zfx2, sm, es, burst_source_ips=set(), capture_ts=time.time()) == {})
check("missing state_manager degrades gracefully to a no-op, not a crash",
      run_dns_evasion_audit(zfx2, None, es, burst_source_ips={EVASIVE_IP}, capture_ts=time.time()) == {})
check("missing evidence_store degrades gracefully to a no-op, not a crash",
      run_dns_evasion_audit(zfx2, sm, None, burst_source_ips={EVASIVE_IP}, capture_ts=time.time()) == {})

check("capture_and_ingest() now accepts state_manager/evidence_store/geoip_engine/ti_engine "
      "as optional keyword arguments (source guard -- signature check)",
      "state_manager=None, evidence_store=None" in _CAPTURE_SRC)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: disk-safety cleanup -- _cleanup_burst_files / _append_burst_history /
# cleanup_stale_scratch_files. Real filesystem operations against a real temp dir, no
# mocks -- raw pcaps and Zeek scratch dirs run ~100MB+ per burst and nothing deleted
# them before this.
# ═══════════════════════════════════════════════════════════════════════════════════
from extractors.fritzbox_capture import _cleanup_burst_files, _append_burst_history, cleanup_stale_scratch_files

CLEAN_TMP = TMP / "cleanup_section"
CLEAN_TMP.mkdir(parents=True, exist_ok=True)

avm_f = CLEAN_TMP / "burst_ath0_123.avm.pcap"
std_f = CLEAN_TMP / "burst_ath0_123.std.pcap"
scratch_d = CLEAN_TMP / "zeek_scratch_ath0_123"
avm_f.write_bytes(b"fake avm pcap data")
std_f.write_bytes(b"fake std pcap data")
scratch_d.mkdir()
(scratch_d / "conn.log").write_text('{"fake": "log"}\n')

_cleanup_burst_files(avm_f, std_f, scratch_d)
check("_cleanup_burst_files() deletes the raw AVM pcap", not avm_f.exists())
check("_cleanup_burst_files() deletes the converted standard pcap", not std_f.exists())
check("_cleanup_burst_files() deletes the entire Zeek scratch directory, not just its contents",
      not scratch_d.exists())

# Must never raise on already-missing files (e.g. a conversion failure meant std_path
# was never created at all).
try:
    _cleanup_burst_files(CLEAN_TMP / "never_existed.pcap", CLEAN_TMP / "also_never.pcap", None)
    check("_cleanup_burst_files() never raises on already-missing files/None scratch", True)
except Exception as e:
    check("_cleanup_burst_files() never raises on already-missing files/None scratch", False, f"raised {e}")

history_dir = CLEAN_TMP / "history_test"
_append_burst_history(history_dir, {"trigger_reason": "unit_test", "timestamp": time.time()})
_append_burst_history(history_dir, {"trigger_reason": "unit_test_2", "timestamp": time.time()})
history_path = history_dir / "reactive_capture_history.jsonl"
check("_append_burst_history() creates the history file and the target directory if needed",
      history_path.exists())
history_lines = [json.loads(l) for l in history_path.read_text().splitlines() if l.strip()]
check("_append_burst_history() appends (2 calls -> 2 lines), never overwrites",
      len(history_lines) == 2, f"got {len(history_lines)} lines")

# cleanup_stale_scratch_files: an old orphaned file gets removed, a fresh one and the
# permanent history file are both left alone.
stale_dir = CLEAN_TMP / "stale_sweep_test"
stale_dir.mkdir()
old_file = stale_dir / "orphaned_burst.avm.pcap"
old_file.write_bytes(b"orphaned")
old_scratch = stale_dir / "zeek_scratch_orphaned"
old_scratch.mkdir()
fresh_file = stale_dir / "fresh_burst.avm.pcap"
fresh_file.write_bytes(b"fresh")
history_in_stale_dir = stale_dir / "reactive_capture_history.jsonl"
history_in_stale_dir.write_text('{"old": "record"}\n')

old_ts = time.time() - 7200  # 2 hours ago, older than the default 3600s max_age
import os
os.utime(old_file, (old_ts, old_ts))
os.utime(old_scratch, (old_ts, old_ts))
os.utime(history_in_stale_dir, (old_ts, old_ts))  # even an OLD history file must survive

removed_count = cleanup_stale_scratch_files(stale_dir, max_age_seconds=3600.0)
check("cleanup_stale_scratch_files() removes an orphaned file older than max_age_seconds",
      not old_file.exists())
check("cleanup_stale_scratch_files() removes an orphaned scratch DIRECTORY older than max_age_seconds",
      not old_scratch.exists())
check("cleanup_stale_scratch_files() leaves a FRESH file alone (not orphaned, still in-progress)",
      fresh_file.exists())
check("cleanup_stale_scratch_files() NEVER removes reactive_capture_history.jsonl, "
      "regardless of its age -- it's the one thing meant to last forever",
      history_in_stale_dir.exists())
check("cleanup_stale_scratch_files() reports the correct removed count",
      removed_count == 2, f"got {removed_count}")

check("cleanup_stale_scratch_files() on a nonexistent directory is a safe no-op",
      cleanup_stale_scratch_files(CLEAN_TMP / "does_not_exist", max_age_seconds=3600.0) == 0)

# Source guards: capture_and_ingest() actually calls the cleanup, gated by config.
check("capture_and_ingest() cleans up via a try/finally so a mid-burst exception still "
      "triggers cleanup, not just the success path",
      "finally:\n            if delete_after_ingest:" in _CAPTURE_SRC)
check("cleanup is gated by reactive_capture_delete_after_ingest (default true), not "
      "unconditional -- an operator can opt out for manual forensic retention",
      'delete_after_ingest = bool(config.get("reactive_capture_delete_after_ingest", True))' in _CAPTURE_SRC)
check("every burst writes a permanent history record via _append_burst_history(), "
      "regardless of the delete setting",
      "_append_burst_history(out_dir, summary)" in _CAPTURE_SRC)


shutil.rmtree(TMP, ignore_errors=True)

if FAILURES:
    print(f"\n{len(FAILURES)} Phase 23 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 23 Fritzbox-capture-client checks PASSED.")
    sys.exit(0)
