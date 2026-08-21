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


shutil.rmtree(TMP, ignore_errors=True)

if FAILURES:
    print(f"\n{len(FAILURES)} Phase 23 check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll Phase 23 Fritzbox-capture-client checks PASSED.")
    sys.exit(0)
