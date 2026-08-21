"""
Fritzbox reactive LAN/WLAN packet-capture client (Phase C of the reactive-capture plan).

Two things confirmed via LIVE testing against the production router this session, both
load-bearing for how this module works and worth keeping visible in code, not just in
session notes:

1. Auth. The router's diagnostic-capture UI (capture.lua/capture_notimeout) uses the
   login_sid.lua PBKDF2 challenge-response flow. This is a SEPARATE, unrelated
   mechanism from the TR-064/SOAP auth `fritzconnection`/`middleware/routers/
   fritzbox_api.py` uses for router-isolation actions -- the two are not
   interchangeable, and there was no existing auth helper to reuse. This module owns
   its own login().

2. Capture mechanism. There is no distinct "start capture" / "stop capture" /
   "download file" sequence. The Start URL's HTTP response body *is* the live-growing
   pcap stream (confirmed live: a GET to the Start URL returns
   Content-Type: application/octet-stream and keeps streaming bytes for as long as the
   connection stays open). The browser UI achieves this via a hidden iframe that just
   holds the connection open. A capture burst here means: open that GET with streaming
   reads, write bytes to disk as they arrive, and fire an independent Stop GET on a
   SEPARATE connection after burst_seconds to make the router close the stream out
   cleanly.

A third thing, verified this session against a real historical capture file
(fritzbox-iad-if-lan_*.eth in the repo root, from this session's earlier live testing),
not the live router: the pcap format the router produces is NOT standard pcap. Its
24-byte global header matches the standard layout field-for-field except the magic
number (0xa1b2cd34 vs the real 0xa1b2c3d4), and each 24-byte per-record header is the
standard 16-byte record header (ts_sec, ts_usec, incl_len, orig_len) plus 8 extra
AVM-specific bytes of unknown meaning immediately before the raw frame. Confirmed
against >99% of 2000 sampled records in a real capture (packet payload starting
right after those 8 extra bytes decodes as a valid, common EtherType). Zeek expects a
real standard pcap, so avm_pcap_to_standard() strips the 8 extra bytes per record and
fixes the magic number before any file is handed to `zeek -r`.
"""
import hashlib
import json
import logging
import shutil
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional

import requests

LOGGER = logging.getLogger("home_ids.fritzbox_capture")

_AVM_MAGIC = 0xA1B2CD34
_STANDARD_MAGIC = 0xA1B2C3D4
_GLOBAL_HDR_LEN = 24
_AVM_RECORD_HDR_LEN = 24
_STANDARD_RECORD_HDR_LEN = 16
_AVM_RECORD_EXTRA_LEN = _AVM_RECORD_HDR_LEN - _STANDARD_RECORD_HDR_LEN


class FritzboxCaptureError(Exception):
    pass


# --- Auth (login_sid.lua PBKDF2 challenge-response) -------------------------------

def _get_challenge(fritz_ip: str, timeout: float) -> Dict[str, Optional[str]]:
    url = f"http://{fritz_ip}/login_sid.lua?version=2"
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    root = ET.fromstring(body)
    return {
        "sid": root.findtext("SID"),
        "challenge": root.findtext("Challenge"),
        "blocktime": root.findtext("BlockTime"),
    }


def _pbkdf2_response(challenge: str, password: str) -> Optional[str]:
    parts = challenge.split("$")
    if len(parts) != 5 or parts[0] != "2":
        return None
    _, iter1, salt1, iter2, salt2 = parts
    hash1 = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt1), int(iter1))
    hash2 = hashlib.pbkdf2_hmac("sha256", hash1, bytes.fromhex(salt2), int(iter2))
    return f"{salt2}${hash2.hex()}"


def _legacy_md5_response(challenge: str, password: str) -> str:
    # Pre-FritzOS-7-era routers only; kept as a fallback since we can't assume every
    # deployment target is on a challenge-v2-capable firmware.
    combined = (challenge + "-" + password).encode("utf-16-le")
    return f"{challenge}-{hashlib.md5(combined).hexdigest()}"


def login(fritz_ip: str, user: str, password: str, timeout: float = 10.0) -> str:
    """Authenticates and returns a fresh SID. Callers should get a new SID per burst
    rather than caching one across bursts -- SIDs expire and a login is cheap (two
    small round trips)."""
    info = _get_challenge(fritz_ip, timeout)
    challenge, blocktime = info["challenge"], info["blocktime"]
    if not challenge:
        raise FritzboxCaptureError(f"Fritzbox at {fritz_ip} did not return a login challenge.")

    if blocktime and blocktime != "0":
        wait_s = min(int(blocktime), 30)
        LOGGER.warning("Fritzbox requested a %ss login cooldown; waiting before retrying.", wait_s)
        time.sleep(wait_s)
        info = _get_challenge(fritz_ip, timeout)
        challenge = info["challenge"]

    if challenge.startswith("2$"):
        response = _pbkdf2_response(challenge, password)
    else:
        response = _legacy_md5_response(challenge, password)
    if not response:
        raise FritzboxCaptureError(f"Could not compute a challenge-response for challenge {challenge!r}.")

    data = urllib.parse.urlencode({"username": user, "response": response}).encode("utf-8")
    req = urllib.request.Request(f"http://{fritz_ip}/login_sid.lua?version=2", data=data, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    sid = ET.fromstring(body).findtext("SID")
    if not sid or sid == "0000000000000000":
        raise FritzboxCaptureError(
            "Fritzbox login failed -- SID is the null value. Check FRITZ_USER/FRITZ_PASS in .env, "
            "and that this account has 'FRITZ!Box Settings' access enabled in the router's user list."
        )
    return sid


# --- Capture burst (streaming Start / independent Stop) ---------------------------

def _capture_one_interface(fritz_ip: str, sid: str, iface: str, snaplen: int,
                            out_path: Path, result: dict, connect_timeout: float,
                            burst_seconds: float) -> None:
    start_url = (f"http://{fritz_ip}/cgi-bin/capture_notimeout"
                 f"?sid={sid}&capture=Start&snaplen={snaplen}&filter=&ifaceorminor=1-{iface}")
    try:
        with requests.get(start_url, stream=True, timeout=(connect_timeout, burst_seconds + 30)) as resp:
            result["status"] = resp.status_code
            if resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code} starting capture on {iface}"
                return
            with open(out_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
                        result["bytes"] = result.get("bytes", 0) + len(chunk)
    except Exception as e:
        result["error"] = str(e)


def _stop_one_interface(fritz_ip: str, sid: str, iface: str, timeout: float) -> None:
    stop_url = (f"http://{fritz_ip}/cgi-bin/capture_notimeout"
                f"?iface={iface}&minor=-1&type=1&capture=Stop&sid={sid}")
    try:
        requests.get(stop_url, timeout=timeout)
    except Exception as e:
        LOGGER.warning("Stop request for %s failed (the capture may keep running until the router's "
                        "own idle/session timeout instead of ending cleanly now): %s", iface, e)


def run_burst(fritz_ip: str, user: str, password: str, radios: List[str], burst_seconds: float,
              out_dir: Path, snaplen: int = 1600, connect_timeout: float = 10.0) -> Dict[str, Path]:
    """Runs one capture burst across all configured radios simultaneously -- one shared
    burst_seconds window covers every radio, so triggering more often costs in burst
    COUNT, not in per-radio duration (see the reactive-capture plan's Phase D shared
    budget design). Returns {iface: raw_avm_pcap_path} for every radio that produced a
    non-empty file; a radio that errored is omitted rather than raising, so one bad
    radio doesn't sink the whole burst."""
    sid = login(fritz_ip, user, password, timeout=connect_timeout)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = int(time.time())

    threads = []
    results: Dict[str, dict] = {}
    paths: Dict[str, Path] = {}
    for iface in radios:
        out_path = out_dir / f"burst_{iface}_{ts}.avm.pcap"
        paths[iface] = out_path
        results[iface] = {}
        t = threading.Thread(
            target=_capture_one_interface,
            args=(fritz_ip, sid, iface, snaplen, out_path, results[iface], connect_timeout, burst_seconds),
            daemon=True,
        )
        threads.append(t)
        t.start()

    time.sleep(burst_seconds)

    for iface in radios:
        _stop_one_interface(fritz_ip, sid, iface, connect_timeout)

    for t in threads:
        t.join(timeout=30)

    out: Dict[str, Path] = {}
    for iface in radios:
        r = results[iface]
        if r.get("error"):
            LOGGER.warning("Capture on %s failed: %s", iface, r["error"])
            continue
        if r.get("bytes", 0) == 0:
            LOGGER.warning("Capture on %s produced an empty file, skipping.", iface)
            continue
        out[iface] = paths[iface]
        LOGGER.info("Capture burst on %s: %d bytes -> %s", iface, r["bytes"], paths[iface])
    return out


# --- AVM pcap -> standard pcap conversion ------------------------------------------

def avm_pcap_to_standard(avm_path: Path, standard_path: Path) -> int:
    """Converts one AVM-format capture into a standard pcap Zeek can read: fixes the
    magic number and strips the 8 extra AVM-specific bytes from each per-record
    header. Returns the number of records converted. Raises FritzboxCaptureError if
    the input doesn't look like the expected AVM format (wrong magic, truncated
    header) -- fail loudly here rather than silently handing Zeek a corrupt file."""
    with open(avm_path, "rb") as f:
        data = f.read()

    if len(data) < _GLOBAL_HDR_LEN:
        raise FritzboxCaptureError(f"{avm_path} is too short to contain a pcap global header.")

    magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, network = struct.unpack(
        "<IHHiIII", data[:_GLOBAL_HDR_LEN]
    )
    if magic != _AVM_MAGIC:
        raise FritzboxCaptureError(
            f"{avm_path}: expected AVM magic 0x{_AVM_MAGIC:08x}, got 0x{magic:08x}. "
            "Either this isn't an AVM capture, or the router's format has changed."
        )

    out = bytearray()
    out += struct.pack("<IHHiIII", _STANDARD_MAGIC, ver_maj, ver_min, thiszone, sigfigs, snaplen, network)

    offset = _GLOBAL_HDR_LEN
    n = 0
    while offset + _AVM_RECORD_HDR_LEN <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", data[offset:offset + 16])
        pkt_start = offset + _AVM_RECORD_HDR_LEN
        pkt_end = pkt_start + incl_len
        if pkt_end > len(data):
            LOGGER.warning("%s: record %d claims %d bytes but only %d remain -- truncated capture, stopping here.",
                            avm_path, n, incl_len, len(data) - pkt_start)
            break
        out += struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        out += data[pkt_start:pkt_end]
        offset = pkt_end
        n += 1

    if n == 0:
        raise FritzboxCaptureError(f"{avm_path}: converted zero records -- capture may be empty or malformed.")

    standard_path.parent.mkdir(parents=True, exist_ok=True)
    with open(standard_path, "wb") as f:
        f.write(out)
    return n


# --- Zeek reprocessing --------------------------------------------------------------

def reprocess_with_zeek(pcap_path: Path, scratch_dir: Path, zeek_bin: str = "/opt/zeek/bin/zeek",
                         timeout: float = 120.0) -> Path:
    """Runs `zeek -r <pcap> local` in scratch_dir so the SAME local.zeek policy the
    live deployment loads (JSON logging, mac-logging, dhcp fingerprinting, ja3/ja4)
    applies to this burst too -- this is deliberate: it means the burst gets real
    lateral-movement/JA3/JA4 signal for free, with zero new detection logic, instead
    of a second hand-parsed detection path (see this module's docstring / the
    reactive-capture plan's "Key design decision"). Returns scratch_dir on success;
    raises FritzboxCaptureError if zeek exits non-zero or isn't found."""
    scratch_dir.mkdir(parents=True, exist_ok=True)
    for old_log in scratch_dir.glob("*.log"):
        old_log.unlink()

    if shutil.which(zeek_bin) is None and not Path(zeek_bin).exists():
        raise FritzboxCaptureError(f"Zeek binary not found at {zeek_bin!r}.")

    try:
        proc = subprocess.run(
            [zeek_bin, "-r", str(pcap_path), "local"],
            cwd=str(scratch_dir),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise FritzboxCaptureError(f"zeek -r timed out after {timeout}s on {pcap_path}") from e

    if proc.returncode != 0:
        raise FritzboxCaptureError(
            f"zeek -r exited {proc.returncode} on {pcap_path}. stderr: {proc.stderr[:2000]}"
        )
    return scratch_dir


def ingest_zeek_logs(log_dir: Path, zeek_fx) -> Dict[str, int]:
    """Reads every *.log JSON-lines file zeek -r produced and feeds each event through
    zeek_fx.ingest(), tagging `_zeek_type` from the filename -- the exact same
    dispatch convention ZeekCollector._on_event uses for live tailing (see
    zeek_features.py), so a reprocessed burst flows through the identical code path
    live traffic does. Returns {log_type: event_count} for observability/logging."""
    counts: Dict[str, int] = {}
    for log_path in sorted(log_dir.glob("*.log")):
        etype = log_path.stem
        n = 0
        try:
            with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event["_zeek_type"] = etype
                    zeek_fx.ingest(event)
                    n += 1
        except OSError as e:
            LOGGER.warning("Could not read %s: %s", log_path, e)
            continue
        if n:
            counts[etype] = n
    return counts


# --- Orchestration -------------------------------------------------------------------

def capture_and_ingest(config: dict, zeek_fx, out_dir: Path, zeek_bin: str = "/opt/zeek/bin/zeek",
                        trigger_reason: str = "unspecified") -> Dict[str, object]:
    """Top-level entry point for a single reactive-capture burst: authenticate, capture
    all configured radios, convert each from AVM's modified pcap format to standard
    pcap, reprocess through real Zeek, and ingest the resulting logs into the SAME
    zeek_fx instance the live pipeline already uses -- so on the very next pipeline
    cycle, whichever devices had traffic during the burst window have real
    zeek_lateral_moves/zeek_ja3_malicious/zeek_ja4_malicious/etc. features, exactly as
    if a wired Zeek tap had seen them the whole time.

    Not wired to any trigger yet (that's Phase D) -- this is the capture+ingest
    mechanism on its own, callable directly (e.g. for a manual/operator-triggered
    burst) once reactive_capture_enabled is true in config.yaml.
    """
    fritz_ip = config.get("fritz_ip", "192.168.1.1")
    fritz_user = config.get("fritz_user", "admin")
    fritz_pass = config.get("fritz_password", "")
    radios = config.get("reactive_capture_radios", ["ath0", "ath1"])
    burst_seconds = float(config.get("reactive_capture_burst_seconds", 120.0))
    snaplen = int(config.get("reactive_capture_snaplen", 1600))

    if not fritz_pass:
        raise FritzboxCaptureError("fritz_password is empty in configuration; cannot authenticate.")

    summary: Dict[str, object] = {
        "trigger_reason": trigger_reason,
        "radios_requested": list(radios),
        "radios_captured": {},
        "zeek_event_counts": {},
        "errors": [],
    }

    raw_pcaps = run_burst(fritz_ip, fritz_user, fritz_pass, radios, burst_seconds, out_dir, snaplen=snaplen)
    if not raw_pcaps:
        summary["errors"].append("No radio produced a non-empty capture.")
        return summary

    for iface, avm_path in raw_pcaps.items():
        std_path = avm_path.with_suffix(".std.pcap")
        try:
            n_records = avm_pcap_to_standard(avm_path, std_path)
        except FritzboxCaptureError as e:
            LOGGER.error("Conversion failed for %s: %s", iface, e)
            summary["errors"].append(f"{iface}: conversion failed -- {e}")
            continue

        summary["radios_captured"][iface] = {"bytes": avm_path.stat().st_size, "records": n_records}

        scratch = out_dir / f"zeek_scratch_{iface}_{int(time.time())}"
        try:
            reprocess_with_zeek(std_path, scratch, zeek_bin=zeek_bin)
        except FritzboxCaptureError as e:
            LOGGER.error("Zeek reprocessing failed for %s: %s", iface, e)
            summary["errors"].append(f"{iface}: zeek reprocessing failed -- {e}")
            continue

        counts = ingest_zeek_logs(scratch, zeek_fx)
        for etype, n in counts.items():
            summary["zeek_event_counts"][etype] = summary["zeek_event_counts"].get(etype, 0) + n

    LOGGER.info("Reactive capture burst (trigger=%s) complete: %s", trigger_reason, summary)
    return summary
