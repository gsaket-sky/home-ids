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

from intelligence.detectors.dns_evasion import DeviceBurstAudit, audit_burst
from metrics import (
    reactive_capture_bursts_total, reactive_capture_bytes_total, reactive_capture_errors_total,
    reactive_capture_last_burst_timestamp, reactive_capture_dns_evasion_findings_total,
    reactive_capture_stale_files_removed_total,
)

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
        reactive_capture_bytes_total.labels(radio=iface).inc(r["bytes"])
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

    # BUGFIX: reactive_capture_scratch_dir (config.yaml) is a RELATIVE path
    # ("state/reactive_capture") by default, same as every other data path in this
    # app -- fine for plain Python file I/O (always resolved against THIS process's
    # cwd), but pcap_path here is handed to zeek as a COMMAND-LINE ARGUMENT while the
    # subprocess's own cwd is set to scratch_dir (below) -- a DIFFERENT directory. A
    # relative pcap_path would then get resolved by zeek relative to scratch_dir, not
    # this process's cwd, so it never finds the file: 100% reproducible "unable to
    # open ... No such file or directory" on every single burst, regardless of
    # concurrency. Resolving to an absolute path here makes it correct no matter what
    # the subprocess's cwd is.
    pcap_path = pcap_path.resolve()

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


def ingest_zeek_logs(log_dir: Path, zeek_fx, collect_sources: set = None) -> Dict[str, int]:
    """Reads every *.log JSON-lines file zeek -r produced and feeds each event through
    zeek_fx.ingest(), tagging `_zeek_type` from the filename -- the exact same
    dispatch convention ZeekCollector._on_event uses for live tailing (see
    zeek_features.py), so a reprocessed burst flows through the identical code path
    live traffic does. Returns {log_type: event_count} for observability/logging.

    collect_sources: optional mutable set -- when given, every conn.log event's
    id.orig_h is added to it, so a caller can discover which devices were actually
    present in this burst without a second pass over the logs (used by
    capture_and_ingest() to know which devices to run the DNS-evasion blind-spot audit
    against). Return type is unchanged either way -- purely additive."""
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
                    if collect_sources is not None and etype == "conn":
                        src = event.get("id.orig_h")
                        if src:
                            collect_sources.add(src)
        except OSError as e:
            LOGGER.warning("Could not read %s: %s", log_path, e)
            continue
        if n:
            counts[etype] = n
    return counts


# --- Orchestration -------------------------------------------------------------------

def run_dns_evasion_audit(zeek_fx, state_manager, evidence_store, burst_source_ips: set,
                           capture_ts: float, geoip_engine=None, ti_engine=None) -> Dict[str, int]:
    """Runs dns_evasion.py's blind-spot audit for every tracked device whose client_ip
    was actually seen in this burst -- the piece Phase C2 built and tested but never
    actually wired into a live capture flow (found while scoping the LightGBM feature
    extension this session; capture_and_ingest() previously stopped at ingest_zeek_logs(),
    so dns_evasion_anomaly evidence never reached the evidence store in production
    despite the detector and its hypothesis existing).

    O(N) over tracked devices (N = get_all_device_ids()), not over burst_source_ips --
    there's no public IP->device_id lookup on StateManager, and N is small (dozens, not
    millions) and this only runs on a rate-limited reactive-capture budget (a handful of
    times per hour at most), so a full scan per burst is cheap. Returns
    {device_id: evidence_count} for observability/logging.
    """
    if not burst_source_ips or state_manager is None or evidence_store is None:
        return {}

    devices: Dict[str, DeviceBurstAudit] = {}
    device_ips: Dict[str, str] = {}  # dev_id -> client_ip, so results can feed set_dns_evasion_ratio()
    for dev_id in state_manager.get_all_device_ids():
        try:
            with state_manager.lock_device(dev_id) as state:
                client_ip = getattr(state, "client_ip", "")
                if client_ip not in burst_source_ips:
                    continue
                dest_ips = zeek_fx.get_dest_ips(client_ip)
                if not dest_ips:
                    continue
                queried_domains = set(getattr(state.rolling, "domain_timestamps", {}).keys())
        except KeyError:
            continue  # device pruned between get_all_device_ids() and lock_device()
        devices[dev_id] = DeviceBurstAudit(dest_ips=dest_ips, queried_domains=queried_domains)
        device_ips[dev_id] = client_ip

    if not devices:
        return {}

    results = audit_burst(devices, capture_ts, geoip_engine=geoip_engine, ti_engine=ti_engine)
    counts: Dict[str, int] = {}
    for dev_id, audit in devices.items():
        evidence_list = results.get(dev_id, [])
        for ev in evidence_list:
            evidence_store.add(ev)
        counts[dev_id] = len(evidence_list)
        if evidence_list:
            LOGGER.warning("🕵️ [DNS-EVASION AUDIT] %s: %d finding(s) from this capture burst.",
                            dev_id, len(evidence_list))
        # PHASE 21-LGBM-EXTEND: feed zeek_fx's LightGBM-consumable signal regardless of
        # outcome -- a device with a stale nonzero ratio from an EARLIER evasive burst
        # needs to be reset back to 0.0 once a later burst finds it clean, not left
        # stuck at the old value forever.
        total = len(audit.dest_ips) or 1
        unexplained_count = evidence_list[0].value if evidence_list else 0.0
        zeek_fx.set_dns_evasion_ratio(device_ips[dev_id], unexplained_count / total)
    return counts


def _cleanup_burst_files(avm_path: Path, std_path: Path, scratch: Optional[Path]) -> None:
    """Deletes the raw/converted pcaps and Zeek scratch reprocessing directory for one
    radio's capture, once its data is already folded into zeek_fx's rolling state (or
    the attempt failed and there's nothing further to salvage from the raw file
    anyway). A single burst runs ~100MB+ (continuous dual-radio capture measured at
    ~3GB/hour live this session) -- even the budget-limited reactive design fills a
    disk over weeks if nothing ever deletes the raw files, which nothing did before
    this. Called unconditionally (success or failure) via a try/finally at the call
    site. Never raises -- a cleanup failure must not fail the whole capture."""
    for p in (avm_path, std_path):
        try:
            if p and p.exists():
                p.unlink()
        except OSError as e:
            LOGGER.warning("Could not delete %s: %s", p, e)
    if scratch is not None:
        try:
            if scratch.exists():
                shutil.rmtree(scratch, ignore_errors=True)
        except OSError as e:
            LOGGER.warning("Could not delete %s: %s", scratch, e)


def _append_burst_history(out_dir: Path, record: dict) -> None:
    """Compact, permanent record of one burst. The raw pcaps/Zeek scratch logs
    _cleanup_burst_files() just deleted are gone, but a KB-scale JSONL line
    (timestamp, trigger, radios, bytes captured, zeek event counts, dns-evasion
    findings, errors) is kept indefinitely in reactive_capture_history.jsonl for
    historical/audit reference -- the "more compact form for future reference"
    alternative to keeping multi-hundred-MB pcaps around."""
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        history_path = out_dir / "reactive_capture_history.jsonl"
        with open(history_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError as e:
        LOGGER.warning("Could not append to reactive_capture_history.jsonl: %s", e)


def cleanup_stale_scratch_files(out_dir: Path, max_age_seconds: float = 3600.0) -> int:
    """Defense-in-depth against capture_and_ingest()'s normal try/finally cleanup: if
    the whole process dies mid-burst (crash, power loss, `kill -9`), the finally block
    never runs and a raw pcap or Zeek scratch directory can be orphaned. This sweeps
    out_dir for entries older than max_age_seconds and removes them -- a burst never
    legitimately takes anywhere close to an hour, so anything that old is orphaned, not
    in-progress. Returns the count removed. Meant to be called periodically (e.g.
    alongside pipeline.py's existing spot-check interval) rather than after every
    burst, since the normal path already handles that case."""
    if not out_dir.exists():
        return 0
    now = time.time()
    removed = 0
    for entry in out_dir.iterdir():
        if entry.name == "reactive_capture_history.jsonl":
            continue  # the one thing in here meant to last forever
        try:
            age = now - entry.stat().st_mtime
            if age < max_age_seconds:
                continue
            if entry.is_dir():
                shutil.rmtree(entry, ignore_errors=True)
            else:
                entry.unlink()
            removed += 1
        except OSError as e:
            LOGGER.warning("Could not remove stale reactive-capture file %s: %s", entry, e)
    if removed:
        reactive_capture_stale_files_removed_total.inc(removed)
        LOGGER.info("Reactive-capture stale-file sweep removed %d orphaned item(s) from %s.", removed, out_dir)
    return removed


def capture_and_ingest(config: dict, zeek_fx, out_dir: Path, zeek_bin: str = "/opt/zeek/bin/zeek",
                        trigger_reason: str = "unspecified", state_manager=None, evidence_store=None,
                        geoip_engine=None, ti_engine=None) -> Dict[str, object]:
    """Top-level entry point for a single reactive-capture burst: authenticate, capture
    all configured radios, convert each from AVM's modified pcap format to standard
    pcap, reprocess through real Zeek, and ingest the resulting logs into the SAME
    zeek_fx instance the live pipeline already uses -- so on the very next pipeline
    cycle, whichever devices had traffic during the burst window have real
    zeek_lateral_moves/zeek_ja3_malicious/zeek_ja4_malicious/etc. features, exactly as
    if a wired Zeek tap had seen them the whole time.

    state_manager/evidence_store are optional (default None, matching this function's
    original signature so existing callers/tests keep working unchanged) -- when BOTH
    are supplied, also runs dns_evasion.py's blind-spot audit (see
    run_dns_evasion_audit()) against every device actually seen in the burst, feeding
    any dns_evasion_anomaly evidence straight into the live evidence store.

    Disk safety: raw/converted pcaps and Zeek's scratch reprocessing output are deleted
    once each radio's data has been ingested (or once an attempt fails, since a partial/
    corrupt raw file has no further salvage value either) -- gated by
    reactive_capture_delete_after_ingest (default true). A compact permanent JSONL
    history record survives regardless (see _append_burst_history()).
    """
    fritz_ip = config.get("fritz_ip", "192.168.1.1")
    fritz_user = config.get("fritz_user", "admin")
    fritz_pass = config.get("fritz_password", "")
    radios = config.get("reactive_capture_radios", ["ath0", "ath1"])
    burst_seconds = float(config.get("reactive_capture_burst_seconds", 120.0))
    snaplen = int(config.get("reactive_capture_snaplen", 1600))
    delete_after_ingest = bool(config.get("reactive_capture_delete_after_ingest", True))

    if not fritz_pass:
        raise FritzboxCaptureError("fritz_password is empty in configuration; cannot authenticate.")

    summary: Dict[str, object] = {
        "trigger_reason": trigger_reason,
        "timestamp": time.time(),
        "radios_requested": list(radios),
        "radios_captured": {},
        "zeek_event_counts": {},
        "dns_evasion_findings": {},
        "errors": [],
    }

    raw_pcaps = run_burst(fritz_ip, fritz_user, fritz_pass, radios, burst_seconds, out_dir, snaplen=snaplen)
    if not raw_pcaps:
        summary["errors"].append("No radio produced a non-empty capture.")
        reactive_capture_errors_total.labels(stage="capture").inc()
        _append_burst_history(out_dir, summary)
        return summary

    burst_source_ips: set = set()
    capture_ts = time.time()

    for iface, avm_path in raw_pcaps.items():
        std_path = avm_path.with_suffix(".std.pcap")
        scratch: Optional[Path] = None
        try:
            try:
                n_records = avm_pcap_to_standard(avm_path, std_path)
            except FritzboxCaptureError as e:
                LOGGER.error("Conversion failed for %s: %s", iface, e)
                summary["errors"].append(f"{iface}: conversion failed -- {e}")
                reactive_capture_errors_total.labels(stage="conversion").inc()
                continue

            summary["radios_captured"][iface] = {"bytes": avm_path.stat().st_size, "records": n_records}

            scratch = out_dir / f"zeek_scratch_{iface}_{int(time.time())}"
            try:
                reprocess_with_zeek(std_path, scratch, zeek_bin=zeek_bin)
            except FritzboxCaptureError as e:
                LOGGER.error("Zeek reprocessing failed for %s: %s", iface, e)
                summary["errors"].append(f"{iface}: zeek reprocessing failed -- {e}")
                reactive_capture_errors_total.labels(stage="zeek_reprocess").inc()
                continue

            counts = ingest_zeek_logs(scratch, zeek_fx, collect_sources=burst_source_ips)
            for etype, n in counts.items():
                summary["zeek_event_counts"][etype] = summary["zeek_event_counts"].get(etype, 0) + n
        finally:
            if delete_after_ingest:
                _cleanup_burst_files(avm_path, std_path, scratch)

    try:
        summary["dns_evasion_findings"] = run_dns_evasion_audit(
            zeek_fx, state_manager, evidence_store, burst_source_ips, capture_ts,
            geoip_engine=geoip_engine, ti_engine=ti_engine,
        )
        reactive_capture_dns_evasion_findings_total.inc(sum(summary["dns_evasion_findings"].values()))
    except Exception as exc:
        LOGGER.error("DNS-evasion audit failed for this burst (non-fatal): %s", exc)
        summary["errors"].append(f"dns_evasion_audit: {exc}")
        reactive_capture_errors_total.labels(stage="dns_evasion_audit").inc()

    reactive_capture_last_burst_timestamp.set(time.time())
    LOGGER.info("Reactive capture burst (trigger=%s) complete: %s", trigger_reason, summary)
    _append_burst_history(out_dir, summary)
    return summary


# --- Trigger dispatch (Phase D) -----------------------------------------------------

class ReactiveCaptureDispatcher:
    """Shared hourly-budget gate for every reactive-capture trigger. One instance is
    shared across all trigger sources in pipeline.py so the thing actually being rate
    limited is BURST EXECUTIONS overall, not any one trigger type -- a single burst
    captures the whole radio regardless of which source fired it, so trigger-source
    COUNT doesn't multiply capture cost, only actual burst-EXECUTION count does. See
    the reactive-capture plan's Phase D design note on this.

    capture_fn is injectable (defaults to capture_and_ingest) so tests can substitute a
    fast stub instead of making real network calls."""

    def __init__(self, capture_fn=None):
        self._lock = threading.Lock()
        self._window_start = time.time()
        self._count = 0
        self._capture_fn = capture_fn or capture_and_ingest
        # BUGFIX: the hourly budget above only ever limited total burst COUNT, never
        # CONCURRENT execution. Every dispatched trigger spawned its own daemon thread
        # immediately, with nothing stopping two bursts from running at the same time.
        # The Fritzbox radio capture is a single shared resource per interface -- it
        # cannot run two independent diagnostic captures on the same radio at once.
        # In production this caused repeated "Capture on athX produced an empty file"
        # results and a genuinely-written .std.pcap disappearing before Zeek could read
        # it (a second overlapping burst's ts/session stomping on the first's). This
        # lock serializes actual burst EXECUTION -- try_dispatch() defers (not queues)
        # a trigger that finds a burst already in flight, exactly like a budget-exhausted
        # trigger, and refunds the budget slot it consumed since it never actually ran.
        self._burst_lock = threading.Lock()

    def _check_and_consume_budget(self, config: dict) -> bool:
        """Pure budget bookkeeping, no threading -- kept separate from try_dispatch()
        so the hourly-window/count logic can be unit tested directly without spinning
        real threads."""
        if not config.get("reactive_capture_enabled", False):
            return False
        max_per_hour = int(config.get("reactive_capture_max_bursts_per_hour", 6))
        with self._lock:
            now = time.time()
            if now - self._window_start >= 3600:
                self._window_start = now
                self._count = 0
            if self._count >= max_per_hour:
                return False
            self._count += 1
            return True

    def try_dispatch(self, config: dict, zeek_fx, trigger_reason: str, state_manager=None,
                      evidence_store=None, geoip_engine=None, ti_engine=None) -> bool:
        """Attempts to fire one capture burst asynchronously. Returns True if
        dispatched (the actual capture runs in a daemon thread and this call never
        blocks), False if reactive_capture_enabled is false or the shared hourly
        budget is exhausted -- logged as [DEFERRED], matching ollama_soc.py's
        per-run-query-cap convention, rather than silently dropping the trigger.

        state_manager/evidence_store/geoip_engine/ti_engine are optional and passed
        straight through to capture_and_ingest() -- when state_manager and
        evidence_store are both supplied, the burst also runs dns_evasion.py's
        blind-spot audit and feeds any findings into the live evidence store (see
        capture_and_ingest()'s docstring). Omitting them keeps the old
        capture-and-ingest-only behavior, e.g. for a caller with no evidence store to
        feed."""
        if not self._check_and_consume_budget(config):
            if config.get("reactive_capture_enabled", False):
                max_per_hour = int(config.get("reactive_capture_max_bursts_per_hour", 6))
                LOGGER.info("[DEFERRED] reactive_capture_max_bursts_per_hour (%d) reached, "
                            "deferring trigger '%s' -- will be reconsidered once the hourly "
                            "window resets.", max_per_hour, trigger_reason)
                reactive_capture_bursts_total.labels(trigger_reason=trigger_reason, outcome="deferred").inc()
            return False

        if not self._burst_lock.acquire(blocking=False):
            LOGGER.info(
                "[DEFERRED] a reactive-capture burst is already in progress -- deferring trigger "
                "'%s' (the router's radio capture is a single shared resource; concurrent bursts "
                "corrupt each other's output). Not counted against the hourly budget.",
                trigger_reason,
            )
            reactive_capture_bursts_total.labels(trigger_reason=trigger_reason, outcome="deferred_concurrent").inc()
            # This trigger consumed a budget slot in _check_and_consume_budget() above but never
            # actually ran a burst -- refund it so the hourly budget only ever counts real executions.
            with self._lock:
                self._count = max(0, self._count - 1)
            return False

        out_dir = Path(config.get("reactive_capture_scratch_dir", "state/reactive_capture"))
        zeek_bin = config.get("reactive_capture_zeek_bin", "/opt/zeek/bin/zeek")
        capture_fn = self._capture_fn

        def _run():
            try:
                capture_fn(config, zeek_fx, out_dir, zeek_bin=zeek_bin, trigger_reason=trigger_reason,
                           state_manager=state_manager, evidence_store=evidence_store,
                           geoip_engine=geoip_engine, ti_engine=ti_engine)
            except Exception as exc:
                LOGGER.error("Reactive capture burst (trigger=%s) failed: %s", trigger_reason, exc)
            finally:
                self._burst_lock.release()

        threading.Thread(target=_run, daemon=True, name=f"reactive-capture-{trigger_reason}").start()
        reactive_capture_bursts_total.labels(trigger_reason=trigger_reason, outcome="dispatched").inc()
        LOGGER.info("Reactive capture burst dispatched (trigger=%s).", trigger_reason)
        return True
