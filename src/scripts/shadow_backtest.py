"""
shadow_backtest.py - Offline backtest of the Gap 1 reputation-tier fix (see
Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md) against real alert history.

Scope: Gap 1 ONLY (reputation tier-5 privilege split via ReputationVector.verified_ioc).
Gap 2 (NetworkIntrusionHypothesis's has_malicious_tls/zeek_notice conflation) cannot be
reliably backtested from state/alerts.json -- the stored `factors` field is just
[{"name": decision["explanation"], "score": risk}], not a list of which raw Evidence.type
values fired, and `reasoning_trail` doesn't retain that breakdown either. Gap 2 needs live
shadow logging (Phase B) once the real fix is wired into pipeline.py.

For every historical alert whose stored `signature` is "Confirmed Malicious IOC" (i.e.
decision_engine.py's tier==5 branch fired and won), this re-derives what the FIXED logic
would have produced, using the exact same inputs that were fed to ReputationClassifier.classify()
at the time (features["ti_risk"], features["abuseipdb_risk"], features["vt_risk"] -- see the
dependency map for where each of those is generated) plus the independent-source count parsed
back out of the alert's own stored reasoning_trail.

Old logic (classifier.py:103, decision_engine.py:168-173):
    confirmed_ioc = vt_score > 2.0 or ti_score > 2.0 or abuse_score >= 4.0  -> tier 5 -> CRITICAL

New logic (the Gap 1 fix):
    verified_ioc = ti_score > 2.0
    if tier == 5 and verified_ioc:            CRITICAL "Confirmed Malicious IOC"        (unchanged)
    elif tier == 5 and not verified_ioc:
        if num_independent_sources >= 1:       CRITICAL "Corroborated Reputation Signal" (label-only change)
        else:                                  HIGH     "Strong Reputation Signal (Uncorroborated)" (real downgrade)

Cross-references every flipped alert's device_id against state/autonomous_muted.jsonl (was
it later corrected -- operator or LLM -- as a false positive?) and
state/confirmed_threat_counts.json (does this device have OTHER confirmed-threat history,
suggesting caution about downgrading it?), so the summary shows not just "how many would
change" but "does the change look right."
"""
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
STATE_DIR = ROOT / "state"

_INDEPENDENT_SOURCES_RE = re.compile(r"(\d+)\s+independent evidence source")
_HYPOTHESES_RE = re.compile(
    r"Hypotheses: attack='([^']*)' \(score=([\d.]+)\) vs benign='([^']*)' \(score=([\d.]+)\)"
)

_HARD_STOP_EXPLANATIONS = frozenset({
    "Internal Honeypot Accessed",
    "Layer-2 ARP Spoofing Detected",
    "Geofencing Policy Violation",
    "Confirmed Exploit/Malware Signature (Suricata)",
})


def _strip_persistence_suffix(signature: str) -> str:
    return (signature or "").split(" (persisted ", 1)[0]


def _load_muted_devices(state_dir: Path) -> dict:
    """device_id -> sorted list of correction timestamps, from every
    autonomous_muted.jsonl entry (operator taps, llm_validated, autonomous_stage23)."""
    path = state_dir / "autonomous_muted.jsonl"
    by_device = defaultdict(list)
    if not path.exists():
        return by_device
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            dev_id = entry.get("device", {}).get("id")
            ts = entry.get("ts_unix")
            if dev_id and ts:
                by_device[dev_id].append(float(ts))
    for dev_id in by_device:
        by_device[dev_id].sort()
    return by_device


def _load_confirmed_counts(state_dir: Path) -> dict:
    path = state_dir / "confirmed_threat_counts.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _was_later_corrected(dev_id: str, alert_ts: float, muted_by_device: dict, window_days: float = 14.0) -> bool:
    """True if this device had ANY false-positive correction within `window_days` after
    this alert -- doesn't have to be the exact same alert (alerts.json doesn't retain a
    stable enough per-alert key to match precisely across the persistence-escalation
    suffix), but a same-device correction shortly after is strong circumstantial
    evidence this alert (or its immediate recurrence) was the one being corrected."""
    window = window_days * 86400.0
    for ts in muted_by_device.get(dev_id, []):
        if alert_ts <= ts <= alert_ts + window:
            return True
    return False


def run_backtest(alerts_path: Path, state_dir: Path) -> None:
    muted_by_device = _load_muted_devices(state_dir)
    confirmed_counts = _load_confirmed_counts(state_dir)

    total_tier5 = 0
    unchanged_verified = 0
    label_only_change = 0
    real_downgrade = 0
    downgrade_later_corrected = 0
    downgrade_with_other_confirmed_history = 0
    downgrade_neither = 0

    results_path = state_dir / "shadow_backtest_gap1_results.jsonl"
    out_f = open(results_path, "w", encoding="utf-8")

    if not alerts_path.exists():
        print(f"ERROR: {alerts_path} does not exist.", file=sys.stderr)
        return

    with open(alerts_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if alert.get("type") != "ids_alert":
                continue

            signature = _strip_persistence_suffix(alert.get("signature", ""))
            if signature != "Confirmed Malicious IOC":
                continue
            if signature in _HARD_STOP_EXPLANATIONS:
                continue  # not reachable given the check above, kept for clarity/safety

            total_tier5 += 1
            features = alert.get("features", {}) or {}
            ti_score = float(features.get("ti_risk", 0.0) or 0.0)
            vt_score = float(features.get("vt_risk", 0.0) or 0.0)
            abuse_score = float(features.get("abuseipdb_risk", 0.0) or 0.0)
            verified_ioc = ti_score > 2.0

            dev_id = alert.get("device", {}).get("id", "unknown")
            hostname = alert.get("device", {}).get("hostname", "unknown")
            target = alert.get("network_context", {}).get("destination_ip") or alert.get("network_context", {}).get("queried_domain") or "unknown"
            alert_ts = float(alert.get("timestamp", 0) or 0)

            reasoning_trail = alert.get("reasoning_trail", []) or []
            num_independent_sources = 0
            attack_name, attack_score, benign_name, benign_score = "", 0.0, "", 0.0
            for trail_line in reasoning_trail:
                m = _INDEPENDENT_SOURCES_RE.search(trail_line)
                if m:
                    num_independent_sources = int(m.group(1))
                hm = _HYPOTHESES_RE.search(trail_line)
                if hm:
                    attack_name, attack_score = hm.group(1), float(hm.group(2))
                    benign_name, benign_score = hm.group(3), float(hm.group(4))

            # REFINEMENT found while verifying against a live example_pc_fritz_box alert
            # (2026-08-26): decision_engine.py already computes attack_score/benign_score
            # BEFORE the tier==5 branch (evaluate()'s top few lines) but never consults
            # them there. A real example showed attack='NETWORK_INTRUSION' (score=2.0) LOSING
            # to benign='LOCAL_DEVICE_DISCOVERY' (score=2.5) while still being called
            # "Confirmed Malicious IOC" -- "num_independent_sources >= 1" alone is not
            # enough to call something "corroborated"; the corroborating evidence has to
            # actually support the ATTACK conclusion, not just exist. Gap 1's fix must check
            # attack_score > benign_score too, not just count sources.
            attack_wins = attack_score > benign_score

            if verified_ioc:
                unchanged_verified += 1
                new_state, new_explanation = "CRITICAL", "Confirmed Malicious IOC"
            elif num_independent_sources >= 1 and attack_wins:
                label_only_change += 1
                new_state, new_explanation = "CRITICAL", "Corroborated Reputation Signal"
            else:
                # BUGFIX (2026-08-27, user catch): matches decision_engine.py's own fix --
                # HIGH contradicted the "Uncorroborated" label; this is the same situation
                # tier==4 already treats as SUSPICIOUS ("Elevated Reputation Signal
                # (Unconfirmed)"), just a bigger raw score. No real corroboration found ==
                # no HIGH, regardless of which side of the 4.0 line the score landed on.
                real_downgrade += 1
                new_state, new_explanation = "SUSPICIOUS", "Elevated Reputation Signal (Unconfirmed, Tier 5 Score)"

                later_corrected = _was_later_corrected(dev_id, alert_ts, muted_by_device)
                other_confirmed = confirmed_counts.get(dev_id, 0) > 0
                if later_corrected:
                    downgrade_later_corrected += 1
                elif other_confirmed:
                    downgrade_with_other_confirmed_history += 1
                else:
                    downgrade_neither += 1

                out_f.write(json.dumps({
                    "device_id": dev_id, "hostname": hostname, "target": target,
                    "alert_ts_human": alert.get("timestamp"),
                    "ti_score": ti_score, "vt_score": vt_score, "abuse_score": abuse_score,
                    "num_independent_sources": num_independent_sources,
                    "attack_name": attack_name, "attack_score": attack_score,
                    "benign_name": benign_name, "benign_score": benign_score,
                    "old_state": "CRITICAL", "old_explanation": "Confirmed Malicious IOC",
                    "new_state": new_state, "new_explanation": new_explanation,
                    "later_corrected_within_14d": later_corrected,
                    "other_confirmed_threat_history": other_confirmed,
                }) + "\n")

    out_f.close()

    print("=" * 78)
    print("GAP 1 SHADOW BACKTEST -- reputation tier-5 privilege split")
    print("=" * 78)
    print(f"Alerts scanned with signature == 'Confirmed Malicious IOC': {total_tier5}")
    print()
    print(f"  Unchanged (ti_score > 2.0, genuine curated-feed IOC match): {unchanged_verified}")
    print(f"  Label-only change (still CRITICAL, corroborated by >=1 independent source): {label_only_change}")
    print(f"  REAL DOWNGRADE (CRITICAL -> SUSPICIOUS, uncorroborated aggregate reputation only): {real_downgrade}")
    print()
    if real_downgrade:
        print("  Of the real downgrades:")
        print(f"    -> later corrected (operator/LLM FP mark within 14d, same device): {downgrade_later_corrected}")
        print(f"    -> device has OTHER confirmed-threat history (be cautious): {downgrade_with_other_confirmed_history}")
        print(f"    -> neither signal either way (needs manual look): {downgrade_neither}")
    print()
    print(f"Full downgrade detail written to: {results_path}")
    print("=" * 78)


def run_gap3_honeypot_backtest(alerts_path: Path, state_dir: Path) -> None:
    """Backtest for Gap 3 (decision_engine.py's shadow fresh_honeypot check): for every
    historical "Internal Honeypot Accessed" alert, checks whether that EXACT alert's own
    persisted features["zeek_honeypot_hits"] was > 0 (a genuine fresh trigger cycle) or == 0
    (a stale EvidenceStore replay -- the verdict fired from evidence created on an EARLIER
    cycle that hadn't yet aged past its 600s TTL, not from anything that happened THIS
    cycle). Only covers honeypot -- arp_spoofing/geofencing_violation/suricata_signature_match
    don't have as direct a raw-feature equivalent in the stored alert schema to backtest the
    same way; those three are shadow-observable only, via state/shadow_decisions.jsonl."""
    total, fresh, stale = 0, 0, 0
    by_device_fresh: dict = defaultdict(int)
    by_device_stale: dict = defaultdict(int)

    if not alerts_path.exists():
        print(f"ERROR: {alerts_path} does not exist.", file=sys.stderr)
        return

    with open(alerts_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            if alert.get("type") != "ids_alert":
                continue
            if _strip_persistence_suffix(alert.get("signature", "")) != "Internal Honeypot Accessed":
                continue

            total += 1
            hostname = alert.get("device", {}).get("hostname", "unknown")
            hits = float((alert.get("features", {}) or {}).get("zeek_honeypot_hits", 0) or 0)
            if hits > 0:
                fresh += 1
                by_device_fresh[hostname] += 1
            else:
                stale += 1
                by_device_stale[hostname] += 1

    print("=" * 78)
    print("GAP 3 SHADOW BACKTEST -- hard-stop evidence-staleness (honeypot only)")
    print("=" * 78)
    print(f"Alerts scanned with signature == 'Internal Honeypot Accessed': {total}")
    print()
    print(f"  FRESH (zeek_honeypot_hits > 0, genuine trigger this cycle): {fresh}")
    for host, c in sorted(by_device_fresh.items(), key=lambda kv: -kv[1]):
        print(f"    {host}: {c}")
    print(f"  STALE ECHO (zeek_honeypot_hits == 0, EvidenceStore-replay artifact): {stale}")
    for host, c in sorted(by_device_stale.items(), key=lambda kv: -kv[1]):
        print(f"    {host}: {c}")
    print("=" * 78)


if __name__ == "__main__":
    alerts_path = STATE_DIR / "alerts.json"
    run_backtest(alerts_path, STATE_DIR)
    print()
    run_gap3_honeypot_backtest(alerts_path, STATE_DIR)
