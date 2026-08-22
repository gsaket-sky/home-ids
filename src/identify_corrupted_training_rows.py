"""
identify_corrupted_training_rows.py -- audits the historical alert training data (the
same sources train_fp_classifier.py's load_dataset() reads: alerts.json / configured
alert_json_path, and autonomous_muted.jsonl) for rows whose Feature 1
(f1_entropy, extract_features_from_alert()'s "first label entropy") was computed from
the WRONG domain, because of two now-fixed domain-attribution bugs:

  - DNS_COVERT_TUNNELING alerts before commit 192d5dc ("fix: DNS_COVERT_TUNNELING
    alerts displayed AND acted on the wrong domain") had the alert's queried_domain
    fall back to _select_target_domain()'s generic "most notable domain in the whole
    window" pick -- structurally disconnected from which domain actually triggered the
    dns_tunnel_v2 evidence that cycle.
  - DGA_BOTNET_C2 alerts before commit 851835a ("fix: DGA_BOTNET_C2 had no real domain
    attribution either -- same gap as DNS_COVERT_TUNNELING, worse in kind") had the
    exact same structural gap; dns_dga_burst carried no domain examples at all pre-fix,
    so queried_domain for these alerts was never even plausibly correct.

Both bugs are fixed at the SOURCE (pipeline.py no longer produces wrong data going
forward) -- this script only concerns itself with rows already written to disk before
each respective fix landed, which train_fp_classifier.py would otherwise keep training
on with a corrupted f1_entropy value indefinitely.

Rather than mutating or deleting anything in alerts.json / autonomous_muted.jsonl --
both are shared historical logs other consumers read too (Grafana, retro_hunter.py,
manual audit) -- this writes a separate, inspectable, deletable overlay file,
state/training_row_exclusions.json, listing the dedup key (device_id|domain|timestamp,
the same convention train_fp_classifier.py's _alert_dedup_key() already uses to
cross-reference the two sources) of every corrupted row found.
train_fp_classifier.py's load_dataset() consults this file and skips matching rows
during training only -- the underlying alert history is never touched. This mirrors
the config_overrides.json / config.yaml split already established in this codebase
(train_fp_classifier.py's own module docstring: "config.yaml stays the human-authored
baseline; the override layer is a separate, plainly-inspectable, deletable file").

Usage:
  Dry run (report only, changes nothing):
    python3 src/identify_corrupted_training_rows.py
  Apply (writes/updates state/training_row_exclusions.json):
    python3 src/identify_corrupted_training_rows.py --apply
"""
import json
import sys
import time
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from scripts.train_fp_classifier import (
    _resolve_alert_input_paths, _read_alert_docs, _extract_payload, _alert_dedup_key,
)

# Fix-commit timestamps (unix epoch, from `git show -s --format=%ct <sha>`) -- the
# conservative per-signature lower bound: an alert of that signature timestamped
# strictly before its own commit is provably running the unfixed attribution code.
# Same repo, same alert-payload "timestamp" field (a float epoch -- see
# pipeline.py's `"timestamp": now` where now = time.time()), so a direct numeric
# comparison is exact, no timezone parsing involved.
_CORRUPTION_CUTOFFS = {
    "DNS_COVERT_TUNNELING": 1787388636,  # commit 192d5dc
    "DGA_BOTNET_C2": 1787403864,          # commit 851835a
}


def _is_corrupted(payload: dict) -> bool:
    sig = payload.get("signature")
    cutoff = _CORRUPTION_CUTOFFS.get(sig)
    if cutoff is None:
        return False
    ts = payload.get("timestamp")
    if not isinstance(ts, (int, float)):
        return False  # no timestamp to compare -- can't prove corruption, don't guess
    return ts < cutoff


def _scan(state_dir: Path) -> dict:
    """Returns {dedup_key: {"signature":..., "timestamp":..., "source": "threat"|"fp"}}
    for every corrupted row found across both training-data sources."""
    found = {}

    for path in _resolve_alert_input_paths(state_dir):
        docs = _read_alert_docs(path)
        if not docs:
            continue
        for doc in docs:
            payload = _extract_payload(doc)
            if payload.get("type") != "ids_alert":
                continue
            if _is_corrupted(payload):
                key = _alert_dedup_key(payload)
                found[key] = {
                    "signature": payload.get("signature"),
                    "timestamp": payload.get("timestamp"),
                    "source": "threat",
                }
        break  # mirrors load_dataset()'s own "first non-empty source wins" priority

    muted_path = state_dir / "autonomous_muted.jsonl"
    if muted_path.exists():
        for line in muted_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError:
                continue
            payload = _extract_payload(doc)
            if _is_corrupted(payload):
                key = _alert_dedup_key(payload)
                found[key] = {
                    "signature": payload.get("signature"),
                    "timestamp": payload.get("timestamp"),
                    "source": "fp",
                }

    return found


def main():
    apply_changes = "--apply" in sys.argv
    state_dir = SRC_DIR.parent / "state"
    exclusions_path = state_dir / "training_row_exclusions.json"

    corrupted = _scan(state_dir)

    if not corrupted:
        print("No historically-corrupted DNS_COVERT_TUNNELING / DGA_BOTNET_C2 training "
              "rows found -- nothing to exclude.")
        return

    by_sig = {}
    for entry in corrupted.values():
        by_sig[entry["signature"]] = by_sig.get(entry["signature"], 0) + 1
    by_source = {}
    for entry in corrupted.values():
        by_source[entry["source"]] = by_source.get(entry["source"], 0) + 1

    verb = "Would exclude" if not apply_changes else "Excluding"
    print(f"{verb} {len(corrupted)} historically-corrupted training row(s) from future retrains:")
    for sig, count in sorted(by_sig.items()):
        cutoff_human = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(_CORRUPTION_CUTOFFS[sig]))
        print(f"  {sig}: {count} row(s) predating the fix ({cutoff_human})")
    print(f"  ({by_source.get('threat', 0)} from the threat/alert stream, "
          f"{by_source.get('fp', 0)} from autonomous_muted.jsonl)")

    if not apply_changes:
        print(f"\nDry run only -- nothing was changed. Re-run with --apply to write "
              f"{exclusions_path}.")
        print("Note: this does NOT modify alerts.json/autonomous_muted.jsonl -- it only "
              "tells train_fp_classifier.py which existing rows to skip.")
        return

    existing = {}
    if exclusions_path.exists():
        try:
            existing = json.loads(exclusions_path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing_keys = existing.get("excluded_keys", {})
    existing_keys.update({
        key: {**meta, "excluded_at": time.time(), "reason": "domain_attribution_bug"}
        for key, meta in corrupted.items()
    })
    exclusions_path.write_text(
        json.dumps({"excluded_keys": existing_keys}, indent=2), encoding="utf-8"
    )
    print(f"\nDone. Wrote {len(existing_keys)} total excluded row(s) to {exclusions_path}.")
    print("These rows are now skipped by train_fp_classifier.py's next retrain -- run it "
          "manually or wait for the next scheduled cycle to see the effect.")


if __name__ == "__main__":
    main()
