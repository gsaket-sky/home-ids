"""
Standalone runtime test for identify_corrupted_training_rows.py + its wiring into
train_fp_classifier.py's load_dataset(). Not part of the pytest suite — run directly:
`python3 tests/test_phase31_corrupted_training_rows.py`.

Covers:
  1. _is_corrupted(): per-signature cutoff logic (before/after fix commit, unrelated
     signature, missing timestamp).
  2. _scan(): end-to-end over synthetic alerts.json + autonomous_muted.jsonl, isolated
     from real production state via a temporary CONFIG override.
  3. train_fp_classifier.load_dataset() actually SKIPS rows listed in
     state/training_row_exclusions.json, without needing alerts.json itself modified.
"""
import json
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


from identify_corrupted_training_rows import _is_corrupted, _CORRUPTION_CUTOFFS, _scan

# ── Test 1: _is_corrupted() cutoff logic ────────────────────────────────────────────
dns_cutoff = _CORRUPTION_CUTOFFS["DNS_COVERT_TUNNELING"]
dga_cutoff = _CORRUPTION_CUTOFFS["DGA_BOTNET_C2"]

check("a DNS_COVERT_TUNNELING alert BEFORE its fix commit is flagged corrupted",
      _is_corrupted({"signature": "DNS_COVERT_TUNNELING", "timestamp": dns_cutoff - 1}))
check("a DNS_COVERT_TUNNELING alert AFTER its fix commit is NOT flagged",
      not _is_corrupted({"signature": "DNS_COVERT_TUNNELING", "timestamp": dns_cutoff + 1}))
check("a DGA_BOTNET_C2 alert BEFORE its fix commit is flagged corrupted",
      _is_corrupted({"signature": "DGA_BOTNET_C2", "timestamp": dga_cutoff - 1}))
check("a DGA_BOTNET_C2 alert AFTER its fix commit is NOT flagged",
      not _is_corrupted({"signature": "DGA_BOTNET_C2", "timestamp": dga_cutoff + 1}))
check("an unrelated signature (e.g. CONNECTION_ABUSE) is never flagged, any timestamp",
      not _is_corrupted({"signature": "CONNECTION_ABUSE", "timestamp": 0}))
check("a row with no timestamp is NOT flagged (can't prove corruption, don't guess)",
      not _is_corrupted({"signature": "DNS_COVERT_TUNNELING"}))
check("the two signatures have DISTINCT cutoffs (DGA fix landed after DNS_COVERT_TUNNELING's)",
      dga_cutoff > dns_cutoff)


# ── Test 2 + 3: _scan() end-to-end, isolated from real production state ────────────
import config as _config_mod
_orig_alert_path = _config_mod.CONFIG._config.get("alert_json_path")

with tempfile.TemporaryDirectory() as tmpdir:
    state_dir = _PathForSysPath(tmpdir)
    alerts_path = state_dir / "alerts.json"
    muted_path = state_dir / "autonomous_muted.jsonl"

    # Force the SAME path load_dataset()/_scan() resolve to, so this test never reads
    # real production alerts.json data.
    _config_mod.CONFIG._config["alert_json_path"] = str(alerts_path)

    alerts = [
        {  # corrupted: DNS_COVERT_TUNNELING, before its fix
            "type": "ids_alert", "signature": "DNS_COVERT_TUNNELING",
            "timestamp": dns_cutoff - 100,
            "device": {"id": "devA", "type": "laptop"},
            "network_context": {"queried_domain": "corrupted1.example"},
            "features": {},
        },
        {  # clean: DNS_COVERT_TUNNELING, after its fix
            "type": "ids_alert", "signature": "DNS_COVERT_TUNNELING",
            "timestamp": dns_cutoff + 100,
            "device": {"id": "devA", "type": "laptop"},
            "network_context": {"queried_domain": "clean1.example"},
            "features": {},
        },
        {  # corrupted: DGA_BOTNET_C2, before its fix
            "type": "ids_alert", "signature": "DGA_BOTNET_C2",
            "timestamp": dga_cutoff - 100,
            "device": {"id": "devB", "type": "phone"},
            "network_context": {"queried_domain": "corrupted2.example"},
            "features": {},
        },
        {  # irrelevant signature, must never be flagged regardless of timestamp
            "type": "ids_alert", "signature": "CONNECTION_ABUSE",
            "timestamp": 100,
            "device": {"id": "devC", "type": "iot"},
            "network_context": {"queried_domain": "irrelevant.example"},
            "features": {},
        },
    ]
    alerts_path.write_text(json.dumps(alerts), encoding="utf-8")

    muted_doc = {
        "type": "LLM_VALIDATED_FALSE_POSITIVE",
        "original_alert": {
            "type": "ids_alert", "signature": "DNS_COVERT_TUNNELING",
            "timestamp": dns_cutoff - 50,
            "device": {"id": "devD", "type": "tablet"},
            "network_context": {"queried_domain": "corrupted3.example"},
            "features": {},
        },
    }
    muted_path.write_text(json.dumps(muted_doc) + "\n", encoding="utf-8")

    found = _scan(state_dir)

    check("_scan() finds exactly 3 corrupted rows (2 threat-stream + 1 muted-FP)",
          len(found) == 3, f"got {len(found)}: {list(found.keys())}")

    threat_sigs = [v["signature"] for v in found.values() if v["source"] == "threat"]
    fp_sigs = [v["signature"] for v in found.values() if v["source"] == "fp"]
    check("both threat-stream corrupted rows are found (1 DNS_COVERT_TUNNELING, 1 DGA_BOTNET_C2)",
          sorted(threat_sigs) == ["DGA_BOTNET_C2", "DNS_COVERT_TUNNELING"], f"got {threat_sigs}")
    check("the muted-FP corrupted row is found, correctly tagged source='fp'",
          fp_sigs == ["DNS_COVERT_TUNNELING"], f"got {fp_sigs}")
    check("REGRESSION GUARD: the clean post-fix DNS_COVERT_TUNNELING row is NOT flagged",
          not any("clean1.example" in k for k in found), f"keys={list(found.keys())}")
    check("REGRESSION GUARD: the unrelated CONNECTION_ABUSE row is NOT flagged",
          not any("irrelevant.example" in k for k in found), f"keys={list(found.keys())}")

    # Write the exclusions file the way main() --apply does, then confirm
    # train_fp_classifier.py's load_dataset() actually honors it.
    exclusions_path = state_dir / "training_row_exclusions.json"
    exclusions_path.write_text(
        json.dumps({"excluded_keys": {k: {**v, "excluded_at": time.time()} for k, v in found.items()}}, indent=2),
        encoding="utf-8",
    )

    from scripts.train_fp_classifier import load_dataset, _load_training_row_exclusions

    loaded_exclusions = _load_training_row_exclusions(state_dir)
    check("_load_training_row_exclusions() reads back all 3 written keys",
          loaded_exclusions == set(found.keys()), f"got {loaded_exclusions}")

    X, y, stats = load_dataset(state_dir)
    check("load_dataset() skips all 3 excluded rows (stats counter)",
          stats["skipped_corrupted_attribution"] == 3, f"stats={stats}")
    check("load_dataset() still accepts the 2 clean rows (clean1 + irrelevant) as normal threat samples",
          stats["threat_accepted"] == 2, f"stats={stats}")
    check("load_dataset() found zero FP samples (the only muted doc was excluded, not trained)",
          stats["fp_accepted"] == 0, f"stats={stats}")

    # REGRESSION GUARD: with the exclusions file absent entirely, nothing is skipped —
    # this feature must be strictly opt-in/additive, never silently active by default.
    exclusions_path.unlink()
    X2, y2, stats2 = load_dataset(state_dir)
    check("REGRESSION GUARD: with no exclusions file present, load_dataset() skips nothing "
          "via this mechanism (feature is inert until identify_corrupted_training_rows.py "
          "--apply has actually been run)",
          stats2["skipped_corrupted_attribution"] == 0, f"stats2={stats2}")
    check("...and the previously-excluded rows are now trained normally (4 threat total)",
          stats2["threat_accepted"] == 4, f"stats2={stats2}")
    check("...and the previously-excluded muted-FP row is now trained normally too",
          stats2["fp_accepted"] == 1, f"stats2={stats2}")

# Restore real CONFIG state
if _orig_alert_path is not None:
    _config_mod.CONFIG._config["alert_json_path"] = _orig_alert_path
else:
    _config_mod.CONFIG._config.pop("alert_json_path", None)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All corrupted-training-row identification/exclusion checks PASSED.")
