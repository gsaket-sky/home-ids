"""
Standalone runtime test for the 2026-09-23 disk-capacity/retention audit fixes.
Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_disk_retention_audit_fixes.py`

No monkeypatching anywhere in this file -- real GraphStore/AutonomousFPEngine
instances, real files on disk, real sqlite3.Connection.set_trace_callback() where a
count of real writes is needed (same pattern as tests/test_argus_live_engine.py's
Section L).

Covers:
  A. GraphStore.get_active_device_ids() -- with/without the seen_since cutoff
  B. GraphStore.prune_backtest_runs() / prune_threshold_history()
  C. GraphStore.prune_stale_regime_baselines() / prune_stale_regime_trust() --
     the "superseded AND old" double condition, never touching the current regime
     or anything recent regardless of regime
  D. utils.rotate_jsonl_if_oversized() -- real file, real rotation
  E. utils.prune_dated_files() -- real files, real mtimes
  F. core.subprocess_launchers.rotate_subprocess_log_if_oversized() -- copytruncate
     correctness against a REAL os.O_APPEND file descriptor (proves the reasoning
     in that function's own docstring, doesn't just assert it)
  G. fp_engine.py's discard_device_profile() now also clears
     confirmed_threat_counts.json (plain + scoped keys) and fp_sigma_shifts.json
  H. train_fp_classifier._write_autotune_relay_stats() prunes stale device_ids out
     of autotune_stats.json's devices dict, against a real GraphStore
"""
import json
import os
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


from argus.graph.store import GraphStore  # noqa: E402
from utils import rotate_jsonl_if_oversized, prune_dated_files  # noqa: E402
from core.subprocess_launchers import rotate_subprocess_log_if_oversized  # noqa: E402
from intelligence.fp_engine import AutonomousFPEngine  # noqa: E402

# ═══════════════════════════════════════════════════════════════════════════════
# Section A: get_active_device_ids()
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_a = tempfile.mkdtemp(prefix="retention_test_a_")
store_a = GraphStore(str(_PathForSysPath(tmpdir_a) / "test.db"))

now = time.time()
store_a.upsert_device("dev_recent", timestamp=now)
store_a.upsert_device("dev_old", timestamp=now - 400 * 86400.0)
store_a.upsert_device("dev_merged", timestamp=now)
store_a._conn.execute("UPDATE devices SET merged_into_device_id = 'dev_recent' WHERE device_id = 'dev_merged'")
store_a._conn.commit()

all_active = store_a.get_active_device_ids()
check("A1: get_active_device_ids() with no cutoff includes both recent and old (not merged) devices",
      "dev_recent" in all_active and "dev_old" in all_active, str(all_active))
check("A2: get_active_device_ids() with no cutoff excludes the merged-away device",
      "dev_merged" not in all_active, str(all_active))

recent_only = store_a.get_active_device_ids(seen_since=now - 30 * 86400.0)
check("A3: get_active_device_ids(seen_since=...) excludes a device idle far longer than the cutoff",
      "dev_recent" in recent_only and "dev_old" not in recent_only, str(recent_only))

store_a.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Section B: prune_backtest_runs() / prune_threshold_history()
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_b = tempfile.mkdtemp(prefix="retention_test_b_")
store_b = GraphStore(str(_PathForSysPath(tmpdir_b) / "test.db"))
now_b = time.time()

store_b._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, overall_pass) VALUES (?, ?, 1)",
    ("run_old", now_b - 200 * 86400.0),
)
store_b._conn.execute(
    "INSERT INTO backtest_runs (run_id, started_at, overall_pass) VALUES (?, ?, 1)",
    ("run_recent", now_b - 1 * 86400.0),
)
store_b._conn.execute(
    "INSERT INTO threshold_history (change_id, parameter, proposed_at) VALUES (?, ?, ?)",
    ("th_old", "fp_combined_suppress_threshold", now_b - 400 * 86400.0),
)
store_b._conn.execute(
    "INSERT INTO threshold_history (change_id, parameter, proposed_at) VALUES (?, ?, ?)",
    ("th_recent", "fp_combined_suppress_threshold", now_b - 1 * 86400.0),
)
store_b._conn.commit()

bt_deleted = store_b.prune_backtest_runs(older_than_days=90.0, now=now_b)
check("B1: prune_backtest_runs() deletes the row past the cutoff", bt_deleted == 1, f"deleted={bt_deleted}")
remaining_bt = {r["run_id"] for r in store_b._conn.execute("SELECT run_id FROM backtest_runs").fetchall()}
check("B2: prune_backtest_runs() keeps the recent row", remaining_bt == {"run_recent"}, str(remaining_bt))

th_deleted = store_b.prune_threshold_history(older_than_days=365.0, now=now_b)
check("B3: prune_threshold_history() deletes the row past the cutoff", th_deleted == 1, f"deleted={th_deleted}")
remaining_th = {r["change_id"] for r in store_b._conn.execute("SELECT change_id FROM threshold_history").fetchall()}
check("B4: prune_threshold_history() keeps the recent row", remaining_th == {"th_recent"}, str(remaining_th))

store_b.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Section C: prune_stale_regime_baselines() / prune_stale_regime_trust()
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_c = tempfile.mkdtemp(prefix="retention_test_c_")
store_c = GraphStore(str(_PathForSysPath(tmpdir_c) / "test.db"))
now_c = time.time()
store_c.upsert_device("devC", timestamp=now_c)

# Three regimes for the same (device, metric, hour): 0 (very old, superseded),
# 1 (old-ish but recent enough it should survive), 2 (current).
for regime, ts in ((0, now_c - 400 * 86400.0), (1, now_c - 10 * 86400.0), (2, now_c - 1 * 86400.0)):
    store_c._conn.execute(
        "INSERT INTO device_baselines (device_id, metric, hour, regime_id, model_kind, n, updated_at) "
        "VALUES (?, 'query_rate', 3, ?, 'gaussian', 10, ?)",
        ("devC", regime, ts),
    )
# A SECOND, entirely old bucket where even the CURRENT (highest) regime is old --
# must never be deleted, since it's still each tuple's own max regime_id.
store_c._conn.execute(
    "INSERT INTO device_baselines (device_id, metric, hour, regime_id, model_kind, n, updated_at) "
    "VALUES (?, 'entropy_avg', 5, 0, 'gaussian', 10, ?)",
    ("devC", now_c - 400 * 86400.0),
)
store_c._conn.commit()

deleted_baselines = store_c.prune_stale_regime_baselines(older_than_days=365.0, now=now_c)
check("C1: prune_stale_regime_baselines() deletes exactly the old+superseded row",
      deleted_baselines == 1, f"deleted={deleted_baselines}")
remaining_regimes = {r["regime_id"] for r in store_c._conn.execute(
    "SELECT regime_id FROM device_baselines WHERE device_id='devC' AND metric='query_rate'").fetchall()}
check("C2: the superseded-but-recent regime (1) and the current regime (2) both survive",
      remaining_regimes == {1, 2}, str(remaining_regimes))
still_has_old_current = store_c._conn.execute(
    "SELECT 1 FROM device_baselines WHERE device_id='devC' AND metric='entropy_avg'").fetchone()
check("C3: an old row that is STILL its own tuple's current (max) regime is never deleted",
      still_has_old_current is not None)

store_c._conn.execute(
    "INSERT INTO hypotheses (hypothesis_id, kind) VALUES ('H1', 'attack') ON CONFLICT DO NOTHING")
for regime, ts in ((0, now_c - 400 * 86400.0), (1, now_c - 1 * 86400.0)):
    store_c._conn.execute(
        "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
        "evidence_family, regime_id, trust_value, n, last_updated) VALUES "
        "('devC', 'bf1', 'cdn', 'H1', 'dns_behavior', ?, 0.5, 5, ?)",
        (regime, ts),
    )
store_c._conn.commit()
deleted_trust = store_c.prune_stale_regime_trust(older_than_days=365.0, now=now_c)
check("C4: prune_stale_regime_trust() deletes exactly the old+superseded row",
      deleted_trust == 1, f"deleted={deleted_trust}")
remaining_trust_regimes = {r["regime_id"] for r in store_c._conn.execute(
    "SELECT regime_id FROM cl_afpe_trust WHERE device_id='devC'").fetchall()}
check("C5: cl_afpe_trust's current regime survives", remaining_trust_regimes == {1}, str(remaining_trust_regimes))

store_c.close()

# ═══════════════════════════════════════════════════════════════════════════════
# Section D: rotate_jsonl_if_oversized()
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_d = tempfile.mkdtemp(prefix="retention_test_d_")
jsonl_path = _PathForSysPath(tmpdir_d) / "test.jsonl"
jsonl_path.write_text("x" * 100, encoding="utf-8")

check("D1: a file under the cap is not rotated",
      rotate_jsonl_if_oversized(jsonl_path, max_bytes=1000) is False)
check("D2: the file's content is untouched", jsonl_path.read_text(encoding="utf-8") == "x" * 100)

jsonl_path.write_text("y" * 2000, encoding="utf-8")
rotated = rotate_jsonl_if_oversized(jsonl_path, max_bytes=1000)
check("D3: a file over the cap IS rotated", rotated is True)
backup_path = jsonl_path.with_suffix(jsonl_path.suffix + ".bak")
check("D4: the oversized content survives in the .bak file",
      backup_path.exists() and backup_path.read_text(encoding="utf-8") == "y" * 2000)
check("D5: the original path no longer exists after rotation (fresh append will recreate it)",
      not jsonl_path.exists())

# ═══════════════════════════════════════════════════════════════════════════════
# Section E: prune_dated_files()
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_e = tempfile.mkdtemp(prefix="retention_test_e_")
reports_dir = _PathForSysPath(tmpdir_e)
old_file = reports_dir / "top_domains_20200101.md"
new_file = reports_dir / "top_domains_20990101.md"
old_file.write_text("old", encoding="utf-8")
new_file.write_text("new", encoding="utf-8")
old_ts = time.time() - 200 * 86400.0
os.utime(old_file, (old_ts, old_ts))

deleted_count = prune_dated_files(reports_dir, "top_domains_*.md", max_age_days=90.0)
check("E1: prune_dated_files() deletes exactly the old file", deleted_count == 1, f"deleted={deleted_count}")
check("E2: the old file is actually gone", not old_file.exists())
check("E3: the recent file survives", new_file.exists())

# ═══════════════════════════════════════════════════════════════════════════════
# Section F: rotate_subprocess_log_if_oversized() -- real O_APPEND correctness
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_f = tempfile.mkdtemp(prefix="retention_test_f_")
log_path = _PathForSysPath(tmpdir_f) / "sub.log"

# Open with append mode -- Python's "a" sets O_APPEND, exactly matching
# subprocess_launchers.py's own real open(path, "a") call for the child's stdout.
fh = open(log_path, "a")
fh.write("a" * 2000)
fh.flush()

check("F1: a log under the cap is not rotated", rotate_subprocess_log_if_oversized(log_path, max_bytes=5000) is False)

fh.write("b" * 4000)
fh.flush()
check("F2: file is now over the cap on disk", log_path.stat().st_size >= 5000)

rotated_f = rotate_subprocess_log_if_oversized(log_path, max_bytes=5000)
check("F3: an oversized log IS rotated", rotated_f is True)
check("F4: the .bak backup holds the pre-rotation content",
      (log_path.with_suffix(".log.bak")).read_text(encoding="utf-8") == "a" * 2000 + "b" * 4000)
check("F5: the live path is truncated to 0 bytes immediately after rotation", log_path.stat().st_size == 0)

# The core correctness claim: the SAME still-open, O_APPEND file descriptor writes
# starting from a fresh 0 -- not into a hole at the old EOF -- because O_APPEND
# always targets the kernel's CURRENT end-of-file, which truncate() just reset to 0.
fh.write("c" * 100)
fh.flush()
fh.close()
check("F6: a write from the SAME still-open fd after rotation lands at a fresh, clean size (no sparse hole)",
      log_path.stat().st_size == 100, f"size={log_path.stat().st_size}")
check("F7: that write's content is exactly what was written, nothing stale from before rotation",
      log_path.read_text(encoding="utf-8") == "c" * 100)

# ═══════════════════════════════════════════════════════════════════════════════
# Section G: fp_engine.py discard_device_profile() now clears sibling stores too
# ═══════════════════════════════════════════════════════════════════════════════
tmpdir_g = tempfile.mkdtemp(prefix="retention_test_g_")
fp = AutonomousFPEngine(config={}, state_dir=tmpdir_g)

fp.record_confirmed_threat("devG", base_domain="evil.example.com", dest_ip=None,
                            reason="STAGE_1_HARD_STOP", signature="CONNECTION_ABUSE")
fp.record_confirmed_threat("devOther", base_domain="other.example.com", dest_ip=None,
                            reason="STAGE_1_HARD_STOP")
fp._apply_sigma_shift("devG", "devG-hostname", direction="TUNE_UP", source="autonomous")
fp._apply_sigma_shift("devOther", "devOther-hostname", direction="TUNE_UP", source="autonomous")

check("G1: confirmed count recorded for devG (plain key)", fp.get_confirmed_count("devG") == 1)
check("G2: confirmed count recorded for devG (scoped key)",
      fp.get_confirmed_count("devG", signature="CONNECTION_ABUSE") == 1)
check("G3: sigma shift recorded for devG", fp.get_sigma_shift("devG") != 0.0)

fp.discard_device_profile("devG", reason="prune")

check("G4: discard_device_profile() clears the plain confirmed-count key",
      fp.get_confirmed_count("devG") == 0)
check("G5: discard_device_profile() clears the scoped confirmed-count key",
      fp.get_confirmed_count("devG", signature="CONNECTION_ABUSE") == 0)
check("G6: discard_device_profile() clears the sigma shift", fp.get_sigma_shift("devG") == 0.0)
check("G7: a DIFFERENT device's confirmed count is untouched", fp.get_confirmed_count("devOther") == 1)
check("G8: a DIFFERENT device's sigma shift is untouched", fp.get_sigma_shift("devOther") != 0.0)

# And it must actually be persisted to disk, not just in-memory.
on_disk_counts = json.loads((_PathForSysPath(tmpdir_g) / "confirmed_threat_counts.json").read_text(encoding="utf-8"))
check("G9: confirmed_threat_counts.json on disk no longer has ANY devG-prefixed key",
      not any(k == "devG" or k.startswith("devG||") for k in on_disk_counts), str(on_disk_counts))
on_disk_sigma = json.loads((_PathForSysPath(tmpdir_g) / "fp_sigma_shifts.json").read_text(encoding="utf-8"))
check("G10: fp_sigma_shifts.json on disk no longer has devG", "devG" not in on_disk_sigma, str(on_disk_sigma))

# ═══════════════════════════════════════════════════════════════════════════════
# Section H: train_fp_classifier's autotune_stats.json stale-device pruning
# ═══════════════════════════════════════════════════════════════════════════════
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))
import train_fp_classifier as tfc  # noqa: E402

tmpdir_h = tempfile.mkdtemp(prefix="retention_test_h_")
state_dir_h = _PathForSysPath(tmpdir_h)
store_h = GraphStore(str(state_dir_h / "test.db"))
now_h = time.time()
store_h.upsert_device("dev_still_here", timestamp=now_h)
store_h.upsert_device("dev_gone", timestamp=now_h - 400 * 86400.0)

# Pre-seed autotune_stats.json as if a PAST run had already written both devices.
(state_dir_h / "autotune_stats.json").write_text(json.dumps({
    "global": {}, "devices": {"dev_still_here": {"hostname": "a"}, "dev_gone": {"hostname": "b"}},
}), encoding="utf-8")

tfc._write_autotune_relay_stats(
    state_dir_h, time.time(), "no_action", (0, 0), {}, {}, store=store_h,
)

final_stats = json.loads((state_dir_h / "autotune_stats.json").read_text(encoding="utf-8"))
check("H1: a device with no recent graph activity is pruned from autotune_stats.json's devices dict",
      "dev_gone" not in final_stats["devices"], str(final_stats["devices"]))
check("H2: a device that's still recently active in the graph survives",
      "dev_still_here" in final_stats["devices"], str(final_stats["devices"]))

store_h.close()

# ═══════════════════════════════════════════════════════════════════════════════
print(f"\n{'='*70}")
if FAILURES:
    print(f"{len(FAILURES)} CHECK(S) FAILED:")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
else:
    print("All checks passed.")
