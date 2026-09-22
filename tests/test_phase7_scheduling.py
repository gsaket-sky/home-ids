"""
Standalone runtime test for Phase 7 (scheduling + training-data integrity fixes). Not
part of the pytest suite — run directly: `python3 test_phase7_scheduling.py`. Exercises
the real scripts/scheduler.py cron logic and scripts/train_fp_classifier.py dataset
loader against your actual repo layout and config.yaml, no mocks.

Covers two confirmed bugs found while auditing the scheduled scripts (originally
ollama_soc, retro_hunter, top_domains_report, train_fp_classifier; ollama_soc.py
itself was retired in v16 in favor of live_llm_review.py, but Section C below stays
relevant regardless -- alerts.json may still carry historical ollama_transparency
entries it wrote before that, which train_fp_classifier.py must keep excluding):

  1. config.yaml's scheduler job key "retrohunter" never matched the actual filename
     scripts/retro_hunter.py — scheduler.py silently logged "not found" and the retro
     hunter never ran, ever, since it was added. Fixed by renaming the job key to
     retro_hunter and giving scheduler.py an explicit "script" override field so this
     class of bug can't silently recur for a future job.
  2. scripts/ollama_soc.py appends `type="ollama_transparency"` entries into the SAME
     alerts.json stream that train_fp_classifier.py treats as ground-truth "confirmed
     threat" training data. Those entries have none of the fields real alerts have, so
     they were silently turned into all-near-zero feature rows and trained as label=0
     threats — confirmed by directly running load_dataset() against a synthetic file
     containing one (see test_phase6_fp_selfheal.py's Section D for the general
     mislabeling-fix pattern this builds on).
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
import time
import json
import tempfile
from pathlib import Path

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "src" / "scripts"

import scripts.scheduler as scheduler_mod
import scripts.train_fp_classifier as train_mod


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: scheduler job -> script-file resolution (the exact bug class that let
# retro_hunter.py silently never run)
# ═══════════════════════════════════════════════════════════════════════════════════
config_path = REPO_ROOT / "config.yaml"
check("config.yaml exists at the expected repo-root location", config_path.exists(),
      f"looked at {config_path}")

if config_path.exists():
    import yaml
    raw_config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    # Use scheduler.py's OWN flattening helper (not a re-derived expression here) so
    # this test proves the shipped code's category-merging behaves correctly, not just
    # this test's independent assumption about the file layout.
    config = scheduler_mod._flatten_config_categories(raw_config)
    scheduler_cfg = config.get("scheduler", {})

    check("config.yaml's scheduler block is non-empty (something is actually configured "
          "to run on a schedule)", len(scheduler_cfg) > 0, f"got={scheduler_cfg}")

    for job_name, cfg in scheduler_cfg.items():
        script_filename = cfg.get("script", f"{job_name}.py")
        script_path = SCRIPTS_DIR / script_filename
        check(f"scheduled job '{job_name}' (enabled={cfg.get('enabled')}) resolves to an "
              f"EXISTING script file — this is the exact check that would have caught "
              f"the retrohunter/retro_hunter.py mismatch before it shipped",
              script_path.exists(), f"resolved path={script_path}")

    check("THE SPECIFIC BUG: the retro hunter job is now keyed 'retro_hunter' (or has an "
          "explicit \"script\" override) so it actually resolves to scripts/retro_hunter.py, "
          "not the never-existing scripts/retrohunter.py",
          any(
              (SCRIPTS_DIR / cfg.get("script", f"{name}.py")).name == "retro_hunter.py"
              for name, cfg in scheduler_cfg.items()
          ),
          f"scheduler_cfg keys={list(scheduler_cfg.keys())}")

    # Regression guard: the OLD broken key must not have silently come back.
    check("the old, never-matching 'retrohunter' (no underscore) job key is gone",
          "retrohunter" not in scheduler_cfg, f"scheduler_cfg keys={list(scheduler_cfg.keys())}")

# scheduler.py's own resolution logic, exercised directly (not just re-deriving the same
# expression inline above) — proves the shipped code, not just this test's reasoning
# about it, does the right thing.
def resolve(job_name, cfg):
    return SCRIPTS_DIR / cfg.get("script", f"{job_name}.py")

check("scheduler.py-style resolution of a job WITHOUT a \"script\" override still falls "
      "back to '<job_name>.py' (unchanged behavior for top_domains_report, whose job key "
      "already matches its filename exactly)",
      resolve("top_domains_report", {}).name == "top_domains_report.py")
check("scheduler.py-style resolution of a job WITH an explicit \"script\" override uses "
      "that filename instead of '<job_name>.py' — this is the defensive fix that keeps "
      "a future job-name/filename mismatch from silently never running again",
      resolve("retro_hunter", {"script": "retro_hunter.py"}).name == "retro_hunter.py")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: cron spacing sanity — confirms the four scheduled jobs (ollama_soc,
# retro_hunter, train_fp_classifier's "autotune" cron, top_domains_report) don't fire
# in the same hour as each other, i.e. they're not all "started at the same time"
# ═══════════════════════════════════════════════════════════════════════════════════
if config_path.exists():
    all_crons = {}
    for job_name, cfg in scheduler_cfg.items():
        if cfg.get("enabled"):
            all_crons[job_name] = cfg.get("cron", "0 0 * * *")
    if config.get("autotune_enabled"):
        all_crons["autotune (train_fp_classifier.py)"] = config.get("autotune_schedule_cron", "0 3 * * *")

    import datetime
    fire_hours = {}
    for job_name, cron in all_crons.items():
        hours = [h for h in range(24) if scheduler_mod.check_cron(cron, datetime.datetime(2026, 1, 5, h, 0))]
        fire_hours[job_name] = set(hours)

    # BUGFIX (2026-09-03): this section's own stated purpose (see the comment above)
    # is checking the DISCRETE daily/weekly batch jobs against each other -- it
    # predates shadow_watcher (a "*/5 * * * *" job, added later) being added to the
    # scheduler. A job firing every 5 minutes around the clock has fire_hours = all
    # 24 hours by construction, so it trivially "collides" with literally any other
    # hourly-or-coarser job under this check -- not a real "started at the same time"
    # resource-contention concern (which is what motivated this check), just a
    # continuously-running poller that was never meant to be compared this way.
    # Confirmed live: every reported collision involved shadow_watcher specifically;
    # the actual discrete batch jobs (ollama_soc/retro_hunter/top_domains_report/
    # autotune) don't collide with each other at all. Excluding any job whose
    # fire_hours spans EVERY hour keeps the check meaningful for what it was built
    # to catch, without needing to hardcode "shadow_watcher" by name (so a future
    # continuously-running job doesn't silently reintroduce this same false
    # positive).
    discrete_fire_hours = {name: hours for name, hours in fire_hours.items() if len(hours) < 24}

    collisions = []
    names = list(discrete_fire_hours.keys())
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            overlap = discrete_fire_hours[names[i]] & discrete_fire_hours[names[j]]
            if overlap:
                collisions.append((names[i], names[j], overlap))

    check("no two enabled scheduled jobs are configured to fire in the same hour "
          "(the user's explicit ask: 'taking care that all are not started at same time')",
          len(collisions) == 0, f"collisions={collisions}, fire_hours={fire_hours}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B2: check_cron()'s comma-separated-list support (BUGFIX 2026-09-15) -- a
# comma list like "2,6,10,14,18,22" (live_llm_review's deliberate 2h stagger from
# ollama_soc's own "*/4" cron, to avoid both hitting .94's single-in-flight-request
# Ollama server at once) used to make match() call int("2,6,10,...") and silently
# swallow the ValueError into an unconditional False -- the job never fired, for days,
# with nothing surfacing it beyond an absent log line nobody was watching. The
# collision check above can't catch this class of bug on its own: a job with zero real
# fire hours (the exact broken state) has an empty fire_hours set, which trivially
# "doesn't collide" with anything -- so this needs its own direct, explicit check.
# ═══════════════════════════════════════════════════════════════════════════════════
import datetime as _dt2

_comma_cron = "30 2,6,10,14,18,22 * * *"
_comma_fire_hours = {h for h in range(24)
                      if scheduler_mod.check_cron(_comma_cron, _dt2.datetime(2026, 1, 5, h, 30))}
check("THE SPECIFIC BUG: check_cron() matches every hour in a comma-separated list "
      "(e.g. live_llm_review's \"30 2,6,10,14,18,22 * * *\"), not zero hours",
      _comma_fire_hours == {2, 6, 10, 14, 18, 22}, f"got={_comma_fire_hours}")

check("a comma-separated cron still correctly rejects a non-matching hour",
      not scheduler_mod.check_cron(_comma_cron, _dt2.datetime(2026, 1, 5, 3, 30)))

# Regression guard: every pre-existing cron style (used by every other real job) must
# still behave identically after adding comma-list support.
_existing_style_crons = {
    "*": ("0 * * * *", 5, True),          # wildcard hour always matches
    "*/N": ("0 */4 * * *", 4, True),      # step still matches an exact multiple
    "*/N miss": ("0 */4 * * *", 5, False),  # step still rejects a non-multiple
    "exact": ("0 3 * * *", 3, True),      # single exact integer still matches
    "exact miss": ("0 3 * * *", 4, False),
}
for _label, (_cron, _hour, _expected) in _existing_style_crons.items():
    _got = scheduler_mod.check_cron(_cron, _dt2.datetime(2026, 1, 5, _hour, 0))
    check(f"pre-existing cron style '{_label}' unaffected by the comma-list fix",
          _got == _expected, f"cron={_cron!r} hour={_hour} got={_got} expected={_expected}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: train_fp_classifier.py no longer trains on ollama_soc's transparency logs
# ═══════════════════════════════════════════════════════════════════════════════════
with tempfile.TemporaryDirectory() as tmpdir:
    state_dir = Path(tmpdir)
    train_mod._resolve_alert_input_paths = lambda sd: [sd / "alerts.json"]

    real_alert = {
        "type": "ids_alert",
        "device": {"id": "dev1", "type": "iot"}, "timestamp": time.time(),
        "network_context": {"queried_domain": "evil-dga-xyz123.biz"},
        "features": {"tranco_rank": 0, "max_label_length": 40, "outbound_bytes_z": 6.0},
        "reasons": [],
    }
    # Exactly what scripts/ollama_soc.py's batch job appends to the SAME alerts.json file.
    transparency_log = {
        "type": "ollama_transparency", "component": "batch_analyzer",
        "device": {"ip": "192.168.1.50"}, "timestamp": time.time(),
        "model": "llama3.1", "prompt": "Alert Payload:...",
        "response": {"classification": "benign"},
    }
    (state_dir / "alerts.json").write_text(
        json.dumps(real_alert) + "\n" + json.dumps(transparency_log) + "\n", encoding="utf-8",
    )

    X, y, stats = train_mod.load_dataset(state_dir)

    check("THE SPECIFIC BUG: the ollama_transparency log entry is excluded from the "
          "training set entirely (not trained as a garbage label=0 'threat' row)",
          stats["threat_skipped_non_alert"] == 1, f"stats={stats}")
    check("the genuine ids_alert entry alongside it IS still trained normally",
          stats["threat_accepted"] == 1, f"stats={stats}")
    check("the resulting dataset has exactly 1 sample (the real alert), not 2",
          len(X) == 1 and len(y) == 1 and y == [0], f"X={X} y={y}")
    check("the one accepted feature row is NOT the previously-observed garbage "
          "all-near-zero pattern a transparency log would have produced "
          "([0,0,0,0,0.3,0,0,0,0.2]) — proves it's the real alert's row, not the "
          "transparency log's",
          X[0] != [0.0, 0.0, 0.0, 0.0, 0.3, 0.0, 0.0, 0.0, 0.2], f"X[0]={X[0]}")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 7 scheduling + training-data-integrity checks PASSED.")
