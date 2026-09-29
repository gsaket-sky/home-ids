"""
Standalone runtime test for the rule-based recommendation panel
(PRODUCTIZATION_ROADMAP.md Phase 4). Run directly:
`python3 test_webui_recommendations.py`.
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


from core.recommendations import build_recommendations


class _Cfg(dict):
    def get(self, k, d=None):
        return super().get(k, d)


# ── Nothing needing attention: default clean state ──────────────────────────
tmp1 = tempfile.mkdtemp()
cfg1 = _Cfg({"onboarding_mode_days": 0})  # onboarding disabled -> no onboarding card
cards1 = build_recommendations(cfg1, tmp1)
check("an empty/clean state produces exactly one 'nothing to do' card",
      len(cards1) == 1 and cards1[0]["severity"] == "ok",
      f"got {cards1}")

# ── Unlabeled devices produce a card linking to /devices ────────────────────
tmp2 = tempfile.mkdtemp()
cfg2 = _Cfg({"onboarding_mode_days": 0})
(_PathForSysPath(tmp2) / "ids_state.json").write_text(json.dumps({
    "devices": {"dev1": {}, "dev2": {}, "dev3": {}}
}))
(_PathForSysPath(tmp2) / "device_labels.json").write_text(json.dumps({"dev1": {"device_type": "phone"}}))
cards2 = build_recommendations(cfg2, tmp2)
check("2 unlabeled devices produces an unlabeled-devices card",
      any("2 device" in c["text"] for c in cards2), f"got {[c['text'] for c in cards2]}")

# ── A stale scheduled job produces a warning card ────────────────────────────
tmp3 = tempfile.mkdtemp()
cfg3 = _Cfg({"onboarding_mode_days": 0})
stale_ts = time.time() - 100 * 3600  # 100h ago, well past every job's expected cadence
(_PathForSysPath(tmp3) / "job_health.json").write_text(json.dumps({
    "retro_hunter": {"last_success": stale_ts, "duration_seconds": 1.0},
}))
cards3 = build_recommendations(cfg3, tmp3)
check("a stale scheduled job produces a warning card",
      any(c["severity"] == "warning" and "retro_hunter" in c["text"] for c in cards3),
      f"got {[c['text'] for c in cards3]}")

# ── Onboarding active produces an actionable card ────────────────────────────
tmp4 = tempfile.mkdtemp()
cfg4 = _Cfg({"onboarding_mode_days": 14})
cards4 = build_recommendations(cfg4, tmp4)
check("active onboarding produces a card with an Activate Protection action",
      any(c.get("action_label") == "Activate Protection Now" for c in cards4),
      f"got {cards4}")


if FAILURES:
    print(f"\n{len(FAILURES)} recommendations check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll recommendations checks PASSED.")
    sys.exit(0)
