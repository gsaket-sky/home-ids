"""
Standalone runtime test for /api/ipc/run_script/{name}'s whitelist
(PRODUCTIZATION_ROADMAP.md Phase 4). The whitelist IS the entire security
boundary for this endpoint -- `name` in the URL never builds a path directly
-- so this is a dedicated negative test. Run directly:
`python3 test_webui_run_script_whitelist.py`.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from fastapi.testclient import TestClient
from middleware.routers import webui_ipc
from middleware.auth import CONFIG

# TestClient's request.client.host is "testclient", not "127.0.0.1" -- verify_token()'s
# loopback bypass (real-network-level, can't be spoofed by a remote caller) correctly
# doesn't trust it, same as it wouldn't trust any other non-loopback source. Configure a
# real Bearer token instead, exactly like a genuine remote/cross-container caller would
# need to, rather than trying to fake a loopback connection.
_TEST_TOKEN = "test-token-for-run-script-whitelist"
CONFIG._config["fritz_api_token"] = _TEST_TOKEN
_AUTH_HEADERS = {"Authorization": f"Bearer {_TEST_TOKEN}"}

from fastapi import FastAPI
app = FastAPI()
app.include_router(webui_ipc.router)
client = TestClient(app, headers=_AUTH_HEADERS)

# ── Every whitelisted script's file actually resolves on disk ───────────────
missing = []
for name, (rel_path, _apply) in webui_ipc._RUNNABLE_SCRIPTS.items():
    full = webui_ipc._SRC_DIR / rel_path
    if not full.is_file():
        missing.append(name)
check("every whitelisted script file exists on disk", not missing, f"missing: {missing}")

# ── Path traversal / arbitrary name rejected ─────────────────────────────────
for bad_name in ["../../etc/passwd", "..%2f..%2fconfig", "main", "not_a_real_script", ""]:
    resp = client.post(f"/api/ipc/run_script/{bad_name or 'x'}" if not bad_name else f"/api/ipc/run_script/{bad_name}")
    check(f"unknown/traversal name {bad_name!r} is rejected (404), never executed",
          resp.status_code == 404, f"got {resp.status_code}")

# ── A script that doesn't support --apply rejects apply=true ────────────────
non_apply_name = next(name for name, (_p, supports) in webui_ipc._RUNNABLE_SCRIPTS.items() if not supports)
resp = client.post(f"/api/ipc/run_script/{non_apply_name}", params={"apply": "true"})
check(f"'{non_apply_name}' (no --apply support) rejects apply=true with 400",
      resp.status_code == 400, f"got {resp.status_code}")

# ── A genuinely whitelisted, cheap, side-effect-free script actually runs ───
# identify_corrupted_training_rows.py with no --apply is read-only (dry-run report).
resp = client.post("/api/ipc/run_script/identify_corrupted_training_rows")
check("a real whitelisted script executes and returns exit_code 0",
      resp.status_code == 200 and resp.json().get("exit_code") == 0,
      f"got {resp.status_code} {resp.text[:300]}")


if FAILURES:
    print(f"\n{len(FAILURES)} run-script-whitelist check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll run-script-whitelist checks PASSED.")
    sys.exit(0)
