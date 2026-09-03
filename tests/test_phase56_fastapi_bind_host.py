"""
Standalone runtime test for Phase 56: main.py's internal FastAPI/uvicorn IPC daemon
(serves /api/ipc/block, /release, /immunize, /revoke, /router_isolation_status --
everything Telegram buttons and the Grafana dashboard's Isolate/Release links hit) used
to hardcode `--host 127.0.0.1`, unconditionally. That's a deliberate security default --
these are powerful hardware-control endpoints, so out of the box nothing else on the LAN
can reach them no matter what token it has -- but it also meant the Grafana dashboard's
Isolate/Release Data Links could NEVER work from a browser on a different machine, even
after fixing the link URL itself to point at the box's real LAN IP (192.168.1.94:8010)
and filling in the real token: nothing was ever listening on that interface to begin
with. Confirmed live: `curl http://192.168.1.94:8010/...` from another device timed
out / connection-refused even with a correct URL and valid token, while the exact same
URL worked from the box itself.

Fix (an explicit operator opt-in, discussed with the user given the security tradeoff):
a new `fastapi_bind_host` config key (default "127.0.0.1", unchanged behavior) that
main.py now passes as uvicorn's --host instead of the hardcoded literal. Setting it to
"0.0.0.0" makes the IPC endpoints reachable from other LAN devices -- at that point
middleware/auth.py's verify_token() bearer-token check (previously bypassed only for
loopback callers) becomes the ONLY thing protecting them, so this test also guards that
loopback-bypass logic hasn't silently drifted, and that every INTERNAL caller in this
codebase (release_device.py, ips.py, alerts.py -- all same-box, same-process-tree calls)
still hardcodes 127.0.0.1 for its own outbound calls regardless of what the daemon binds
to (loopback always reaches a 0.0.0.0-bound server too, so those call sites correctly
never needed to change).

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase56_fastapi_bind_host.py`

Sections:
  A. Config defaults -- fastapi_bind_host exists, defaults to "127.0.0.1", is a
     restart-required (_STATIC_KEYS) key
  B. SOURCE-GUARD: main.py reads fastapi_bind_host from config and passes it (not a
     hardcoded "127.0.0.1" literal) as uvicorn's --host
  C. SOURCE-GUARD: main.py warns when the bind host is opened up beyond loopback
  D. REGRESSION GUARD: every internal IPC caller still hardcodes 127.0.0.1 for its own
     outbound call (release_device.py, ips.py, alerts.py x4)
  E. REGRESSION GUARD: middleware/auth.py's loopback-bypass check is unchanged --
     this is what actually gates LAN access once fastapi_bind_host=0.0.0.0
  F. config.yaml.example documents the new key with a safe (loopback) default
"""
import sys
from pathlib import Path

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from config import DEFAULT_CONFIG, _STATIC_KEYS

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: config defaults
# ═══════════════════════════════════════════════════════════════════════════════════
check("fastapi_bind_host exists in config defaults, set to the safe '127.0.0.1' default",
      DEFAULT_CONFIG.get("fastapi_bind_host") == "127.0.0.1",
      f"got {DEFAULT_CONFIG.get('fastapi_bind_host')!r}")
check("fastapi_bind_host is a restart-required (_STATIC_KEYS) key -- a live daemon can't "
      "rebind its own listening socket without a process restart",
      "fastapi_bind_host" in _STATIC_KEYS)
check("REGRESSION GUARD: fastapi_port is still a _STATIC_KEYS entry too, untouched by this fix",
      "fastapi_port" in _STATIC_KEYS)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section B & C: main.py source checks
# ═══════════════════════════════════════════════════════════════════════════════════
_main_src = (ROOT / "src" / "main.py").read_text(encoding="utf-8")

check('THE CORE FIX: main.py reads fastapi_bind_host from config (CONFIG.get("fastapi_bind_host", "127.0.0.1"))',
      'CONFIG.get("fastapi_bind_host", "127.0.0.1")' in _main_src)
check('THE CORE FIX: the uvicorn subprocess\'s "--host" arg is the fastapi_bind_host variable, '
      'not a hardcoded "127.0.0.1" string literal',
      '"--host", fastapi_bind_host,' in _main_src)
check('REGRESSION GUARD: the OLD hardcoded literal ("--host", "127.0.0.1") is genuinely gone from '
      "the uvicorn Popen args, not just shadowed",
      '"--host", "127.0.0.1",' not in _main_src)
check("THE CORE FIX: main.py logs a WARNING when the bind host is opened up beyond loopback "
      "(operator-visible, not a silent security-relevant config change)",
      'if fastapi_bind_host != "127.0.0.1":' in _main_src and "LOGGER.warning(" in _main_src)
check("REGRESSION GUARD: main.py's own /health readiness probe (checking its OWN just-spawned "
      "daemon) still calls loopback directly -- that check is about reachability from the box "
      "itself, which is always true regardless of fastapi_bind_host",
      'urlopen(f"http://127.0.0.1:{CONFIG.get(\'fastapi_port\', 8010)}/health"' in _main_src)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: REGRESSION GUARD -- every internal caller still hardcodes loopback
# ═══════════════════════════════════════════════════════════════════════════════════
_release_device_src = (ROOT / "src" / "release_device.py").read_text(encoding="utf-8")
check("REGRESSION GUARD: release_device.py's own IPC call still hardcodes 127.0.0.1 -- it's a "
      "same-box CLI tool, always correct regardless of fastapi_bind_host",
      'f"http://127.0.0.1:{fastapi_port}/api/ipc/release"' in _release_device_src)

_ips_src = (ROOT / "src" / "mitigation" / "ips.py").read_text(encoding="utf-8")
check("REGRESSION GUARD: ips.py's router-isolation-status reconcile call still hardcodes "
      "127.0.0.1, untouched by this fix",
      'f"http://127.0.0.1:{fastapi_port}/api/ipc/router_isolation_status"' in _ips_src)

_alerts_src = (ROOT / "src" / "mitigation" / "alerts.py").read_text(encoding="utf-8")
_alerts_loopback_count = _alerts_src.count('f"http://127.0.0.1:{fastapi_port}/api/ipc/')
check("REGRESSION GUARD: all 5 of alerts.py's internal IPC calls (release x2/block/immunize/revoke) "
      "still hardcode 127.0.0.1, untouched by this fix",
      _alerts_loopback_count == 5, f"found {_alerts_loopback_count} occurrences, expected 5")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: REGRESSION GUARD -- the loopback-bypass auth check is unchanged
# ═══════════════════════════════════════════════════════════════════════════════════
_auth_src = (ROOT / "src" / "middleware" / "auth.py").read_text(encoding="utf-8")
check('REGRESSION GUARD: verify_token() still bypasses the token check only for '
      '("127.0.0.1", "::1", "localhost") -- this becomes the ONLY protection once '
      "fastapi_bind_host=0.0.0.0, so it must not have silently drifted",
      'if client_host in ("127.0.0.1", "::1", "localhost"):' in _auth_src)
check("REGRESSION GUARD: verify_token() still rejects a remote request outright when no "
      "fritz_api_token is configured at all (never silently allow-all on the LAN)",
      "API token required for remote access" in _auth_src)

# ═══════════════════════════════════════════════════════════════════════════════════
# Section F: config.yaml.example documents the new key
# ═══════════════════════════════════════════════════════════════════════════════════
_example_src = (ROOT / "config.yaml.example").read_text(encoding="utf-8")
check('config.yaml.example documents fastapi_bind_host with the safe "127.0.0.1" default',
      'fastapi_bind_host: "127.0.0.1"' in _example_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 56 fastapi_bind_host checks PASSED.")
