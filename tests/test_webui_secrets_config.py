"""
Standalone runtime test for config.py's webui_secrets.env layer
(PRODUCTIZATION_ROADMAP.md Phase 4 -- threat-intel/GeoIP setup wizard). Run
directly: `python3 test_webui_secrets_config.py`.

Runs each scenario in a fresh subprocess -- os.environ is process-global and
load_env_file() only sets a key once (first file wins), so re-importing
config.py in the SAME process across scenarios would silently reuse the first
scenario's environment. A subprocess is the only clean way to test this.
"""
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path as _PathForSysPath

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


SRC_DIR = _PathForSysPath(__file__).resolve().parent.parent / "src"


def _run_scenario(tmp_root: _PathForSysPath, env_content: str, secrets_content: str, probe_key: str) -> str:
    """Writes .env / state/webui_secrets.env under a fresh project root, then runs a
    subprocess that imports config.py against it and prints the resolved value."""
    project_root = tmp_root
    (project_root / "state").mkdir(parents=True, exist_ok=True)
    (project_root / ".env").write_text(env_content, encoding="utf-8")
    if secrets_content is not None:
        (project_root / "state" / "webui_secrets.env").write_text(secrets_content, encoding="utf-8")
    (project_root / "config.yaml").write_text("{}\n", encoding="utf-8")

    # Instantiate LiveConfig directly with a file_path pointed at the scratch project
    # root, rather than importing the pre-built CONFIG singleton -- config.py's
    # module-level CONFIG_FILE is computed from config.py's OWN source location
    # (Path(__file__).parent.parent), not cwd, so os.chdir() alone can't redirect it.
    script = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(SRC_DIR)!r})
        from pathlib import Path
        import config as config_module
        cfg = config_module.LiveConfig(config_module.DEFAULT_CONFIG, Path({str(project_root)!r}) / "config.yaml")
        print(cfg.get({probe_key!r}, "__MISSING__"))
    """)
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=30)
    return result.stdout.strip()


# ── webui_secrets.env takes priority over .env for the same key ─────────────
tmp1 = _PathForSysPath(tempfile.mkdtemp())
out1 = _run_scenario(
    tmp1,
    env_content="ABUSEIPDB_KEY=from_dotenv\n",
    secrets_content="ABUSEIPDB_KEY=from_wizard\n",
    probe_key="abuseipdb_api_key",
)
check("state/webui_secrets.env value wins over .env for the same key", out1 == "from_wizard", f"got {out1!r}")

# ── .env alone still works when webui_secrets.env is absent ─────────────────
tmp2 = _PathForSysPath(tempfile.mkdtemp())
out2 = _run_scenario(
    tmp2, env_content="ABUSEIPDB_KEY=from_dotenv\n", secrets_content=None, probe_key="abuseipdb_api_key",
)
check(".env alone still resolves when webui_secrets.env doesn't exist", out2 == "from_dotenv", f"got {out2!r}")

# ── webui_secrets.env alone works when .env doesn't set the key ─────────────
tmp3 = _PathForSysPath(tempfile.mkdtemp())
out3 = _run_scenario(
    tmp3, env_content="", secrets_content="ABUSEIPDB_KEY=wizard_only\n", probe_key="abuseipdb_api_key",
)
check("webui_secrets.env alone resolves when .env doesn't set the key", out3 == "wizard_only", f"got {out3!r}")

# ── A key from webui_secrets.env is still a _STATIC_KEY (live-reload can't touch it) ──
import importlib.util
spec = importlib.util.spec_from_file_location("config_module", str(SRC_DIR / "config.py"))
config_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config_module)
check("abuseipdb_api_key stays in _STATIC_KEYS (restart-required, unchanged by this feature)",
      "abuseipdb_api_key" in config_module._STATIC_KEYS)
check("webui_port is in _STATIC_KEYS (new port, same restart-tier convention as fastapi_port)",
      "webui_port" in config_module._STATIC_KEYS)


if FAILURES:
    print(f"\n{len(FAILURES)} secrets-config check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("\nAll secrets-config checks PASSED.")
    sys.exit(0)
