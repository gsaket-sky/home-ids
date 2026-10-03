# Tests

About 165 test files, one per area (decision engine, hypotheses, evidence families, identity, false-positive engine,
autotuner, health manager, storage, web interface, updater, sync guards, ...). They need no running system: each
builds its own temporary state and graph database.

**Run each file on its own** -- never a bare `pytest tests/`. Many are standalone check scripts with a module-level
`sys.exit()` that would break a pytest collection run.

| Style | How to run |
|---|---|
| Script (prints `[PASS]`/`[FAIL]` lines, exits non-zero on failure) | `python tests/test_x.py` |
| pytest (`def test_...` functions) | `python -m pytest tests/test_x.py` |

CI (`.github/workflows/release.yml`) runs `tests/test_phase*.py` and `tests/test_webui_*.py` as scripts, so a
pytest-style file in those groups needs an `if __name__ == "__main__": pytest.main(...)` hook.

The only expected local failure is `test_phase45_*`, which needs the licensed MaxMind GeoLite ASN database in
`models/`.

**Beyond unit tests:**

- The nightly backtest (`src/argus/ops/backtest_job.py`) replays real incidents and a synthetic attack sweep through
  the real decision code.
- `tools/threat_simulator.py` generates real attack-shaped traffic from another device on the LAN, to check a running
  installation end to end.
