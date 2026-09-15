"""Tests for src/middleware/routers/autonomy_api.py -- direct-call style, real
GraphStore against a temp SQLite file, following test_graph_api.py's/
test_config_api.py's own convention.

Seeds threshold_history/cl_afpe_trust via direct SQL matching their real
schema/INSERT shape (AutotuneEngine.propose_change()'s own statement,
composite_trust.record_corroborating_signal()'s own statement) -- this test
is exercising the READ/serialization side (autonomy_api.py itself), not the
proposal-validation or corroboration-accumulation logic, which already have
their own dedicated test coverage elsewhere.
"""
import sys
import time
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from argus.graph.store import GraphStore  # noqa: E402
from middleware import graph_client  # noqa: E402
from middleware.routers import autonomy_api  # noqa: E402


@pytest.fixture
def graph_db(tmp_path, monkeypatch):
    db_path = tmp_path / "v13_graph.db"
    store = GraphStore(str(db_path))
    now = time.time()

    # --- autotuner: one promoted tightening, one pending loosening ---
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, parameter, old_value, new_value, "
        "proposed_at, canary_until, promoted_at, reason, backtest_run_id) VALUES "
        "('chg_tight', NULL, 'hard_stop_candidate_sensitivity', 0.85, 0.70, ?, ?, ?, "
        "'synthetic detection fell below floor', 'run_1')",
        (now - 3600, now - 1800, now - 1000),
    )
    store._conn.execute(
        "INSERT INTO threshold_history (change_id, device_id, parameter, old_value, new_value, "
        "proposed_at, canary_until, reason, backtest_run_id) VALUES "
        "('chg_loose', NULL, 'bocpd_hazard_rate', 0.004, 0.002, ?, ?, "
        "'every class at 100 percent detection, no drift', 'run_2')",
        (now - 100, now + 21500),
    )

    # --- composite trust: one resolved grant, one still-building tuple ---
    store.upsert_device("dev_a", timestamp=now)
    store.upsert_destination("192.168.1.41", "ip", timestamp=now)
    store.add_edge("device", "dev_a", "destination", "192.168.1.41", "trusts", timestamp=now,
                    metadata={"source": "autonomous_local_origin", "hypothesis": "COORDINATED_TARGETING"})
    store._conn.execute("INSERT OR IGNORE INTO hypotheses (hypothesis_id, kind) VALUES ('COORDINATED_TARGETING', 'attack')")
    store.upsert_device("dev_b", timestamp=now)  # cl_afpe_trust.device_id is a real FK too
    store._conn.execute(
        "INSERT INTO cl_afpe_trust (device_id, behavior_fingerprint, destination_class, hypothesis_id, "
        "evidence_family, regime_id, trust_value, n, last_updated) VALUES "
        "('dev_b', 'NORMAL', 'private', 'COORDINATED_TARGETING', 'cross_device_correlation', 0, 0.3, 2, ?)",
        (now,),
    )
    store._maybe_commit()
    store.close()
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", db_path)


def test_autonomy_empty_store_returns_empty_lists(tmp_path, monkeypatch):
    monkeypatch.setattr(graph_client, "GRAPH_DB_PATH", tmp_path / "does_not_exist.db")
    result = autonomy_api.get_autonomy(limit=50, token="test")
    assert result == {"autotuner": [], "trust_grants": [], "building_trust": []}


def test_autonomy_autotuner_direction_labeled_correctly(graph_db):
    result = autonomy_api.get_autonomy(limit=50, token="test")
    by_change_id = {row["change_id"]: row for row in result["autotuner"]}

    tightened = by_change_id["chg_tight"]
    assert tightened["parameter"] == "hard_stop_candidate_sensitivity"
    # hard_stop_candidate_sensitivity is used as a min_confidence BAR
    # (decision/engine.py:353) -- a HIGHER value means FEWER things qualify as
    # a hard-stop candidate (harder to clear -> less sensitive), so tightening
    # (wanting to catch MORE) means the value must go DOWN. Confirmed two
    # independent ways: (1) direct execution of backtest_job.py's own
    # _propose_tuning_change() formula against argus/autotune/engine.py's own
    # CURRENT _LESS_SENSITIVE_DIRECTION[...]=1 and max_step=0.05 gives
    # 0.745 -> 0.695 for a tightening step; (2) that matches this parameter's
    # own plain-English _LESS_SENSITIVE_DIRECTION comment verbatim. NOTE (not
    # yet resolved, flagged separately to the user, not silently assumed
    # away): the ONE real threshold_history row on .94
    # (old=0.745, new=0.795) shows an INCREASE for a row whose own reason
    # text says "tightening" -- the opposite of what this verified-correct
    # formula produces, and git history shows neither file has changed since
    # that row was written. This fixture and this test assert the
    # code-verified-correct direction, not the one real row's own value.
    assert tightened["direction"] == "tightened"
    assert tightened["status"] == "promoted"

    loosened = by_change_id["chg_loose"]
    # bocpd_hazard_rate's direction is -1 (LOWER = less sensitive) and the
    # value went DOWN -- also loosened, opposite raw sign from the case above,
    # proving this isn't just "new > old".
    assert loosened["direction"] == "loosened"
    assert loosened["status"] == "pending_canary"


def test_autonomy_trust_grants_carry_a_human_source_label(graph_db):
    result = autonomy_api.get_autonomy(limit=50, token="test")
    assert len(result["trust_grants"]) == 1
    grant = result["trust_grants"][0]
    assert grant["device_id"] == "dev_a"
    assert grant["destination_id"] == "192.168.1.41"
    assert grant["source"] == "autonomous_local_origin"
    assert "local-origin" in grant["source_label"].lower()


def test_autonomy_building_trust_reports_progress_toward_the_floor(graph_db):
    result = autonomy_api.get_autonomy(limit=50, token="test")
    assert len(result["building_trust"]) == 1
    row = result["building_trust"][0]
    assert row["device_id"] == "dev_b"
    assert row["trust_value"] == pytest.approx(0.3)
    assert row["trust_floor"] == pytest.approx(0.6)
    assert row["progress_fraction"] == pytest.approx(0.5)


def test_autonomy_respects_limit(graph_db):
    result = autonomy_api.get_autonomy(limit=1, token="test")
    assert len(result["autotuner"]) == 1
