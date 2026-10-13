"""
Autotune learns only from real outcomes (MASTER_TODO 0c Step 2, Section I open points (a)/(b), 2026-10-13):

- a change is promoted only by a REAL nightly backtest (it ran the golden set) that started after the proposal, passed
  and flagged no drift -- never by a row a job synthesizes for itself (train_fp_classifier confirmed its own proposals
  that way, bypassing the backtest gate);
- one pending proposal per scope and value (the same promotion row was written 7 times for one device);
- confirmations are counted by source; the ARP-threshold tightening counts only an operator's confirmation or a
  curated threat-intel feed match, not CL-AFPE's automatic ones; the operator paths record theirs;
- a backtest class moves only the parameters its evidence passes through.
"""
import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))
sys.path.insert(0, str(SRC / "scripts"))

from argus.autotune.engine import AutotuneEngine, _DEFAULT_CANARY_SECONDS  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402

NOW = 1_800_000_000.0
P = "arp_sweep_unique_targets_threshold"


def _run(store, run_id, at, passed=True, golden=True, drift=False, kind=None):
    store._conn.execute(
        "INSERT INTO backtest_runs (run_id, started_at, finished_at, overall_pass, golden_set_result_json, "
        "synthetic_result_json, drift_result_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (run_id, at, at + 60, 1 if passed else 0, json.dumps({"passed": passed}) if golden else "{}",
         json.dumps({"kind": kind} if kind else {}), json.dumps({"drift_detected": drift})))
    store._maybe_commit()


@pytest.fixture
def env():
    store = GraphStore(":memory:")
    store.upsert_device("d1", timestamp=NOW)
    engine = AutotuneEngine(store)
    _run(store, "evidence", NOW - 10, golden=False, kind="confirmed_label_evidence")   # backs the proposal
    res = engine.propose_change(P, 7.0, reason="t", device_id="d1", backtest_run_id="evidence", now=NOW, default=8.0)
    assert res.accepted
    return store, engine, res.change_id


AFTER = NOW + _DEFAULT_CANARY_SECONDS + 10


@pytest.mark.parametrize("kw,ok", [
    (dict(golden=False, kind="confirmed_label_evidence"), False),            # a synthesized row: never confirms
    (dict(golden=False, kind="population_prior_calibration"), False),
    (dict(passed=False), False),
    (dict(drift=True), False),
    (dict(), True),
])
def test_only_a_real_passing_driftless_backtest_confirms(env, kw, ok):
    store, engine, cid = env
    _run(store, "confirm", NOW + _DEFAULT_CANARY_SECONDS, **kw)
    assert engine.promote_change(cid, "confirm", now=AFTER) is ok


def test_a_backtest_from_before_the_proposal_does_not_confirm(env):
    store, engine, cid = env
    _run(store, "older", NOW - 3600)
    assert engine.promote_change(cid, "older", now=AFTER) is False


def test_latest_real_backtest_run_skips_synthesized_rows(env):
    store, engine, _ = env
    _run(store, "real", NOW + 100)
    _run(store, "synth", NOW + 200, golden=False, kind="confirmed_label_evidence")
    assert engine.latest_real_backtest_run(NOW) == "real"
    assert engine.latest_real_backtest_run(NOW + 150) is None


def test_the_same_value_is_not_proposed_twice_while_pending(env):
    store, engine, cid = env
    res = engine.propose_change(P, 7.0, reason="t", device_id="d1", backtest_run_id="evidence",
                                now=NOW + 7200, default=8.0)
    assert not res.accepted and cid in res.reason


def test_train_fp_waits_for_the_nightly_backtest_instead_of_confirming_itself(env, monkeypatch):
    import train_fp_classifier as tfc
    store, engine, cid = env
    tfc._propose_and_promote(engine, store, P, 7.0, "t", {"rule": "x"}, default=8.0, device_id="d1", now=AFTER)
    row = store._conn.execute("SELECT promoted_at FROM threshold_history WHERE change_id=?", (cid,)).fetchone()
    assert row["promoted_at"] is None                                          # no nightly run yet: still pending
    n_synth = store._conn.execute("SELECT COUNT(*) FROM backtest_runs WHERE synthetic_result_json LIKE "
                                  "'%confirming%'").fetchone()[0]
    assert n_synth == 0                                                        # no self-made confirming row
    _run(store, "nightly", NOW + _DEFAULT_CANARY_SECONDS)
    tfc._propose_and_promote(engine, store, P, 7.0, "t", {"rule": "x"}, default=8.0, device_id="d1",
                             now=AFTER + 10)
    row = store._conn.execute("SELECT promoted_at FROM threshold_history WHERE change_id=?", (cid,)).fetchone()
    assert row["promoted_at"] is not None


# ------------------------------------------------------------------------------------------------ outcome sources

@pytest.fixture
def cl():
    from argus.cl_afpe.engine import ClAfpeEngine
    store = GraphStore(":memory:")
    store.upsert_device("d1", timestamp=NOW)
    class _Intel:                                   # the engine has its confirmed-intel store in production
        def record(self, *a, **k):
            pass
    return ClAfpeEngine(store, local_intel=_Intel())


def test_confirmations_are_counted_by_source(cl):
    from argus.cl_afpe.engine import _confirmation_source
    assert _confirmation_source(["ThreatIntel IOC match (ti_risk=3.00) – domain on global malware blacklist"]) == "feed"
    assert _confirmation_source(["Internal honeypot accessed (2 connections to decoy server)",
                                 "AbuseIPDB blacklisted destination IP (risk=4.0)"]) == "automatic"
    cl.record_confirmed_threat("d1", None, None, reason="HIGH_CRITICAL_DECISION", signature="CONNECTION_ABUSE")
    cl.record_confirmed_threat("d1", None, None, reason="STAGE_1_HARD_STOP", signature="CONNECTION_ABUSE",
                               source="feed")
    cl.record_operator_confirmation("d1", "CONNECTION_ABUSE")
    assert cl.get_confirmed_count("d1", "CONNECTION_ABUSE") == 3               # the plain count, as before
    assert cl.get_confirmed_count("d1", "CONNECTION_ABUSE", sources=("operator", "feed")) == 2
    assert cl.get_confirmed_count("d1", sources=("automatic",)) == 1


def test_arp_tightening_counts_only_real_outcomes():
    import train_fp_classifier as tfc
    src = (SRC / "scripts" / "train_fp_classifier.py").read_text(encoding="utf-8")
    assert tfc.REAL_OUTCOME_SOURCES == ("operator", "feed") and "sources=REAL_OUTCOME_SOURCES" in src


def test_the_telegram_real_threat_answer_records_an_operator_confirmation(tmp_path, monkeypatch):
    from core.state_guard import StateManager
    from middleware.routers import pihole_api
    path = tmp_path / "ids_state.json"
    sm = StateManager(state_path=str(path))
    sm.get_or_create("d1", "10.0.0.5", "h")
    sm.record_action(action_id="r1", action_type="immunize_domain", target="x.example", device_id="d1",
                     hostname="h", extra={"signature": "DGA_BOTNET_C2"})
    sm.flush_to_disk()
    monkeypatch.setattr(pihole_api, "CONFIG", {"state_path": str(path)})
    calls = []

    class _Eng:
        def revoke(self, target):
            pass

        def record_operator_confirmation(self, dev, sig=""):
            calls.append((dev, sig))
    monkeypatch.setattr(pihole_api, "_get_argus_cl_afpe_engine", lambda: _Eng())
    pihole_api._ipc_revoke_logic("r1")
    assert calls == [("d1", "DGA_BOTNET_C2")]


# ------------------------------------------------------------------------------------------------ class -> parameter

def test_a_class_moves_only_the_parameters_its_evidence_passes_through():
    from argus.ops import backtest_job as bj
    affected = bj._classes_affected_by(bj._TUNE_PARAMETER)
    from argus.synthetic.attacks import ATTACK_GENERATORS
    for name, gen in ATTACK_GENERATORS.items():
        has_suricata = any(e.evidence_type == "suricata_signature_match" for e in gen("p"))
        assert (name in affected) == has_suricata
    totals = {"port_scan": (1, 10), "honeypot_touch": (0, 10)}
    assert bj._restrict_to_parameter(totals, bj._TUNE_PARAMETER) == {k: v for k, v in totals.items() if k in affected}


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
