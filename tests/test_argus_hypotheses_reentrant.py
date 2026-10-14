"""
Per-call hypotheses (MASTER_TODO 0d "Found while working", 2026-10-14; follows U7's pure decide()).

HypothesisEngine kept ONE instance of each hypothesis for the life of the process, and each instance carries scratch state
from its last evaluation (required_satisfied, strong/supporting/contradicting scores, even its own `name` for the
hypotheses that rename themselves) plus an override the engine wrote onto the shared instance and never reset
(DeviceProfileBenignHypothesis.FAMILIARITY_TRUST_BAR, set from the autotuner's value). So decide() was pure only while a
single thread decided at a time, and an evaluation could see the previous call's trust bar. Each evaluate_all() call now
builds its own hypothesis instances: nothing survives a call, and concurrent calls (parallel challenger evaluation,
console/API threads) cannot touch each other.

Run directly: `python tests/test_argus_hypotheses_reentrant.py`
"""
import sys
import threading
import time
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
from argus.evidence.ingest import convert_list  # noqa: E402
from argus.hypotheses.independence import INDEPENDENCE_FAMILY_MAP  # noqa: E402
import argus.hypotheses.engine as hyp  # noqa: E402

NOW = time.time()
rep = ReputationVector(domain="", tier=3)


def evidence(*types, value=6.0):
    return convert_list([V1Evidence(type=t, source="x", timestamp=NOW, device="d", value=value, confidence=0.9,
                                    domain="example.net") for t in types], INDEPENDENCE_FAMILY_MAP)


def summary(result):
    return (result["attack"]["name"], round(result["attack"]["score"], 9), result["benign"]["name"],
            round(result["benign"]["score"], 9),
            tuple(sorted((result["attack"].get("checklist") or {}).items())))


# --- nothing survives a call: the trust-bar override of one call never reaches the next ---------------------------------
# Input that exercises the bar: routine telemetry (dns_rate > 20) on an expected-category device, familiarity 0.5 -- the
# device-profile benign hypothesis is satisfied at a bar of 0.4 and not at the default 0.6.
engine = hyp.HypothesisEngine()
TELEMETRY = evidence("dns_rate", value=25.0)


def benign_score(bar):
    return engine.evaluate_all(TELEMETRY, rep, "smart_tv", 0.5, now=NOW, familiarity_trust_bar=bar)["benign"]["score"]


check("setup: at the default bar (0.6) familiarity 0.5 is not enough", benign_score(None) == 0.0, str(benign_score(None)))
check("setup: at an overridden bar of 0.4 it is", benign_score(0.4) > 0.0, str(benign_score(0.4)))
check("the override of the previous call does not leak: the next call without one is back at the default",
      benign_score(None) == 0.0, str(benign_score(None)))
check("the class default of the trust bar is untouched", hyp.DeviceProfileBenignHypothesis.FAMILIARITY_TRUST_BAR == 0.6)

# --- the hypotheses a caller can inspect are not the ones that decided -------------------------------------------------
a1, b1 = engine.attack_hypotheses, engine.benign_hypotheses
a2 = engine.attack_hypotheses
check("attack_hypotheses/benign_hypotheses describe the registered hypotheses (fresh, never carrying a call's state)",
      len(a1) == 11 and len(b1) == 3 and all(h.strong_score == 0.0 and not h.required_satisfied for h in a1 + b1))
check("each access gives new instances (no shared mutable object)", all(x is not y for x, y in zip(a1, a2)))
try:
    engine.attack_hypotheses = []
    check("the registered list cannot be replaced on an instance", False, "assignment succeeded")
except AttributeError:
    check("the registered list cannot be replaced on an instance", True)

# --- concurrent calls do not touch each other -----------------------------------------------------------------------------
CASES = [
    (evidence("dns_dga_burst"), "laptop", 0.0, None),
    (evidence("zeek_exfiltration", "zeek_beaconing"), "laptop", 0.0, None),
    (evidence("zeek_lateral_scan"), "smart_tv", 0.9, 0.2),
    (evidence("zeek_notice_medium", "dns_rate"), "smart_tv", 0.5, 0.95),
    (evidence("arp_sweep", "zeek_conn_abuse"), "iot", 0.1, None),
    ([], "router", 0.9, 0.3),
]
shared = hyp.HypothesisEngine()
expected = [summary(hyp.HypothesisEngine().evaluate_all(ev, rep, dt, fam, now=NOW, familiarity_trust_bar=bar))
            for ev, dt, fam, bar in CASES]
mismatches = []
errors = []


def worker(i):
    try:
        for _ in range(250):
            ev, dt, fam, bar = CASES[i % len(CASES)]
            got = summary(shared.evaluate_all(ev, rep, dt, fam, now=NOW, familiarity_trust_bar=bar))
            if got != expected[i % len(CASES)]:
                mismatches.append((i, got))
                return
    except Exception as exc:  # pragma: no cover
        errors.append(repr(exc))


threads = [threading.Thread(target=worker, args=(i,)) for i in range(12)]
old_interval = sys.getswitchinterval()
sys.setswitchinterval(1e-6)             # switch threads as often as the interpreter allows
try:
    for t in threads:
        t.start()
    for t in threads:
        t.join()
finally:
    sys.setswitchinterval(old_interval)
check("12 threads x 250 evaluations on ONE engine give each input its own sequential result",
      not mismatches and not errors, f"{mismatches[:1]} {errors[:1]}")

print("HYPOTHESES REENTRANT", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
