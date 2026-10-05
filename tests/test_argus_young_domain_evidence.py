"""
Domain age, part 2b: a young domain as supporting evidence only (MASTER_TODO M2; owner decision 2026-10-05).

Covers, against the real DecisionEngine: young-domain evidence alone changes nothing; with one detector family it
stays below HIGH (it is never an extra source); with two real families on the same destination it adds the bounded
lift that can reach HIGH; a young domain about a different destination adds nothing; it never appears among the
independent sources; the explanation line names it. And the live-engine injection: only this cycle's domain
destinations, never IPs, nothing without a configured source, failures swallowed.

Run directly: `venv/Scripts/python.exe tests/test_argus_young_domain_evidence.py`
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.decision.engine import DecisionEngine, DecisionState, _YOUNG_DOMAIN_SCORE_LIFT  # noqa: E402
from argus.hypotheses.independence import family_for, NON_ATTACK_FAMILIES  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402

NOW = 1_000_000.0
C2 = "c2.evil-new.com"


def ev(evidence_type, dest=NO_DESTINATION, value=1.0, confidence=0.5):
    return Evidence(device_id="cam", destination_id=dest, evidence_type=evidence_type,
                    independence_family=family_for(evidence_type), timestamp=NOW, source="s", value=value,
                    confidence=confidence)


def rep():
    return ReputationVector(domain=C2, tier=3)


def young(dest=C2):
    return ev("domain_age_young", dest=dest, confidence=0.5)


engine = DecisionEngine()


def run(items):
    return engine.evaluate(items, rep(), now=NOW)


def trail(r):
    return " | ".join(r.get("reasoning_trail") or [])


check("domain_age_young is registered as a non-attack family",
      family_for("domain_age_young") == "registration_age" and "registration_age" in NON_ATTACK_FAMILIES)

# --- alone ---
r = run([young()])
check("young-domain evidence alone changes nothing (BENIGN, no sources)",
      r["state"] == DecisionState.BENIGN and r.get("independent_sources", 0) == 0, str({k: r.get(k) for k in ("state", "independent_sources")}))

# --- one detector family on the destination ---
one = [ev("dns_dga_burst", dest=C2)]
r1, r1y = run(one), run(one + [young()])
check("one family: the verdict is the same with or without the young domain (never an extra source)",
      r1["state"] == r1y["state"] and r1["state"] != DecisionState.HIGH and r1y["independent_sources"] == r1["independent_sources"],
      f"{r1['state']} -> {r1y['state']}")

# --- two real families on the same destination ---
two = [ev("dns_dga_burst", dest=C2), ev("zeek_notice_medium", dest=C2)]
r2, r2y = run(two), run(two + [young()])
check("two families below the score bar: SUSPICIOUS without the young domain",
      r2["state"] == DecisionState.SUSPICIOUS, f"{r2['state']} sources={r2.get('independent_sources')}")
check("two families + young domain on the same destination: the lift reaches HIGH",
      r2y["state"] == DecisionState.HIGH, f"{r2y['state']} {trail(r2y)}")
check("the young domain is not counted as a source", r2y["independent_sources"] == r2["independent_sources"])
check("the explanation names the young domain and says it is supporting only",
      C2 in trail(r2y) and "supporting only" in trail(r2y), trail(r2y))

# --- a young domain about something else ---
r2o = run(two + [young("other-new.com")])
check("a young domain about a different destination adds nothing", r2o["state"] == r2["state"], r2o["state"])

check("the lift is one score step (1.0), the smallest that can reach the HIGH bar", _YOUNG_DOMAIN_SCORE_LIFT == 1.0)

# --- one family, scored high enough on its own: still not HIGH, no lift applied ---
r1s = run([ev("dns_dga_burst", dest=C2, confidence=0.9), young()])
check("one strong family + young domain: no lift (needs 2 families), never HIGH",
      r1s["state"] != DecisionState.HIGH and "Domain age" not in trail(r1s), f"{r1s['state']} {trail(r1s)}")

# --- injection in the live engine ---
class _Src:
    def __init__(self, young_names, fail=False):
        self.young, self.fail, self.asked = set(young_names), fail, []

    def is_young(self, d):
        self.asked.append(d)
        if self.fail:
            raise RuntimeError("db")
        return d in self.young


fresh = [ev("dns_dga_burst", dest=C2), ev("dns_dga_burst", dest="old.example.com"), ev("zeek_beaconing", dest="203.0.113.9"),
         ev("peer_deviation", dest=NO_DESTINATION), ev("dns_dga_burst", dest="2001:db8::1")]
live_engine.configure_domain_age(None)
check("no configured source: no evidence", live_engine._inject_domain_age_evidence("cam", fresh, NOW) == [])
src = _Src({C2})
live_engine.configure_domain_age(src)
out = live_engine._inject_domain_age_evidence("cam", fresh, NOW)
check("one evidence item for the young destination, with the right type and family",
      [(e.destination_id, e.evidence_type, e.independence_family) for e in out] == [(C2, "domain_age_young", "registration_age")])
check("IP addresses and no-destination items are never asked about",
      not any(a in src.asked for a in ("203.0.113.9", "2001:db8::1", NO_DESTINATION)), str(src.asked))
live_engine.configure_domain_age(_Src({C2}, fail=True))
check("a failing source yields no evidence, never an exception", live_engine._inject_domain_age_evidence("cam", fresh, NOW) == [])
live_engine.configure_domain_age(None)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("All young-domain supporting-evidence checks PASSED.")
