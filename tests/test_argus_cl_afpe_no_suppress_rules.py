"""U6 (DETECTION_CORE_REWORK, handover 2026-10-14): two things Stage 2/3 must never do.

1. The static rule fallback (used when no trained embedding model is loaded -- the fresh-install default) may RANK, never
   suppress or immunize: it scored any CDN/cloud-pattern domain 0.88 -> FALSE_POSITIVE, immunized the domain and unblocked
   it in Pi-hole, even for a corroborated HIGH.
2. Stage 2/3 never suppresses a decision with >= 2 independent evidence families (rule G3, first step), whatever the
   scores say.
A real model's suppression of a single-family alert still works (control).

Run directly: `python tests/test_argus_cl_afpe_no_suppress_rules.py`"""
import sys
import tempfile
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402

NOW = 1_000_000.0
store = GraphStore(str(_P(tempfile.mkdtemp(prefix="clafpe_nosupp_")) / "t.db"))


class FakeScorer:
    """A loaded model: high classifier score, high embedding similarity to a known vendor pattern."""
    def score_stage2(self, features, domain, is_trust_cached=False):
        return 0.95

    def score_stage3(self, domain):
        return 0.95, "known vendor pattern"


def alert(dev, domain):
    return {"signature": "NETWORK_INTRUSION", "device": {"id": dev, "hostname": dev}, "network_context": {
        "queried_domain": domain, "destination_ip": ""}, "features": {}}


def trusted(base):
    """True when a trust edge exists for the base (eTLD+1) domain -- what immunize() writes."""
    return bool(store.get_edges(relation="trusts", dst_id=base))


def run(engine, dev, domain, decision=None):
    store.upsert_device(dev, timestamp=NOW)
    a = alert(dev, domain)
    return engine.evaluate(a, a["features"], decision=decision, asn_owner="", now=NOW)


no_model = ClAfpeEngine(store)                       # no scorer: Stage 2/3 uses the static rule fallback
for label, domain, base in (("CDN/cloud pattern", "d111111abcdef8.cloudfront.net", "cloudfront.net"),
                            ("telemetry", "o123456.ingest.sentry.io", "sentry.io")):
    v = run(no_model, "dev_" + label[:3], domain, decision={"state": "HIGH", "independent_sources": 2,
                                                            "evidence_families": ["a", "b"], "evidence_types": ["x", "y"]})
    check(f"no model, {label} domain, corroborated HIGH: not a FALSE_POSITIVE", v["verdict"] != "FALSE_POSITIVE", str(v["verdict"]))
    v2 = run(no_model, "dev_s_" + label[:3], domain)     # no decision at all: the fallback still cannot suppress
    check(f"no model, {label} domain, no decision context: not a FALSE_POSITIVE", v2["verdict"] != "FALSE_POSITIVE", str(v2["verdict"]))
    check(f"no model, {label} domain: no trust edge written for {base}", not trusted(base))

with_model = ClAfpeEngine(store, ml_scorer=FakeScorer())
v = run(with_model, "dev_m1", "cdn.vendor-example.net", decision={"state": "HIGH", "independent_sources": 1,
                                                                   "evidence_families": ["a"], "evidence_types": ["x"]})
check("control: a loaded model still suppresses a single-family alert", v["verdict"] == "FALSE_POSITIVE", str(v["verdict"]))
v = run(with_model, "dev_m2", "cdn2.vendor-example.net", decision={"state": "HIGH", "independent_sources": 2,
                                                                    "evidence_families": ["a", "b"], "evidence_types": ["x", "y"]})
check("a loaded model does not suppress a decision with 2 independent families", v["verdict"] != "FALSE_POSITIVE", str(v["verdict"]))
check("control: the single-family suppression wrote its trust edge (so the edge check is meaningful)", trusted("vendor-example.net"))
v = run(with_model, "dev_m3", "x.other-example.org", decision={"state": "HIGH", "independent_sources": 3,
                                                                "evidence_families": ["a", "b", "c"], "evidence_types": ["x"]})
check("a refused suppression immunizes nothing", v["verdict"] != "FALSE_POSITIVE" and not trusted("other-example.org"))
print("NO SUPPRESS RULES", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
