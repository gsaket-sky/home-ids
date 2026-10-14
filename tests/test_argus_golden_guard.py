"""
Continuous golden guard (DETECTION_CORE_REWORK.md H2, MASTER_TODO 0d P0): the frozen golden decision cases
(src/argus/golden/cases.json) decide exactly as pinned, inside their safety bounds, on every change.

Also checks the guard itself: it is deterministic and independent of the wall clock, it catches a broken rule, a pin
change needs a reason and is never written over the committed file, overrides check the safety bounds only, the case
file is canonical text, every decision path and single-signal basis is covered, and the case data is network-agnostic.

A pin failure after a deliberate behaviour change: see argus/golden/guard.py's docstring (propose, review, commit).

Run directly: `python tests/test_argus_golden_guard.py`
"""
import ipaddress
import re
import sys
import tempfile
import time
from pathlib import Path as _P
from unittest import mock
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


import argus.decision.engine as decision_engine  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402
from argus.evidence.model import NO_DESTINATION  # noqa: E402
from argus.golden import guard  # noqa: E402
from mitigation.containment_gate import SINGLE_SIGNAL_BASES  # noqa: E402

cases = guard.load_cases()
by_id = {c.case_id: c for c in cases}

# --- 1. the committed set passes: pins and safety bounds ------------------------------------------------------------
report = guard.run_guard(cases)
check("every golden case decides as pinned and inside its safety bounds", report.passed, report.describe())
check(f"the set is substantial ({len(cases)} cases, >= 30)", len(cases) >= 30)
check("every kind is represented", {c.kind for c in cases} == guard.CASE_KINDS, sorted({c.kind for c in cases}))
check("every case has a pin and the reason it was accepted",
      all(c.pinned and c.pinned_reason.strip() for c in cases),
      [c.case_id for c in cases if not (c.pinned and c.pinned_reason.strip())])
# an attack case has a lower bound, except a scenario case whose target in that intel setup is "none" (e.g. a weak
# signal that only means something when a feed names it) -- that one is bounded from above instead
check("every attack case has a lower bound (or, target 'none', an upper bound), every benign case an upper bound and "
      "a containment bound",
      all(c.expect.state_at_least or (c.note.startswith("target none") and c.expect.state_at_most)
          for c in cases if c.kind == "attack")
      and all(c.expect.state_at_most and c.expect.containment is not None for c in cases if c.kind == "benign"),
      [c.case_id for c in cases if (c.kind == "attack" and not c.expect.state_at_least and not c.note.startswith("target none"))
       or (c.kind == "benign" and not (c.expect.state_at_most and c.expect.containment is not None))])
check(f"the whole set runs in milliseconds ({report.elapsed_ms:.1f} ms < 500 ms)", report.elapsed_ms < 500.0)

# --- 2. canonical text: a diff of cases.json shows exactly what moved ------------------------------------------------
raw = guard.DEFAULT_CASES_PATH.read_bytes()
check("cases.json is LF-only", b"\r\n" not in raw)
check("cases.json is canonical (dump(load(file)) == file): no hand formatting, no lost field",
      guard.dump_cases(cases) == raw.decode("utf-8"))

# --- 3. deterministic, wall-clock independent, inputs untouched -------------------------------------------------------
before = guard.dump_cases(cases)
again = guard.run_guard(cases)
check("deciding twice gives identical summaries",
      [r.summary for r in report.results] == [r.summary for r in again.results])
with mock.patch("time.time", return_value=time.time() + 30 * 86400):
    later = guard.run_guard(cases)
check("the decisions do not depend on the wall clock (30 days later: same)", later.passed, later.describe())
check("running the guard leaves the case inputs unchanged", guard.dump_cases(cases) == before)

# --- 4. the guard catches regressions ----------------------------------------------------------------------------------
no_honeypot = [r for r in decision_engine.DEFAULT_HARD_STOP_REGISTRY if r.name != "honeypot"]
with mock.patch.object(live_engine._v13_engine, "hard_stop_registry", no_honeypot):
    broken = guard.run_guard(cases)
failed = {r.case_id for r in broken.failures}
check("a removed honeypot rule fails the honeypot case (bounds and pin)",
      "exception_honeypot_contact" in failed
      and any("missed" in v for v in next(r for r in broken.results
                                          if r.case_id == "exception_honeypot_contact").violations), broken.describe())

with mock.patch.object(decision_engine, "_count_independent_sources", lambda families: len(families)):
    b6_broken = guard.run_guard(cases)
check("counting the Zeek-derived families separately again (B6 broken) moves a pin",
      "beacon_with_malicious_ja3" in {r.case_id for r in b6_broken.failures}, b6_broken.describe())


def _boom(*_a, **_k):
    raise RuntimeError("engine down")


with mock.patch.object(live_engine._v13_engine, "evaluate", _boom):
    raising = guard.run_guard(cases[:3])
check("a decide() error is a failure, never a pass",
      not raising.passed and all("raised" in r.violations[0] for r in raising.results))

# --- 5. overrides (challenger / tuned champion values) check the safety bounds, not the pins -------------------------
check("a parameter decide() does not read has no golden verdict",
      guard.guard_parameter_value("bocpd_hazard_rate", 0.005, cases) is None)
same = guard.guard_parameter_value("familiarity_trust_bar", live_engine.CHAMPION_DEFAULTS.familiarity_trust_bar, cases)
check("an override run does not check pins", same is not None and not same.pins_checked and same.passed,
      same.describe() if same else "None")
blind = guard.guard_parameter_value("reputation_tier_suspicious_floor", 5.0, cases)
check("a floor that hides a curated-feed match is rejected (missed attack)",
      blind is not None and "exception_verified_feed_ioc" in {r.case_id for r in blind.failures})
loose = guard.guard_parameter_value("reputation_tier_suspicious_floor", 1.0, cases)
check("a floor that turns one weak feed score into a containment exception is rejected",
      loose is not None and any("containment" in v for r in loose.failures for v in r.violations), loose and loose.describe())

# --- 6. pin changes: a reason, a separate file, never automatic -------------------------------------------------------
try:
    guard.propose(cases, "  ")
    check("a pin change without a reason is refused", False)
except ValueError:
    check("a pin change without a reason is refused", True)
with mock.patch.object(decision_engine, "_count_independent_sources", lambda families: len(families)):
    proposed, diff = guard.propose(cases, "test reason")
moved = {c.case_id for c in proposed if c.pinned != by_id[c.case_id].pinned}
check("a proposal re-pins exactly the moved cases and records the reason on them",
      moved and moved == {r.case_id for r in b6_broken.failures if r.pin_diff}
      and all(c.pinned_reason == "test reason" for c in proposed if c.case_id in moved), sorted(moved))
check("the proposal diff names each moved case", all(any(line.startswith(cid + ":") for line in diff) for cid in moved))
check("proposing never touches cases.json", guard.DEFAULT_CASES_PATH.read_bytes() == raw)
try:
    guard.main(["--propose", str(guard.DEFAULT_CASES_PATH), "--reason", "x"])
    check("the CLI refuses to write a proposal over cases.json", False)
except SystemExit as e:
    check("the CLI refuses to write a proposal over cases.json", e.code != 0)
with tempfile.TemporaryDirectory() as tmp:
    out = _P(tmp) / "proposal.json"
    check("the CLI writes an unchanged proposal for unchanged code",
          guard.main(["--propose", str(out), "--reason", "x"]) == 0 and out.read_bytes() == raw)

# --- 7. coverage: every decision path and single-signal basis ---------------------------------------------------------
src = _P(decision_engine.__file__).read_text(encoding="utf-8")
paths = set(re.findall(r'decision_path\s*=\s*"([a-z0-9_]+)"', src))
paths |= {r.decision_path for r in decision_engine.DEFAULT_HARD_STOP_REGISTRY}
paths |= {r.uncorroborated_decision_path for r in decision_engine.DEFAULT_HARD_STOP_REGISTRY if r.requires_corroboration}
pinned_paths = {c.pinned["decision_path"] for c in cases}
check("every decision path the engine can take has a golden case", paths <= pinned_paths, sorted(paths - pinned_paths))
check("every owner-named single-signal basis has a golden case",
      SINGLE_SIGNAL_BASES <= {c.pinned["single_signal_basis"] for c in cases})
check("every attack and benign hypothesis outcome kind is exercised (HIGH and a benign hypothesis win)",
      any(c.pinned["state"] == "HIGH" for c in cases)
      and any(c.pinned["benign_hypothesis"][1] > 0 for c in cases))

# --- 8. the cases are decided with the live champion's defaults -------------------------------------------------------
live_engine.configure(str(_P(tempfile.mkdtemp(prefix="argus_golden_")) / "graph.db"))
resolved = live_engine.resolve_decision_parameters("golden-device")
check("CHAMPION_DEFAULTS is what an untuned device resolves to", resolved == live_engine.CHAMPION_DEFAULTS,
      f"{resolved} != {live_engine.CHAMPION_DEFAULTS}")
check("every case is decided with the champion defaults (or says why not)",
      all(c.params == live_engine.CHAMPION_DEFAULTS for c in cases))

# --- 9. network-agnostic data: documentation ranges and reserved names only --------------------------------------------
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]
_RESERVED = (".example", ".example.com", ".example.net", ".example.org", ".test", ".invalid", ".home.arpa")


def _agnostic(name: str) -> bool:
    if name == NO_DESTINATION:
        return True
    try:
        return any(ipaddress.ip_address(name) in net for net in _DOC_NETS)
    except ValueError:
        return ("." + name).endswith(_RESERVED)


names = set()
for c in cases:
    g = c.gathered
    for e in g.fresh_v2 + g.windowed_v2 + g.baseline_v2 + g.domain_age_v2:
        names.add(e.destination_id)
    for item in g.graph_derived:
        names.add(getattr(item, "destination_id", None) or item.destination)
    if g.rep_vector is not None:
        names.add(g.rep_vector.domain)
bad = sorted(n for n in names if not _agnostic(n))
check("every destination is a documentation address or a reserved name", not bad, bad)

print("GOLDEN GUARD", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
