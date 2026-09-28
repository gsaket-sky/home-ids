"""
Standalone runtime test for Phase 62 (Gap 6 item 6, tarpit mitigation).

CORRECTED SCOPE, found while implementing (not assumed from the original third-party
review): the review's premise -- "only Monitor/Pi-hole-block/Isolation exist; no
tarpit module" -- was WRONG. mitigation/ips.py already has a fully-built, live,
decision-driven Layer-2 dual-stack (ARP + NDP) tarpit subsystem (Scapy-based,
_arp_tarpit_loop/_ndp_tarpit_loop worker threads, ips_tarpit_active/
ips_tarpit_activations_total metrics, persistent state, interactive-mode gating,
operator-release-cooldown respect, lateral-threat override) -- activated at
risk_score>=9.0 or a lateral-threat signal, in the SAME real-time code path that
handles hardware router isolation. Confirmed by reading the code directly before
building anything, exactly the "verify, don't assume" discipline this whole session
has been trying to apply to the LLM's own reasoning.

The REAL gap: IPSMitigator.release_device() already exists (the same one the
operator's manual Telegram Release button uses) and already releases tarpit +
router isolation + Pi-hole blocks together for a device -- but ollama_soc.py's
benign-confirmation path only ever called unblock_by_base_domain() (Pi-hole), never
release_device(). PHASE 14's own comment already states the intended principle --
"an autonomous correction should also undo containment that's no longer warranted,
not just stop future alerts" -- but that principle was only half-implemented: a
device that crossed the real-time risk_score>=9.0 tarpit bar BEFORE Ollama's later
review validated the same pattern as benign stayed trapped indefinitely, with no
autonomous path back out. Phase 62 closed that: both benign-confirmation branches
(domain-immunize and the no-domain/IP-only fallback) called
ips_mitigator.release_device(device_id) -- a safe no-op if the device isn't
currently contained, real containment release if it is.

[RETIRED, Section B below] ollama_soc.py itself was deleted 2026-09-22 (commit 57c9c4a,
"consolidate Layer-3 LLM review onto live_llm_review.py") -- its successor is
advisory/reporting-only by design (live_llm_review.py's own docstring: "an LLM verdict
here does NOT autonomously suppress or confirm anything," that authority retired to
argus/autotune/engine.py + argus/cl_afpe/composite_trust.py, neither of which calls
release_device()). Phase 62's specific benign-confirmation-releases-containment wiring
has no live equivalent to test; Section B's checks were removed rather than pointed at
a replacement.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase62_tarpit_release_on_benign.py`

Sections:
  A. mitigation/ips.py -- tarpit subsystem genuinely exists and is decision-driven
     (source-level confirmation, so this test fails loudly if a future refactor
     removes what this phase's fix depends on)
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


_ips_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "mitigation" / "ips.py").read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: the tarpit subsystem genuinely already exists
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: mitigation/ips.py's existing tarpit subsystem ---")

check("a real Layer-2 dual-stack (ARP+NDP) tarpit worker exists, not a stub",
      "def _arp_tarpit_loop(self)" in _ips_src and "def _ndp_tarpit_loop(self)" in _ips_src)

check("tarpit activation is decision-driven (risk_score>=9.0 or lateral_threat), in "
      "the same real-time path as router isolation -- not a separate, disconnected "
      "mechanism",
      "risk_score >= 9.0 or lateral_threat" in _ips_src)

check("release_device() already exists and releases tarpit targets specifically "
      "(not just router isolation/Pi-hole)",
      "def release_device(self, identifier: str) -> bool:" in _ips_src
      and "del self._tarpit_active_targets[ip]" in _ips_src)

check("release_device() ALSO releases router isolation and Pi-hole blocks in the "
      "same call -- confirms it's the correct single entry point to reuse, not one "
      "of several partial release mechanisms",
      "del self._router_isolated_devices[mac]" in _ips_src
      and "self.unblock_domain(dom, reason=\"manual\")" in _ips_src)


# Section B (ollama_soc.py wiring) removed -- see module docstring: ollama_soc.py was
# deleted 2026-09-22 and this wiring has no live equivalent.

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 62 tarpit-release-on-benign checks PASSED.")
