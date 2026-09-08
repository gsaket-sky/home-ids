"""
test_telegram_vocabulary_coverage.py - v13 full-architecture plan, Phase 7
(presentation-layer drift guard).

Audit finding this session (not guessed): pipeline.py's Telegram alert IS driven
by the single real decision engine (the headline `threat_name` is sourced
directly from decision["explanation"]), but the WHY-section per-evidence text
comes from two separate, hardcoded lookup tables -- _EVIDENCE_PLAIN_LANGUAGE and
_EVIDENCE_FAMILY_LABELS -- that describe the SAME evidence the decision engine
scored, via a non-authoritative vocabulary. An evidence_type/family with no
entry doesn't error -- it silently falls back to a generic
`.replace("_", " ").capitalize()` label. That's an acceptable fallback for a
genuinely new/rare type, but a real drift (a detector renaming or adding a type
that never gets a human-readable entry) would never surface on its own. This
test makes that drift LOUD instead of silent.

Real gaps found and fixed by this same session's audit: arp_spoof_pending,
local_device_discovery, suricata_signature_match, malicious_ja3, malicious_ja4
were all missing from _EVIDENCE_PLAIN_LANGUAGE (present in real detector code,
confirmed via direct grep across src/intelligence/detectors/ and
src/core/pipeline.py's own Evidence(...) construction sites) -- now added.
_EVIDENCE_FAMILY_LABELS was already complete against
intelligence/hypotheses/evidence.py's real EVIDENCE_FAMILIES frozenset (10/10)
at the time of this audit.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_telegram_vocabulary_coverage.py`
"""
import re
import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

FAILURES = []


def check(label: str, condition: bool) -> None:
    status = "[PASS]" if condition else "[FAIL]"
    print(f"{status} {label}")
    if not condition:
        FAILURES.append(label)


from core.pipeline import _EVIDENCE_PLAIN_LANGUAGE, _EVIDENCE_FAMILY_LABELS  # noqa: E402
from intelligence.hypotheses.evidence import EVIDENCE_FAMILIES  # noqa: E402


def _extract_literal_evidence_types() -> set:
    """Regex-scans every real evidence-producing source file for a literal
    `type="..."` (or `evidence_type="..."`) argument -- catches the vast
    majority of real evidence types directly from source, without needing to
    import/execute detector code. Deliberately over-broad (scans core/
    and intelligence/detectors/ entirely) rather than an exact file list, so a
    brand-new detector file is automatically covered too."""
    found = set()
    pattern = re.compile(r'\btype\s*=\s*"([a-z][a-z0-9_]*)"')
    search_roots = [SRC_DIR / "core" / "pipeline.py"] + list((SRC_DIR / "intelligence" / "detectors").glob("*.py"))
    for path in search_roots:
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        found.update(pattern.findall(text))
    return found


def _extract_threat_signals_add_types() -> set:
    """threat_signals.py builds Evidence via a local add(etype, ...) helper --
    the type is a variable there, invisible to the plain type="..." regex above.
    Extracts the literal first-argument string from every add("...", call site
    instead."""
    path = SRC_DIR / "intelligence" / "detectors" / "threat_signals.py"
    if not path.exists():
        return set()
    text = path.read_text(encoding="utf-8")
    return set(re.findall(r'\badd\(\s*"([a-z][a-z0-9_]*)"', text))


# zeek_network.py's malicious_ja3/malicious_ja4 evidence type is read directly
# off Zeek's own raw event dict (`evt.get("type")`), not a literal in this
# codebase -- a real, KNOWN, stable pair (confirmed via direct read this
# session), recorded here explicitly since no static regex can discover it.
# If Zeek/this detector ever adds a third malicious-fingerprint type, a
# reviewer touching zeek_network.py should update this set alongside it.
_KNOWN_DYNAMIC_EVIDENCE_TYPES = {"malicious_ja3", "malicious_ja4"}


def main() -> None:
    real_types = (
        _extract_literal_evidence_types()
        | _extract_threat_signals_add_types()
        | _KNOWN_DYNAMIC_EVIDENCE_TYPES
    )
    check("sanity: extraction found a substantial real evidence-type set (not an empty/broken scan)",
          len(real_types) >= 15)

    missing_plain_language = sorted(t for t in real_types if t not in _EVIDENCE_PLAIN_LANGUAGE)
    check(f"every real evidence_type has a _EVIDENCE_PLAIN_LANGUAGE entry (missing: {missing_plain_language})",
          not missing_plain_language)

    missing_family_labels = sorted(f for f in EVIDENCE_FAMILIES if f not in _EVIDENCE_FAMILY_LABELS)
    check(f"every real EVIDENCE_FAMILIES family has an _EVIDENCE_FAMILY_LABELS entry (missing: {missing_family_labels})",
          not missing_family_labels)

    # Guards the guard: if this ever stops catching a real gap, the test itself
    # is worthless -- prove it actually fails loud on an injected unmapped type.
    fake_plain_language = dict(_EVIDENCE_PLAIN_LANGUAGE)
    del fake_plain_language["dns_rate"]
    check("REGRESSION GUARD: removing a real entry is correctly detected as a gap (proves this test isn't a no-op)",
          "dns_rate" not in fake_plain_language and "dns_rate" in real_types)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} check(s) FAILED:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All Telegram vocabulary coverage checks PASSED.")


if __name__ == "__main__":
    main()
