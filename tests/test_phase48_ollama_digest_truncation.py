"""
Standalone runtime test for Phase 48: ollama_soc.py's Telegram digest was being cut
off mid-sentence. Not part of the pytest suite -- run directly:
`python3 tests/test_phase48_ollama_digest_truncation.py`.

Context (2026-09-01): a live operator report pasted a real Telegram digest that ended
mid-word, inside entry #7 of a run with 54 "withheld_multi_device" outcomes:
"...indicating no known malicious activity associated wit" -- cut off, no closing
quote, no trailing entries, nothing.

Root cause: the digest was capped by ENTRY COUNT alone (10 entries), then the whole
finished message was hard-sliced to [:4000] characters as an afterthought. Ten
entries' worth of real LLM reasoning text (each ~200-400 chars once you include the
device/target line, the LLM quote, and the outcome line) routinely exceeds 4000
characters well before reaching the 10th entry, so the count cap never actually
prevented the character-level slice from firing -- and that slice cuts wherever it
lands, with zero regard for entry or sentence boundaries.

Sections:
  A. Empty pattern_outcomes -> None (nothing to send, matches the old `if
     ordered_keys:` gate at the call site)
  B. A handful of short entries -> everything included, no truncation, no "...and N
     more" trailer
  C. THE BUG'S EXACT SHAPE: many entries with realistic-length LLM reasoning text
     (enough to exceed the character budget before the count cap would) -> the
     message NEVER ends mid-entry -- every entry that appears is complete, and a
     "...and N more" trailer accounts for the rest
  D. REGRESSION GUARD: the message never exceeds Telegram's real 4096-char hard limit
  E. REGRESSION GUARD: the optional "Technical detail" section is dropped entirely
     (not truncated) when it wouldn't fit
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts"))

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


from ollama_soc import build_ollama_digest_message


def _make_po(i: int, outcome: str = "withheld_multi_device", reason_len: int = 260) -> dict:
    """One synthetic pattern-outcome entry, matching the real dict shape ollama_soc.py's
    main() appends to pattern_outcomes (see its two pattern_outcomes.append() call
    sites). reason_len defaults to a realistic real-world LLM reasoning length (real
    examples in the live report ran ~200-400 chars)."""
    return {
        "cache_key": f"key{i}", "device_id": f"dev{i}", "hostname": f"device_{i}_fritz_box",
        "device_ip": f"192.168.1.{i}", "target": f"target-{i}.example.com", "target_asn_note": "",
        "signature": "NETWORK_INTRUSION", "classification": "benign",
        "llm_confidence": 0.8, "llm_reason": ("x" * reason_len), "alerts_covered": 1,
        "outcome": outcome, "outcome_detail": f"withheld {i} time(s) — spread detail here",
    }


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: empty input
# ═══════════════════════════════════════════════════════════════════════════════════
check("empty pattern_outcomes returns None -- nothing to send",
      build_ollama_digest_message([], "report.md") is None)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: a handful of short entries -- everything fits, no truncation needed
# ═══════════════════════════════════════════════════════════════════════════════════
small = [_make_po(i, reason_len=50) for i in range(3)]
msg_small = build_ollama_digest_message(small, "report.md")
check("a small run's message is built (not None)", msg_small is not None)
if msg_small:
    check("a small run includes all 3 entries (no '...and N more' trailer needed)",
          "...and" not in msg_small, f"got: {msg_small[-200:]!r}")
    check("a small run's message stays well under Telegram's 4096-char limit",
          len(msg_small) < 4096, f"got length={len(msg_small)}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: THE BUG'S EXACT SHAPE -- 54 entries with realistic-length LLM reasoning,
# same as the live report (54 withheld_multi_device outcomes). Enough that the
# character budget, not the 10-entry count cap, is what actually limits inclusion.
# ═══════════════════════════════════════════════════════════════════════════════════
many = [_make_po(i, reason_len=260) for i in range(54)]
msg_many = build_ollama_digest_message(many, "soc_daily_report_20260901.md")
check("a 54-entry run's message is built (not None)", msg_many is not None)
if msg_many:
    check("THE CORE FIX: the message does NOT end mid-sentence -- it ends with the "
          "'...and N more' trailer line (or a complete entry's blank-line terminator), "
          "never a bare truncated fragment",
          msg_many.rstrip().endswith(f"more (see soc_daily_report_20260901.md)")
          or msg_many.rstrip().endswith("</b>")  # the tech-detail header, if nothing else fit
          or msg_many.rstrip().endswith(")"),  # a complete tech-detail line
          f"message ends with: {msg_many[-150:]!r}")
    check("THE CORE FIX: no entry's LLM-reason quote is left unclosed (a truncated "
          "entry would show an odd number of \" characters within any single entry "
          "block -- check the whole message has an EVEN count, since every real quote "
          "opens and closes)",
          msg_many.count('"') % 2 == 0, f"got {msg_many.count(chr(34))} double-quote characters")
    check("fewer than all 54 entries were included, since 54 x ~260-char reasoning "
          "entries cannot fit in one Telegram message -- proving the character budget "
          "(not just the old 10-entry count cap) is the thing actually limiting "
          "inclusion here",
          "...and" in msg_many, f"got tail: {msg_many[-200:]!r}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: REGRESSION GUARD -- never exceeds Telegram's real hard limit, across a
# range of run sizes
# ═══════════════════════════════════════════════════════════════════════════════════
for n in (1, 5, 10, 20, 54, 100):
    po_list = [_make_po(i, reason_len=300) for i in range(n)]
    msg = build_ollama_digest_message(po_list, "report.md")
    check(f"REGRESSION GUARD: a {n}-entry run's message never exceeds Telegram's "
          f"4096-char hard limit",
          msg is None or len(msg) <= 4096, f"got length={len(msg) if msg else 0}")


# ═══════════════════════════════════════════════════════════════════════════════════
# Section E: REGRESSION GUARD -- optional Technical detail section is dropped
# entirely (not truncated) when it wouldn't fit
# ═══════════════════════════════════════════════════════════════════════════════════
huge = [_make_po(i, reason_len=380) for i in range(30)]
msg_huge = build_ollama_digest_message(huge, "report.md")
# Technical detail is appended atomically (the whole "\n".join(tech_lines) block, or
# nothing -- see build_ollama_digest_message's "dropped entirely (never truncated)"
# comment), so if present its last line is always a complete
# "...alerts_covered=<digit>" entry, never a mid-word cutoff.
check("REGRESSION GUARD: when Technical detail wouldn't fit, it's either fully "
      "present or fully absent -- never a partial/cut-off tech-detail section",
      msg_huge is not None and (
          "Technical detail" not in msg_huge
          or msg_huge.rstrip()[-1].isdigit()  # complete "...alerts_covered=N" line
      ),
      f"got tail: {msg_huge[-150:]!r}" if msg_huge else "message was None")

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 48 ollama-digest-truncation checks PASSED.")
