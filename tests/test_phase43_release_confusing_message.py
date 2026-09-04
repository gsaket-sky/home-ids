"""
Standalone runtime test for Phase 43: the Telegram "Release Device" button/command
gave a confusing "nothing to release" response for an alert that was still "awaiting
approval" (Interactive HITL mode never applies the hardware block until Approve is
tapped, so there is genuinely nothing to undo). User report: "releasing on telegram
does not work as it shows nothing is marked currently" -- the underlying release logic
was correct (the device really was never blocked), only the wording was confusing,
reading like a failed action instead of the reassuring "you're already safe" it should
convey. A second, related bug found in the same function: the text-command path
(/unblock, /release) never checked the IPC response body's released/released_count at
all -- it claimed "Successfully released" on any HTTP 200, even when nothing was
actually under containment (the inline-button callback path already had this fixed).

Not part of the pytest suite -- run directly:
`python3 tests/test_phase43_release_confusing_message.py`.

alerts.py's release handlers make real network calls (Telegram API, local FastAPI IPC)
with no seams for the no-mock convention this codebase uses elsewhere -- covered here
as source-guard checks (matching test_phase32/34's own established pattern for
network-calling code) rather than live invocation.
"""
import sys
from pathlib import Path as _PathForSysPath

# BUGFIX (pre-existing, unrelated to any Phase this session touched -- found while
# running the full suite): this file printed a literal emoji/em-dash without the
# UTF-8 reconfigure guard every other test file in this repo already has, crashing
# with UnicodeEncodeError under a Windows console's default cp1252 codec.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_ALERTS_PATH = _PathForSysPath(__file__).resolve().parent.parent / "src" / "mitigation" / "alerts.py"

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


src = _ALERTS_PATH.read_text(encoding="utf-8")

# NOTE: the raw old wording is deliberately still quoted inside this fix's own BUGFIX
# comment for context (this codebase's established convention -- see any other
# BUGFIX comment in this repo) -- what must actually be gone is the old CODE line that
# assigned it as msg_text, not every mention of the phrase anywhere in the file.
check("the old confusing 'ℹ️ ... nothing to release' msg_text assignment is gone",
      'msg_text = f"ℹ️' not in src)

check("the button-callback release-nothing-to-do case now reads as reassurance "
      "('is not blocked'), not an error",
      "is not blocked — no hardware containment was ever" in src)

check("the button-callback message explicitly reassures the device stays on the network "
      "(split across adjacent string literals -- checked as two separate substrings "
      "since the raw source line-wraps between them)",
      "Nothing further to do; the device stays on the" in src and '"network."' in src)

# The text-command (/unblock, /release) path used to claim success on ANY HTTP 200
# without checking the response body at all -- verify it now reads released/
# released_count before claiming success, same as the button-callback path already did.
command_section_start = src.index('if cmd in ("/unblock", "/release"')
command_section = src[command_section_start:command_section_start + 2500]

check("SOURCE-GUARD: the /release text-command path now reads released_count for 'all'",
      'body.get("released_count", 0)' in command_section)
check("SOURCE-GUARD: the /release text-command path now reads released for a single target",
      'body.get("released", 0)' in command_section)
check("SOURCE-GUARD: the /release text-command path no longer claims success unconditionally "
      "on HTTP 200 alone (the old bug the button-callback path already had fixed)",
      command_section.count('if resp.status_code == 200:') == 0,
      "still found an unconditional 'if resp.status_code == 200:' success claim")
check("the /release text-command path also gives the reassuring not-blocked message "
      "for a single target with nothing to release",
      "is not blocked — no hardware containment was" in command_section)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Phase 43 release-message checks PASSED.")
