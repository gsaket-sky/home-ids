"""
Standalone runtime test for the "autonomous-action alerts don't explain why" fixes:
1. pipeline.py's "Auto-action: immunized" revoke prompt now surfaces the LightGBM/
   FastEmbed/combined-threshold breakdown, calibrated confidence, originating
   signature/risk/destination, and a hostname+IP identity (never dead-ending on a bare
   "unknown" hostname with no fallback).

v16 NOTE: this file originally also covered (2) scripts/retro_hunter.py's own
_geo_note()/_load_device_display_map()/check_local_intel_history() and (3)
scripts/ollama_soc.py's per-run digest spread-trend logic. Both scripts were retired
in the v16 cleanup -- (2)'s surviving equivalent (argus/retro_hunter.py's RetroHunter,
a direct port) is covered by tests/test_argus_retro_hunter.py; (3)'s withheld-history
multi-device-spread mechanism was never ported to argus/ops/live_llm_review.py, so
there is no surviving code left to test. Only pipeline.py's own _build_geo_note()
coverage (item 1, still live) remains below.

Not part of the pytest suite (no fixtures needed) -- run directly:
`python3 test_phase41_alert_context_enrichment.py`.
"""
import sys
import types
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

# This file's own check names/details deliberately include the same unicode arrows
# (->) the real code under test produces -- on some Windows console codepages
# (cp1252) printing those crashes with UnicodeEncodeError regardless of whether the
# underlying check passed or failed, which would mask a real future failure's
# message. Force UTF-8 stdout/stderr so this test's own diagnostics are always
# printable, independent of whatever console encoding happens to be active.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from core.pipeline import _build_geo_note
from intelligence.geoip import GeoIPEngine

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


ROOT = _PathForSysPath(__file__).resolve().parent.parent
CITY_DB = str(ROOT / "models" / "GeoLite2-City.mmdb")
ASN_DB = str(ROOT / "models" / "GeoLite2-ASN.mmdb")

# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: pipeline.py's _build_geo_note
# ═══════════════════════════════════════════════════════════════════════════════════
check("_build_geo_note() with no engine degrades to empty string, not a crash",
      _build_geo_note(None, "8.8.8.8") == "")
check("_build_geo_note() with a non-IP string degrades to empty string",
      _build_geo_note(None, "example.com") == "")
check("_build_geo_note() with 'unknown' degrades to empty string",
      _build_geo_note(None, "unknown") == "")

class _StubGeoIP:
    """Answers like GeoIPEngine does (lookup_asn()/lookup() objects), so the note's
    formatting is checked on every machine, with or without the licensed mmdb files."""
    def __init__(self, org, country):
        self._org, self._country = org, country

    def lookup_asn(self, ip):
        return types.SimpleNamespace(autonomous_system_organization=self._org) if self._org else None

    def lookup(self, ip):
        return types.SimpleNamespace(country=types.SimpleNamespace(name=self._country)) if self._country else None


check("_build_geo_note() formats org and country as ' _(Org, Country)_'",
      _build_geo_note(_StubGeoIP("Example Org", "Germany"), "203.0.113.7") == " _(Example Org, Germany)_")
check("_build_geo_note() with only an org still returns a note",
      _build_geo_note(_StubGeoIP("Example Org", None), "203.0.113.7") == " _(Example Org)_")
check("_build_geo_note() with neither org nor country degrades to empty string",
      _build_geo_note(_StubGeoIP(None, None), "203.0.113.7") == "")

# The GeoLite2 databases are licensed downloads, not part of the repo; this end-to-end
# check runs wherever they are installed (e.g. the production host) and says so if not.
if _PathForSysPath(CITY_DB).exists() and _PathForSysPath(ASN_DB).exists():
    real_geoip = GeoIPEngine(db_path=CITY_DB, asn_db_path=ASN_DB)
    google_dns_note = _build_geo_note(real_geoip, "8.8.8.8")
    check("_build_geo_note() with a real engine and a well-known public IP (8.8.8.8) "
          "returns a non-empty, correctly-formatted org/country note",
          google_dns_note.startswith(" _(") and google_dns_note.endswith(")_") and "Google" in google_dns_note,
          f"got={google_dns_note!r}")
else:
    print(f"[SKIP] real-GeoIP check: {CITY_DB} / {ASN_DB} not installed")


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 41 alert-context-enrichment checks PASSED.")
