"""
Per-alert state of every optional reputation source (2026-10-14, MASTER_TODO 0c Step 3).

A source that is switched off, has no key, is rate-limited, holds stale feeds or failed its lookup used to write
risk 0.0 -- the same as a clean lookup -- so every reader took "not checked" for "checked, clean". Each source now
reports one of three states for the alert's destination:

    hit          the source lists / scores the destination
    clean        the source answered and does not list it
    not_checked  no answer, with the reason

The risk numbers (`ti_risk`, `abuseipdb_risk`, `vt_risk`) are unchanged; this record sits beside them in the
features (`features["reputation_sources"]`, stored with the alert and its training row).

Reasons split in two: NOT_APPLICABLE (the source is off by choice, or the destination is not something it can look
up -- a private address) and UNAVAILABLE (it should have answered and did not). Only an UNAVAILABLE source makes a
"no hit" less than clean. Pure functions, no I/O.
"""
import ipaddress
from typing import Dict, Iterable, List, Optional, Tuple

HIT, CLEAN, NOT_CHECKED = "hit", "clean", "not_checked"

LABELS = {"threat_intel": "threat-intel lists", "abuseipdb": "AbuseIPDB", "virustotal": "VirusTotal"}

NOT_APPLICABLE = frozenset({"off", "no public address", "no target"})
UNAVAILABLE = frozenset({"paused", "not loaded", "empty", "stale", "rate-limited", "failed", "pending"})


def _entry(state: str, reason: str = "") -> Dict[str, str]:
    return {"state": state, "reason": reason if state == NOT_CHECKED else ""}


def _public(ip: Optional[str]) -> bool:
    try:
        return bool(ip) and ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _combine(parts: Iterable[Tuple[str, str]]) -> Dict[str, str]:
    """One state from several lookups by the same source (address and name): any hit wins; clean only when every
    applicable lookup answered clean; else the first lookup's not-checked reason, an UNAVAILABLE one first."""
    parts = list(parts)
    if any(s == HIT for s, _ in parts):
        return _entry(HIT)
    applicable = [(s, r) for s, r in parts if not (s == NOT_CHECKED and r in NOT_APPLICABLE)]
    if applicable and all(s == CLEAN for s, _ in applicable):
        return _entry(CLEAN)
    missing = [r for s, r in applicable if s != CLEAN] or [r for _, r in parts]
    return _entry(NOT_CHECKED, missing[0] if missing else "no target")


def collect(ti_engine, abuseipdb, virustotal, *, ti_match: bool, dest_ip: Optional[str],
            domain: Optional[str]) -> Dict[str, Dict[str, str]]:
    """The three sources' states for this window's destination address and domain. A source object that is missing
    (None) is "off". The threat-intel state takes `ti_match` from the pipeline's own lookups (they also cover the
    window's other domains); a match counts even from stale lists."""
    if ti_engine is None:
        ti = _entry(NOT_CHECKED, "off")
    elif ti_match:
        ti = _entry(HIT)
    else:
        ok, why = ti_engine.check_status()
        ti = _entry(CLEAN) if ok else _entry(NOT_CHECKED, why)

    if abuseipdb is None or not abuseipdb.active:
        abuse = _entry(NOT_CHECKED, "off")
    elif not _public(dest_ip):
        abuse = _entry(NOT_CHECKED, "no public address")
    else:
        abuse = _combine([abuseipdb.check_status(dest_ip)])

    if virustotal is None or not virustotal.active:
        vt = _entry(NOT_CHECKED, "off")
    else:
        vt = _combine([
            virustotal.check_status("ip", dest_ip) if _public(dest_ip) else (NOT_CHECKED, "no public address"),
            virustotal.check_status("domain", domain) if domain else (NOT_CHECKED, "no target"),
        ])
    return {"threat_intel": ti, "abuseipdb": abuse, "virustotal": vt}


def not_checked(sources: Optional[dict]) -> List[Tuple[str, str]]:
    """(label, reason) for every source that did not answer, in a fixed order."""
    out = []
    for key, label in LABELS.items():
        e = (sources or {}).get(key) or {}
        if e.get("state") == NOT_CHECKED:
            out.append((label, e.get("reason") or "unknown"))
    return out


def unavailable(sources: Optional[dict]) -> List[str]:
    """Keys of the sources that should have answered and did not (a failure, not a choice)."""
    return [k for k, e in (sources or {}).items()
            if (e or {}).get("state") == NOT_CHECKED and (e or {}).get("reason") not in NOT_APPLICABLE]


def verified_clean(sources: Optional[dict]) -> Optional[bool]:
    """True when no source hit, the threat-intel lists answered clean and no switched-on source failed to answer;
    False otherwise. None when the record is missing (a payload written before 2026-10-14): the caller keeps its
    previous rule."""
    if not sources:
        return None
    if any((e or {}).get("state") == HIT for e in sources.values()):
        return False
    if (sources.get("threat_intel") or {}).get("state") != CLEAN:
        return False
    return not unavailable(sources)


def describe_not_checked(sources: Optional[dict]) -> str:
    """One alert-text clause, "" when every source answered: "AbuseIPDB (off), VirusTotal (lookup failed)"."""
    words = {"off": "off", "no public address": "private address", "no target": "nothing to look up",
             "paused": "paused under load", "not loaded": "lists not loaded yet", "empty": "lists empty",
             "stale": "lists out of date", "rate-limited": "rate-limited", "failed": "lookup failed",
             "pending": "answer pending"}
    return ", ".join(f"{label} ({words.get(reason, reason)})" for label, reason in not_checked(sources))
