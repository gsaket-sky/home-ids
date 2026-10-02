"""
Local IOC index built from the Emerging Threats Open ruleset (BSD-licensed).

Why this exists: the engine's third-party reputation feeds (AbuseIPDB, OTX, VirusTotal, URLhaus,
ThreatFox) are free for personal use only and need per-user keys, so a shipped product cannot
depend on them. ET Open is BSD-licensed, needs no key, and is published for direct download by
every Suricata install. It already contains curated bad-IP lists (DROP/CINS/COMPROMISED/C2 rules),
malicious domain indicators (DNS query and TLS SNI rules) and JA3 fingerprints -- so we read the
ruleset as DATA and never run Suricata for this.

Only ENABLED rules are read (lines starting with '#' are rules ET ships disabled because they are
noisy or obsolete); that is deliberate -- respecting ET's own defaults keeps false positives down.

The result is deliberately shaped like ThreatIntel's own structures (`_bad_ips`, `_bad_cidrs`,
`_bad_domains`: {indicator: {"confidence", "tags", "source", ...}}), so ThreatIntel.ioc_risk_score()
(confidence * 4.0 -> ti_risk) and every threshold built on it keep working unchanged.
"""
from __future__ import annotations

import gzip
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

LOGGER = logging.getLogger("home_ids.local_ioc")

# 2: JA3 hashes are only taken from rules where the hash is the whole condition. A cached v1 index still holds
# hashes of conditional rules (stock Windows TLS fingerprints), so it is rejected and rebuilt.
INDEX_SCHEMA_VERSION = 2

# --- confidence per source category ---------------------------------------------------------
# HOW THIS STEERS THE ENGINE: ThreatIntel turns confidence into ti_risk as confidence * 4.0, and
# fp_engine's Stage-1 hard-stop fires at ti_risk >= 2.0, i.e. confidence >= 0.5 => a single hit can
# CONFIRM a threat on its own. So only indicators that are specific to malware/C2 get >= 0.5.
# Everything that is merely "poor reputation" or "context" stays below 0.5: it still creates
# reputation evidence (weak corroboration, needs a second independent evidence family), but can
# never hard-stop a device by itself. Measured on the real ruleset: ~15k CINS and ~7k Tor entries --
# treating those as hard-stops would flag ordinary scanners' and Tor users' peers en masse.
_IP_CATEGORY_CONFIDENCE = {
    "ET CNC": 0.95,            # Feodo/botcc command-and-control servers: can hard-stop
    "ET COMPROMISED": 0.45,    # known compromised / hostile hosts (mostly SSH brute-forcers)
    "ET DROP": 0.45,           # Spamhaus DROP netblocks (hijacked/criminal): suspicious, not proof
    "ET Threatview.io": 0.45,  # community threat feed
    "ET CINS": 0.35,           # "poor reputation" list: noisy
    "ET TOR": 0.25,            # Tor exit nodes: context only, Tor use is legal
}
_DEFAULT_IP_CONFIDENCE = 0.40

# classtypes that mean "this domain is operated by malware/attackers" vs merely unwanted software
_HIGH_CONFIDENCE_CLASSTYPES = {
    "trojan-activity", "command-and-control", "domain-c2", "exploit-kit", "credential-theft",
    "targeted-activity", "attempted-admin", "successful-admin",
}
_DOMAIN_HIGH_CONFIDENCE = 0.90   # specific malware/C2 domains: same treatment as URLhaus hostfile
_DOMAIN_DEFAULT_CONFIDENCE = 0.40  # adware/PUP/misc: weak evidence only
_JA3_CONFIDENCE = 0.90

_RULE_MSG_RE = re.compile(r'\bmsg:"([^"]*)"')
_RULE_SID_RE = re.compile(r"\bsid:(\d+)")
_RULE_CLASS_RE = re.compile(r"\bclasstype:([a-z0-9_-]+)")
_BRACKET_LIST_RE = re.compile(r"\[([^\]]+)\]")
_JA3_RE = re.compile(r'\bja3(?:_hash|\.hash)\s*;[^;]*?content:"([0-9a-fA-F]{32})"')
# A JA3 hash identifies a TLS client STACK, not a malware family: the same hash is every ordinary client built on
# that library. ET therefore pairs the hash with a second condition whenever the stack is a common one -- e.g.
# sid 2058288 "GootLoader C2 Activity - Windows 11" needs ja3.hash AND tls.sni "barefootinc.com.au"; the hash alone is
# stock Windows 11 (found live 2026-10-01: every Windows 11 TLS connection on a home network was flagged
# "malicious JA3", "matched a known-bad signature directly"). Only rules whose hash IS the whole condition may feed a
# standalone hash blocklist.
_RULE_CONTENT_RE = re.compile(r"\bcontent:")
_RULE_EXTRA_CONDITION_RE = re.compile(
    r"\b(?:tls[._](?:sni|cert\w*)|http[._]\w+|dns[._]query|flowbits:\s*(?:isset|isnotset|noalert))")


def _ja3_rule_is_standalone(line: str) -> bool:
    """True when the rule's only condition is the JA3 hash: exactly one `content`, no SNI/certificate/HTTP/DNS
    buffer, and not gated by flowbits (see the comment above)."""
    opts = line[line.find("("):] if "(" in line else line
    return len(_RULE_CONTENT_RE.findall(opts)) == 1 and not _RULE_EXTRA_CONDITION_RE.search(opts)


# dns.query / dns_query / tls.sni followed (possibly after buffer modifiers) by content:"..."
_DOMAIN_RULE_RE = re.compile(r'\b(?:dns[._]query|tls\.sni)\s*;(?:[^;]*;){0,3}?\s*content:"([^"]+)"')
_HEX_ESCAPE_RE = re.compile(r"\|([0-9A-Fa-f ]+)\|")
_DOMAIN_OK_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$")


@dataclass
class ParsedIOCs:
    """Indicators parsed from a ruleset. `ips`/`domains`/`ja3` map indicator -> meta dict."""
    ips: Dict[str, dict] = field(default_factory=dict)
    cidrs: List[Tuple[str, dict]] = field(default_factory=list)   # (cidr string, meta)
    domains: Dict[str, dict] = field(default_factory=dict)
    ja3: Dict[str, dict] = field(default_factory=dict)
    rules_seen: int = 0
    rules_used: int = 0
    ja3_skipped: int = 0   # JA3 rules not used because the hash is only part of their condition

    def counts(self) -> Dict[str, int]:
        return {"ips": len(self.ips), "cidrs": len(self.cidrs), "domains": len(self.domains),
                "ja3": len(self.ja3), "rules_seen": self.rules_seen, "rules_used": self.rules_used}


def _is_public(net) -> bool:
    """False for anything that must never be treated as a threat indicator: private, loopback,
    link-local, multicast, reserved or unspecified space (a bad list must never flag the LAN)."""
    return not (net.is_private or net.is_loopback or net.is_link_local or net.is_multicast
                or net.is_reserved or net.is_unspecified)


def _category(msg: str) -> str:
    parts = msg.split()
    return " ".join(parts[:2]) if len(parts) >= 2 else msg


def _decode_content(raw: str) -> str:
    """Suricata content with |xx xx| hex escapes -> plain text (invalid escapes -> '')."""
    def _sub(m):
        try:
            return bytes.fromhex(m.group(1).replace(" ", "")).decode("latin-1")
        except ValueError:
            return "\x00"
    return _HEX_ESCAPE_RE.sub(_sub, raw)


def _normalize_domain(raw: str) -> Optional[str]:
    text = _decode_content(raw).strip().lower().lstrip(".")
    if "\x00" in text or "/" in text or " " in text:
        return None
    return text if _DOMAIN_OK_RE.match(text) else None


def _add_ip_items(items: str, meta: dict, out: ParsedIOCs) -> int:
    added = 0
    for item in items.split(","):
        item = item.strip()
        if not item or item.startswith("!") or item.startswith("$"):
            continue
        try:
            if "/" in item:
                net = ipaddress.ip_network(item, strict=False)
                if not _is_public(net):
                    continue
                if net.num_addresses == 1:
                    out.ips.setdefault(str(net.network_address), meta)
                else:
                    out.cidrs.append((str(net), meta))
            else:
                addr = ipaddress.ip_address(item)
                if not _is_public(ipaddress.ip_network(addr)):
                    continue
                out.ips.setdefault(str(addr), meta)
            added += 1
        except ValueError:
            continue
    return added


def parse_et_rules(lines: Iterable[str]) -> ParsedIOCs:
    """Parse ET Open (Suricata) rule lines into indicators. Disabled ('#') rules are skipped."""
    out = ParsedIOCs()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.rules_seen += 1
        msg_m = _RULE_MSG_RE.search(line)
        msg = msg_m.group(1) if msg_m else ""
        sid_m = _RULE_SID_RE.search(line)
        cls_m = _RULE_CLASS_RE.search(line)
        category = _category(msg)
        used = False

        # --- JA3 fingerprints -----------------------------------------------------------
        ja3_m = _JA3_RE.search(line)
        if ja3_m and not _ja3_rule_is_standalone(line):
            out.ja3_skipped += 1
        elif ja3_m:
            out.ja3.setdefault(ja3_m.group(1).lower(), {
                "confidence": _JA3_CONFIDENCE, "tags": ["ja3", "et_open"], "source": "et_open",
                "sid": int(sid_m.group(1)) if sid_m else None, "category": category})
            used = True

        # --- IP lists: rule header has a [a,b,c] list on the src or dst side -------------------
        head = line.split("(", 1)[0]
        if head.startswith("alert ip") or head.startswith("alert tcp") or head.startswith("alert udp"):
            # ET writes reputation lists in both directions ("[hostile hosts] -> $HOME_NET" and
            # "$HOME_NET -> [C2 servers]"); either way the bracketed entries are hostile hosts.
            for m in _BRACKET_LIST_RE.finditer(head):
                conf = _IP_CATEGORY_CONFIDENCE.get(category, _DEFAULT_IP_CONFIDENCE)
                meta = {"confidence": conf, "tags": ["et_open", category.lower().replace(" ", "_")],
                        "source": "et_open", "sid": int(sid_m.group(1)) if sid_m else None,
                        "category": category}
                if _add_ip_items(m.group(1), meta, out):
                    used = True

        # --- domains (DNS query and TLS SNI rules) ---------------------------------------
        dom_m = _DOMAIN_RULE_RE.search(line)
        if dom_m:
            domain = _normalize_domain(dom_m.group(1))
            if domain:
                classtype = cls_m.group(1) if cls_m else ""
                conf = _DOMAIN_HIGH_CONFIDENCE if classtype in _HIGH_CONFIDENCE_CLASSTYPES else _DOMAIN_DEFAULT_CONFIDENCE
                if category == "ET RETIRED":
                    # Retired signatures are old; their domains may have been re-registered since.
                    conf = _DOMAIN_DEFAULT_CONFIDENCE
                existing = out.domains.get(domain)
                if existing is None or conf > existing["confidence"]:
                    out.domains[domain] = {
                        "confidence": conf, "tags": ["et_open", classtype or "unclassified"],
                        "source": "et_open", "sid": int(sid_m.group(1)) if sid_m else None,
                        "category": category}
                used = True

        if used:
            out.rules_used += 1
    return out


# --- persistence (atomic, compact) ------------------------------------------------------------

def save_index(parsed: ParsedIOCs, path: Path, *, source_version: str = "", fetched_at: Optional[float] = None) -> None:
    """Write the index atomically (temp file + rename) so a crash never leaves a half-written file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": INDEX_SCHEMA_VERSION,
        "source": "et_open",
        "source_version": source_version,
        "fetched_at": fetched_at if fetched_at is not None else time.time(),
        "counts": parsed.counts(),
        "ips": parsed.ips,
        "cidrs": parsed.cidrs,
        "domains": parsed.domains,
        "ja3": parsed.ja3,
    }
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", compresslevel=6) as gz:
            gz.write(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_index(path: Path) -> Optional[Tuple[ParsedIOCs, dict]]:
    """Return (parsed, metadata) or None if the file is missing/corrupt/incompatible."""
    path = Path(path)
    try:
        with gzip.open(path, "rb") as f:
            payload = json.loads(f.read().decode("utf-8"))
        if payload.get("schema") != INDEX_SCHEMA_VERSION:
            return None
        parsed = ParsedIOCs(
            ips=payload["ips"], cidrs=[(c, m) for c, m in payload["cidrs"]],
            domains=payload["domains"], ja3=payload["ja3"],
            rules_seen=payload["counts"].get("rules_seen", 0), rules_used=payload["counts"].get("rules_used", 0))
        meta = {k: payload.get(k) for k in ("source", "source_version", "fetched_at", "counts")}
        return parsed, meta
    except (OSError, ValueError, KeyError, EOFError, gzip.BadGzipFile):
        return None
