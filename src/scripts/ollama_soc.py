import os
import sys
import json
import time
import hashlib
import logging
import requests
import ipaddress
import urllib.request
import yaml
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

# Ensures the script can resolve modules from the src directory
sys.path.append(str(Path(__file__).resolve().parent.parent))


_TELEGRAM_MSG_BUDGET = 3800  # headroom under Telegram's 4096-char hard limit


def build_ollama_digest_message(pattern_outcomes: list, report_filename: str) -> "str | None":
    """Builds the Telegram digest text for one ollama_soc.py run, or None if there's
    nothing to report (empty pattern_outcomes). Extracted into its own function (was
    inline in main()) specifically so this can be unit tested directly -- see
    tests/test_phase48_ollama_digest_truncation.py.

    BUGFIX (live report, 2026-09-01): previously capped detail entries by COUNT alone
    (10 entries), then hard-sliced the finished message to [:4000] chars -- but 10
    entries' worth of full LLM reasoning text routinely exceeds 4000 characters on its
    own (live report: a 54-withheld-entry run was cut off mid-sentence, mid-entry,
    inside entry #7 of the 10-entry budget), so the count cap never actually prevented
    the character-level slice from firing, and that slice cut wherever it landed with
    zero regard for entry/sentence boundaries. Now builds each entry as a complete,
    whole block and stops adding NEW entries once the running total approaches
    Telegram's real 4096-char limit -- every entry that makes it into the message is
    complete, never truncated mid-sentence; entries that don't fit are folded into the
    "...and N more" counter instead of being cut off."""
    if not pattern_outcomes:
        return None

    _OUTCOME_LABELS = {
        "immunized": "🛡️ immunized as false positive (sensitivity loosened)",
        "confirmed_threat": "🚨 confirmed malicious (sensitivity tightened)",
        "withheld_multi_device": "⏸️ withheld (spreading across multiple devices, re-checking next run)",
        "skipped": "⚠️ skipped (could not safely apply the action)",
        "already_actioned": "✅ already actioned / no new action needed",
        "no_action_needed": "✅ already actioned / no new action needed",
        "deferred_query_cap": "⏳ deferred (per-run query cap reached, retrying next run)",
    }
    by_outcome = defaultdict(list)
    for po in pattern_outcomes:
        by_outcome[po["outcome"]].append(po)

    digest_lines = [f"🤖 <b>Ollama SOC run: {len(pattern_outcomes)} pattern(s) analyzed</b>", ""]

    # Summary counts, in a fixed order (interesting outcomes first).
    summary_order = ["immunized", "confirmed_threat", "withheld_multi_device", "skipped",
                      "deferred_query_cap"]
    quiet_count = len(by_outcome.get("already_actioned", [])) + len(by_outcome.get("no_action_needed", []))
    for oc in summary_order:
        if by_outcome.get(oc):
            digest_lines.append(f"{_OUTCOME_LABELS[oc]}: {len(by_outcome[oc])}")
    if quiet_count:
        digest_lines.append(f"✅ {quiet_count} already actioned / no new action needed (see report for the full list)")
    digest_lines.append("")

    # Per-pattern detail for the outcomes worth a human's attention -- see this
    # function's own docstring for why this is character-budgeted, not just count-capped.
    detail_budget = 10
    detail_worthy = [
        po
        for oc in ("immunized", "confirmed_threat", "withheld_multi_device", "skipped")
        for po in by_outcome.get(oc, [])
    ][:detail_budget]

    included = 0
    tech_lines = ["", "🔧 <b>Technical detail (optional)</b>"]
    running_len = len("\n".join(digest_lines))
    for po in detail_worthy:
        device_label = po["hostname"] if po["hostname"] and po["hostname"] != "unknown" else po["device_ip"]
        entry_lines = [f"• <code>{device_label}</code> → {po['target']}{po['target_asn_note']} ({po['signature']})"]
        if po["llm_reason"]:
            conf_str = f"{po['llm_confidence']:.2f}" if isinstance(po.get("llm_confidence"), (int, float)) else "n/a"
            entry_lines.append(f"  LLM (confidence {conf_str}): \"{po['llm_reason']}\"")
        if po["outcome_detail"]:
            entry_lines.append(f"  → {po['outcome_detail']}")
        entry_lines.append("")
        entry_text = "\n".join(entry_lines)
        if running_len + len(entry_text) > _TELEGRAM_MSG_BUDGET:
            break
        digest_lines.extend(entry_lines)
        running_len += len(entry_text) + 1
        included += 1
        tech_lines.append(
            f"• {device_label} [{po['cache_key']}]: classification={po.get('classification')}, "
            f"confidence={po.get('llm_confidence')}, alerts_covered={po['alerts_covered']}"
        )

    total_detail_worthy = sum(
        len(by_outcome.get(oc, [])) for oc in ("immunized", "confirmed_threat", "withheld_multi_device", "skipped")
    )
    remaining = total_detail_worthy - included
    if remaining > 0:
        digest_lines.append(f"...and {remaining} more (see {report_filename})")

    full_msg = "\n".join(digest_lines)
    # Technical detail is explicitly labeled optional -- only appended if it fits
    # without pushing past budget; dropped entirely (never truncated) otherwise.
    if len(tech_lines) > 2:
        tech_text = "\n".join(tech_lines)
        if len(full_msg) + len(tech_text) <= _TELEGRAM_MSG_BUDGET + 200:
            full_msg += tech_text

    return full_msg[:4096]


def _send_telegram(config: dict, msg: str) -> None:
    """Mirrors retro_hunter.py's own _send_telegram() -- same reasoning: a validated
    finding deserves the same real-time channel every other finding in this codebase
    gets, not just a line in a Markdown report nobody has a reason to open. This script
    reads config via its own flat load_config() (not the config.py CONFIG singleton
    retro_hunter.py uses), so config is passed in rather than imported."""
    token = config.get("telegram_token", "")
    chat_id = config.get("telegram_chat_id", "")
    if not token or not chat_id:
        return
    try:
        data = json.dumps({"chat_id": chat_id, "text": msg, "parse_mode": "HTML"}).encode("utf-8")
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data,
            headers={"Content-Type": "application/json"}, method="POST",
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        LOGGER.error(f"Failed to send Telegram ollama_soc alert: {e}")


def _geo_note(geoip_engine, ip: str) -> str:
    """Returns ' (Org, Country)' for a raw IP via local mmdb lookups, or '' if
    unavailable/not an IP. Same small helper as retro_hunter.py's own copy -- kept
    local rather than shared, matching this script's existing self-contained style."""
    if not ip or ip == "unknown" or not geoip_engine:
        return ""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return ""
    try:
        asn_res = geoip_engine.lookup_asn(ip)
        city_res = geoip_engine.lookup(ip)
        geo_org = getattr(asn_res, "autonomous_system_organization", None) if asn_res else None
        geo_country = getattr(getattr(city_res, "country", None), "name", None) if city_res else None
        geo_parts = [p for p in (geo_org, geo_country) if p]
        return f" ({', '.join(geo_parts)})" if geo_parts else ""
    except Exception:
        return ""


def _flatten_config_categories(raw: dict) -> dict:
    """Mirror config.py's LiveConfig._load() flattening rule: merge every top-level
    mapping whose name doesn't start with "_"/"#" into one flat key->value namespace.
    Category names in config.yaml are purely organizational -- this script reads the
    same flat keys regardless of which category they're grouped under."""
    flattened = {}
    for section_name, section_val in (raw or {}).items():
        if str(section_name).startswith("_") or str(section_name).startswith("#"):
            continue
        if isinstance(section_val, dict):
            flattened.update(section_val)
        else:
            flattened[section_name] = section_val
    return flattened


def load_config():
    """Returns the FLAT config namespace (already merged across every category).

    BUGFIX (2026-09-01, live report: "ollama should also send telegram message, i am
    not getting it"): config.yaml's own telegram: section comment says "token/chat ID
    come from .env" -- true for the main pipeline process, which goes through
    config.py's LiveConfig.__init__() (load_env_file() + apply_env_overrides()) and
    therefore has telegram_token/telegram_chat_id available. This script deliberately
    reads config.yaml directly instead of importing the full config.py CONFIG
    singleton (see _send_telegram()'s own docstring: "so this standalone daemon
    doesn't need to boot the full engine") -- but that also meant it never loaded
    .env at all. _send_telegram() has always silently no-op'd (`if not token or not
    chat_id: return`, no log line) on every single run as a result -- the digest was
    dead code from day one, not an intermittent failure. Reuses config.py's own
    load_env_file()/apply_env_overrides() (same env-var mapping table, not a
    duplicated copy that could drift) rather than re-deriving the .env path/parsing
    logic here.
    """
    config_path = Path(__file__).resolve().parent.parent.parent / "config.yaml"
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        flat = _flatten_config_categories(raw)
        try:
            from config import load_env_file, apply_env_overrides
            env_path = config_path.parent / flat.get("env_file", ".env")
            load_env_file(env_path)
            apply_env_overrides(flat)
        except Exception as e:
            LOGGER.error(f"Failed to load .env overrides (Telegram/API keys will be "
                         f"unavailable this run): {e}")
        return flat
    except Exception as e:
        LOGGER.error(f"Failed to load config: {e}")
        return {}
from intelligence.ai_soc import DeterministicValidator, VALIDATOR_SCHEMA_VERSION
from intelligence.hypotheses.evidence import Evidence
from intelligence.fp_engine import AutonomousFPEngine
from intelligence.geoip import GeoIPEngine
from mitigation.ips import IPSMitigator
from core.state_guard import StateManager
from utils import write_job_health

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [OLLAMA-SOC] %(message)s")
LOGGER = logging.getLogger("ollama_soc")

# PHASE 11 FIX: a live diagnostic run on the actual server showed a single trivial
# "say hello" /api/generate call taking 849s total_duration while the model's own
# reported load+eval durations summed to only ~13s — ~836s of that was pure CPU-
# contention queueing (the server was observed at 300%+ CPU). With no dedup, this
# script was calling Ollama once per alert in the last 24h — and a single noisy
# threat pattern (confirmed in a live alerts.json: one device/destination pair firing
# 54 times in 11 hours) meant one recurring pattern alone could cost 50+ multi-minute
# calls in a single run. That's the real reason no soc_daily_report has ever had
# content: any run either took far longer than the 4h gap to its next scheduled
# invocation, or individual calls timed out against the 900s request timeout. Per
# explicit direction: "use ollama sparingly and only when absolutely needed", "save
# every redundant call to it with no repeat query on same threat". The fix has three
# parts, all below: (1) group alerts by device+target+signature and query ONCE per
# group, not once per alert — collapses the 54-alert case to 1 call; (2) persist
# verdicts to a cache file with a TTL so the SAME pattern recurring across separate
# scheduled runs (every 4h) doesn't re-query either; (3) a hard cap on fresh queries
# per run so one unusually noisy day can't turn into an hours-long run regardless.
DEFAULT_CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days -- matches this codebase's other
                                            # weekly cadence (fp_engine's own retrain loop)
DEFAULT_MAX_QUERIES_PER_RUN = 5             # 5 x up to ~15min worst-case (900s request
                                            # timeout) = 75min worst case, well inside the
                                            # 4h gap between scheduled runs

# Found via a live-data audit: a DGA-shaped domain pattern (identical prefix, rotating
# numeric suffix -- e.g. "xkqz289dfj10dj-NNN.ru") fired the same signature on 9 different
# devices over 47 hours. Ollama analyzes one device+target+signature group at a time with
# no visibility into what's happening on other devices, so it confidently (1.0 confidence)
# classified two instances on the device seeing it MOST as benign/suppress -- while a
# different device's instance of the identical pattern was classified malicious/block in
# the same run. A per-alert LLM call structurally cannot see a cross-device campaign; only
# the batch driver (this script) has that visibility, since it already reads every alert
# in the window. If the same signature is independently firing on this many *distinct*
# devices right now, that is exactly the situation that deserves a human look, not a
# same-day autonomous immunization -- so auto-suppress is withheld (not skipped outright:
# it's still logged, still reported) and the pattern falls through to the next run
# unactioned, where it'll be reconsidered against then-current device spread.
DEFAULT_MULTI_DEVICE_SUPPRESS_GUARD = 3

# BUGFIX (2026-09-01, live report: "is Ollama ever completing all the alerts or is it
# just piling up"): the guard above has no exit condition at all -- a pattern that
# withholds once withholds forever, re-checked every run against then-current spread,
# with nothing that ever lets it resolve on its own. On this deployment that's not
# hypothetical: a live audit of state/ollama_analysis_cache.json found 165 distinct
# patterns sitting in withheld_history, some withheld 15-18 times over 4.6 days
# straight, 100% NETWORK_INTRUSION (this network's single most common signature, so
# spread>=3 is essentially always true for it) and 100% still classified benign at
# high confidence (0.8-1.0) every single time. Device-count STABILITY turned out not to
# be the right signal to auto-resolve on (spot-checked live: most stuck patterns still
# show device-count churn between checks -- normal background noise as different
# devices intermittently trip the same common alert, not a genuinely growing incident)
# -- what actually IS the right signal is the model independently re-reaching the exact
# SAME verdict (benign, validator-passed) this many times in a row, since a genuinely
# active/evolving campaign (the DGA case above) would be expected to show new evidence
# or a verdict flip well within this many cron cycles, not a perfectly static repeat.
# Once a pattern's OWN streak (this device+target+signature key specifically, not the
# cross-device spread count) reaches this length, it falls through to the normal
# immunize path instead of withholding again -- logged distinctly as an
# auto-resolved-after-streak action, not silently folded into the immediate-immunize
# case. A verdict flip (malicious, or the validator rejecting it) never increments this
# streak, so this only ever fires for a genuinely stable, repeatedly-reconfirmed benign
# pattern -- it does not weaken the guard's original cross-device contradiction check
# (a malicious verdict on any one device still never reaches the withhold branch at
# all, immediately going to confirmed_threat instead).
DEFAULT_MULTI_DEVICE_WITHHOLD_AUTO_RESOLVE_AFTER = 10


def should_still_withhold(spread: int, multi_device_suppress_guard: int,
                           existing_withheld_count: int, multi_device_withhold_auto_resolve_after: int,
                           campaign_corroborated: bool = True) -> bool:
    """Pure decision function, extracted specifically so it's unit-testable without
    mocking Ollama/fp_engine/state -- see tests/test_phase49_ollama_withhold_streak.py.
    True iff the multi-device spread guard is currently satisfied (spread >= threshold)
    AND this exact pattern hasn't yet independently reconfirmed the identical
    benign/validator-passed verdict multi_device_withhold_auto_resolve_after times in a
    row. Once the streak is exhausted, a pattern falls through to the normal immunize
    branch in main() instead of withholding again -- see
    DEFAULT_MULTI_DEVICE_WITHHOLD_AUTO_RESOLVE_AFTER's own comment for the full incident
    this closes (165 patterns stuck in withheld_history, some 15-18 times over 4.6 days,
    with no exit condition at all before this).

    PHASE 53 (campaign correlation): `campaign_corroborated` (optional, default True --
    every pre-Phase-53 caller/test is unaffected) is _is_campaign_corroborated()'s own
    verdict on whether this signature's cross-device spread actually LOOKS like a
    coordinated campaign (destinations concentrated on shared/unexplained infra) versus
    devices independently reaching different, individually reputable infrastructure
    under a merely-common signature name -- the "3 smart-TVs hitting 3 different CDN
    edges" case. Device COUNT alone (spread) answers "how many devices," not "are they
    actually part of the same incident" -- this is the second, independent question the
    original guard conflated into one. Defaults True (the pre-Phase-53, err-toward-
    caution behavior) so a caller that hasn't computed it yet still withholds exactly as
    before."""
    return (spread >= multi_device_suppress_guard and campaign_corroborated
            and existing_withheld_count < multi_device_withhold_auto_resolve_after)


def _is_campaign_corroborated(members: list, geoip_engine) -> bool:
    """PHASE 53 (campaign correlation): True if this signature's spread across devices
    looks like it could genuinely be ONE coordinated incident -- destinations
    concentrated on a small/shared set of IPs, or destinations that aren't recognized
    reputable cloud/CDN infrastructure (unexplained, so treated with the same caution
    the guard has always used). False ONLY when there are multiple genuinely DISTINCT
    destination IPs and EVERY one of them resolves to a recognized cloud/CDN provider --
    the concrete "3 smart-TVs independently hitting 3 different CDN edges" shape a
    generic/noisy signature produces, not a real campaign. Deliberately conservative:
    any lookup failure, missing GeoIP engine, or destination that doesn't resolve to a
    recognized provider keeps the result True (unchanged, err-toward-caution behavior)
    -- this function can only ever RELAX the guard, never tighten it beyond what spread
    alone already required, since should_still_withhold() ANDs it with the existing
    spread check rather than replacing it."""
    distinct_ips = {
        ip for p in members
        if (ip := (p.get("network_context", {}) or {}).get("destination_ip")) not in (None, "", "unknown")
    }
    if len(distinct_ips) <= 1:
        return True  # concentrated on one destination (or nothing to disambiguate)
    if not geoip_engine:
        return True  # can't classify -- conservative default

    try:
        from utils import is_cloud_cdn_provider_org
    except Exception:
        return True

    classified = 0
    reputable = 0
    for ip in distinct_ips:
        try:
            asn_res = geoip_engine.lookup_asn(ip)
            owner = getattr(asn_res, "autonomous_system_organization", None) if asn_res else None
        except Exception:
            owner = None
        if not owner:
            continue
        classified += 1
        if is_cloud_cdn_provider_org(owner):
            reputable += 1

    if classified == 0:
        return True  # nothing resolvable -- conservative default
    # "Scattered across reputable infra" requires EVERY resolvable destination to be
    # reputable -- a single unexplained/unclassified destination among several keeps
    # the conservative True (still corroborated, still withheld).
    all_reputable = reputable == classified == len(distinct_ips)
    return not all_reputable


# VERSION 10 (incident aggregation): this grouping-key logic used to live only here,
# duplicated nowhere else -- pipeline.py's own real-time Telegram-volume gate
# (core/incident_tracker.py) needed the identical "same ongoing incident" concept, so
# both now import the single shared definition from incident_key.py instead of drifting
# independently. Kept as thin wrappers under their original names so nothing else in
# this file needs to change.
from incident_key import target_for_key as _target_for_key_raw, incident_key as _incident_key


def _target_for_key(payload: dict) -> str:
    nc = payload.get("network_context", {}) or {}
    return _target_for_key_raw(nc.get("destination_ip"), nc.get("queried_domain"))


def _cache_key(payload: dict) -> str:
    """Canonical 'same threat' identity: same device, same target, same signature
    (persistence-escalation suffix stripped -- see incident_key.signature_base -- so an
    incident that escalates mid-episode, e.g. "DNS_EVASION" -> "DNS_EVASION (persisted
    603s)", still collapses to the same cache key instead of fragmenting into two).
    Deliberately stays this coarse -- used for THIS RUN's in-memory grouping
    (`groups[...]`), where the whole point is that repeat firings of the identical
    pattern collapse into one Ollama call regardless of minor feature fluctuation. NOT
    used directly against the persistent on-disk cache anymore -- see
    _persistent_cache_key() below."""
    device_id = payload.get("device", {}).get("id", "unknown")
    signature = payload.get("signature", "unknown")
    return _incident_key(device_id, payload.get("network_context", {}).get("destination_ip"),
                          payload.get("network_context", {}).get("queried_domain"), signature)


# PHASE 57 (evidence fingerprint): raw feature keys that actually feed a Hypothesis's
# required/strong/contradicting checks somewhere in hypotheses/engine.py (arp_sweep/
# lateral-scan/TLS-fingerprint/notice/honeypot-shaped signals) or a validator IOC check
# (ti/abuse/vt risk) -- a change in any of these means the underlying EVIDENCE changed,
# not just noise, even if the pattern's device/target/signature name (_cache_key) stayed
# the same. Deliberately excludes fast-fluctuating, non-evidence-bearing fields (exact
# query rate, unique-domain count, timestamps) so the persistent cache doesn't
# invalidate on every run's minor variance.
_FINGERPRINT_PRESENCE_KEYS = (
    "zeek_lateral_moves", "zeek_honeypot_hits", "zeek_arp_spoof", "zeek_notice_count",
    "malicious_ja3", "malicious_ja4", "zeek_conn_abuse", "zeek_long_conn",
    "zeek_exfiltration", "zeek_beaconing", "dns_tunnel_score", "dns_dga_score",
)
_FINGERPRINT_BUCKETED_KEYS = (
    "ti_risk", "abuseipdb_risk", "vt_risk", "entropy_avg", "nxdomain_ratio", "blocked_ratio",
)


def _evidence_fingerprint(payload: dict) -> str:
    """PHASE 57: content hash of the evidence-bearing features, distinct from
    _cache_key()'s coarse device|target|signature grouping. Two alerts with the SAME
    _cache_key() but a genuinely different fingerprint (e.g. arp_sweep newly appearing
    on an already-cached NETWORK_INTRUSION pattern) get different persistent cache
    entries -- see _persistent_cache_key(). Presence-only (any nonzero value) for
    attack-shaped signals, since a fresh hit mattering is a yes/no fact, not a magnitude;
    rounded to 1 decimal place for continuous signals that matter to hypothesis scoring
    but shouldn't invalidate the cache on every minor fluctuation."""
    features = payload.get("features", {}) or {}
    presence = sorted(k for k in _FINGERPRINT_PRESENCE_KEYS if _safe_feature_float(features.get(k)) > 0)
    bucketed = {k: round(_safe_feature_float(features.get(k)), 1) for k in _FINGERPRINT_BUCKETED_KEYS}
    raw = json.dumps({"presence": presence, "bucketed": bucketed}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _safe_feature_float(val) -> float:
    try:
        return float(val) if val is not None else 0.0
    except (TypeError, ValueError):
        return 0.0


def _persistent_cache_key(payload: dict) -> str:
    """PHASE 57: the key actually used for the persistent on-disk `cache` dict
    (read/write) -- _cache_key() alone stays reserved for in-run grouping (see its own
    docstring). Folds in the evidence fingerprint (so a genuine evidence change
    invalidates a stale verdict even under an unchanged pattern name) and
    VALIDATOR_SCHEMA_VERSION (so upgrading DeterministicValidator.validate()'s logic
    makes every previously-cached verdict unreachable by lookup immediately, rather than
    silently trusting a `validator_passed` boolean computed under superseded rules for
    up to DEFAULT_CACHE_TTL_SECONDS, or indefinitely for a pattern kept alive via
    withheld_history -- see Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 6 root
    cause, the live bug this exists to close. An orphaned old-version/old-fingerprint
    entry is simply never looked up again and ages out of the cache file via the
    existing TTL prune in _load_cache() like any other unused entry -- no separate
    migration/invalidation pass needed."""
    return f"{_cache_key(payload)}|{_evidence_fingerprint(payload)}|v{VALIDATOR_SCHEMA_VERSION}"


# VERSION 10 (#15/#16, Ollama circular-reasoning guard): every field below encodes a
# PRIOR VERDICT this system already computed about the alert, not a raw observation --
# confirmed via a third-party review of production ollama_transparency records that the
# old prompt handed the model the whole raw alert_payload undiscriminated, including
# "risk": 9.9 and "signature": "Confirmed Malicious IOC" sitting right next to genuinely
# raw evidence. That let the model simply reflect the existing verdict back as
# "confirmation" ("risk=9.9 therefore malicious") instead of independently reasoning
# from device/network_context/features -- exactly the failure mode DeterministicValidator
# (ai_soc.py) now also has a defense-in-depth check for.
_VERDICT_SHAPED_FIELDS = frozenset({
    "risk", "signature", "factors", "fp_verdict", "hypothesis_weight",
    "evidence_verification_required", "reasoning_trail",
    # PHASE 50: this system's own prior attack-vs-benign hypothesis competition for this
    # exact alert (pipeline.py, decision_engine.py) -- a verdict/taxonomy decision, not a
    # raw observation, same reasoning as every other field in this set. Used below to
    # ground-truth-check the LLM's response AFTER it's generated, never shown beforehand.
    "hee_hypotheses", "hee_independent_sources", "hee_decision_path", "hee_evidence_families",
})


def _build_evidence_only_payload(representative: dict) -> dict:
    """Strips every verdict-shaped field (see _VERDICT_SHAPED_FIELDS above) before the
    alert reaches the LLM prompt. Everything left -- device, network_context, features,
    timestamp, schema, incident_id -- is a genuine raw observation, INCLUDING features
    like ti_risk/abuse_risk/vt_risk: those are input signals for the model to weigh
    itself, not this system's own already-computed verdict, so they deliberately stay."""
    return {k: v for k, v in representative.items() if k not in _VERDICT_SHAPED_FIELDS}


def _load_cache(cache_path: Path, ttl_seconds: float) -> dict:
    if not cache_path.exists():
        return {}
    try:
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
    except Exception as e:
        LOGGER.warning(f"Could not read ollama analysis cache ({e}) -- starting fresh.")
        return {}
    now = time.time()
    fresh = {k: v for k, v in raw.items() if isinstance(v, dict) and (now - float(v.get("ts", 0.0))) < ttl_seconds}
    pruned = len(raw) - len(fresh)
    if pruned:
        LOGGER.info(f"Pruned {pruned} expired entries from ollama analysis cache.")
    return fresh


def _save_cache(cache_path: Path, cache: dict) -> None:
    try:
        cache_path.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception as e:
        LOGGER.error(f"Failed to save ollama analysis cache: {e}")


def _write_ollama_relay_stats(state_dir: Path, calls_made: int, cache_hits: int, deferred: int, run_validated: dict) -> None:
    """Writes state/ollama_run_stats.json -- synced into Prometheus gauges by the
    long-running pipeline process's sync_relay_metrics() (this script is a separate
    cron process with no HTTP server of its own). validated_totals is cumulative across
    runs, not just this one, so it's read-modify-write against the existing file."""
    path = state_dir / "ollama_run_stats.json"
    try:
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        existing = {}
    validated_totals = existing.get("validated_totals", {})
    for verdict, count in run_validated.items():
        validated_totals[verdict] = validated_totals.get(verdict, 0) + count
    stats = {
        "last_run": time.time(),
        "calls_made": calls_made,
        "cache_hits": cache_hits,
        "deferred": deferred,
        "validated_totals": validated_totals,
    }
    try:
        path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    except Exception as e:
        LOGGER.debug(f"Failed to write ollama_run_stats.json: {e}")


def _query_ollama(ollama_url: str, ollama_model: str, prompt_text: str, system_prompt: str) -> dict:
    """Single /api/generate call. Returns the parsed response JSON, or None on any
    failure (HTTP error, timeout, malformed JSON) -- caller decides how to log/handle."""
    resp = requests.post(
        f"{ollama_url}/api/generate",
        json={
            "model": ollama_model,
            "system": system_prompt,
            "prompt": prompt_text,
            "format": "json",
            "stream": False
        },
        timeout=900.0
    )
    if resp.status_code != 200:
        LOGGER.error(f"Ollama returned HTTP {resp.status_code}")
        return None
    response_text = resp.json().get("response", "").strip()
    try:
        return json.loads(response_text)
    except json.JSONDecodeError:
        LOGGER.error(f"Failed to parse Ollama JSON: {response_text}")
        return None


def main():
    LOGGER.info("Starting Daily Ollama SOC Batch Analysis...")
    run_start = time.time()

    root_dir = Path(__file__).resolve().parent.parent.parent

    config = load_config()  # already flat -- merged across every config.yaml category

    ollama_url = config.get("ollama_url", "http://127.0.0.1:11434").rstrip("/")
    ollama_model = config.get("ollama_model", "llama3.1")
    cache_ttl_seconds = float(config.get("ollama_cache_ttl_seconds", DEFAULT_CACHE_TTL_SECONDS))
    max_queries_per_run = int(config.get("ollama_max_queries_per_run", DEFAULT_MAX_QUERIES_PER_RUN))

    alerts_path = root_dir / config.get("alert_json_path", "state/alerts.json")
    if not alerts_path.exists():
        alerts_path = root_dir / "alerts.json"

    if not alerts_path.exists():
        LOGGER.error(f"Alerts file not found at {alerts_path}")
        return

    # 1. Parse last 24 hours of alerts
    yesterday = time.time() - (24 * 3600)
    alerts_to_analyze = []

    try:
        with open(alerts_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): continue
                try:
                    payload = json.loads(line)
                    # PHASE 9 FIX: this file is also where THIS SCRIPT appends its own
                    # "ollama_transparency" entries a few dozen lines down. Without a type
                    # filter, tomorrow's run would read today's transparency logs back in as
                    # if they were fresh alerts and re-query the LLM about them.
                    if payload.get("type") != "ids_alert":
                        continue
                    # PHASE 11 FIX: fp_engine already runs a fast, cheap 3-stage check on
                    # EVERY alert before it's published; entries with suppressed=True were
                    # already confidently resolved as false positives by that pipeline. Ollama
                    # is the expensive, scarce resource here -- spend it only on alerts that
                    # actually needed a human/LLM judgment call because CL-AFPE didn't
                    # resolve them with confidence, not on ones already closed out.
                    if payload.get("suppressed"):
                        continue
                    if payload.get("timestamp", 0) > yesterday:
                        alerts_to_analyze.append(payload)
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        LOGGER.error(f"Failed to read alerts.json: {e}")
        return

    if not alerts_to_analyze:
        LOGGER.info("No recent (published, non-suppressed) alerts found for analysis.")
        state_dir = root_dir / "state"
        _write_ollama_relay_stats(state_dir, calls_made=0, cache_hits=0, deferred=0, run_validated={})
        write_job_health(state_dir, "ollama_soc", time.time() - run_start)
        return

    # 2. Group into "same threat" buckets -- one Ollama call per bucket, not per alert.
    groups: dict = defaultdict(list)
    for payload in alerts_to_analyze:
        groups[_cache_key(payload)].append(payload)
    # Largest/noisiest patterns first, so if the per-run cap is hit, the highest-impact
    # patterns are the ones that actually got analyzed this run.
    ordered_keys = sorted(groups.keys(), key=lambda k: len(groups[k]), reverse=True)

    # Multi-device spread guard (see DEFAULT_MULTI_DEVICE_SUPPRESS_GUARD above): same
    # signature -> the set of distinct device IDs that fired it anywhere in this run's
    # window, independent of the exact target domain string (a rotating-suffix DGA domain
    # never repeats exactly, so this must key on signature alone, not on _cache_key()).
    signature_device_counts: dict = defaultdict(set)
    # PHASE 53 (campaign correlation): every alert payload sharing a signature, not just
    # its device -- _is_campaign_corroborated() below needs the actual destination_ips
    # to tell "many devices independently hitting the SAME/few infra" (a real
    # coordinated campaign) apart from "many devices hitting MANY DIFFERENT, individually
    # reputable destinations" (a noisy generic signature, not a campaign) -- device COUNT
    # alone can't distinguish these two shapes, which is exactly what this phase adds.
    signature_members: dict = defaultdict(list)
    for payload in alerts_to_analyze:
        sig = payload.get("signature", "unknown")
        dev = payload.get("device", {}).get("id", "unknown")
        if dev and dev != "unknown":
            signature_device_counts[sig].add(dev)
        signature_members[sig].append(payload)
    multi_device_suppress_guard = int(config.get("ollama_multi_device_suppress_guard", DEFAULT_MULTI_DEVICE_SUPPRESS_GUARD))
    multi_device_withhold_auto_resolve_after = int(config.get(
        "ollama_multi_device_withhold_auto_resolve_after", DEFAULT_MULTI_DEVICE_WITHHOLD_AUTO_RESOLVE_AFTER
    ))

    # BUGFIX (live alert audit): device_id -> display name (hostname, or IP if hostname
    # unknown -- never a bare device_id, meaningless to a human at a glance). Built once
    # per run from this run's own alert payloads (already in hand, no extra I/O) rather
    # than a fresh state load -- used both for per-pattern display and for the withheld-
    # pattern spread-history trend (which devices joined a spreading pattern since last
    # run, not just how many).
    dev_display_map = {}
    for p in alerts_to_analyze:
        d = p.get("device", {}) or {}
        if d.get("id"):
            dev_display_map[d["id"]] = d["hostname"] if d.get("hostname") not in (None, "unknown") else d.get("ip", d["id"])

    geoip_engine = GeoIPEngine(
        db_path=config.get("geoip_db", str(root_dir / "models" / "GeoLite2-City.mmdb")),
        asn_db_path=config.get("geoip_asn_db", ""),
    )

    # PHASE 53 (campaign correlation): computed once per DISTINCT signature (not per
    # cache_key/target -- several targets can share one signature) and reused across the
    # run, since _is_campaign_corroborated() does real GeoIP ASN lookups per distinct
    # destination IP -- no reason to repeat that work for every target sharing the
    # signature.
    campaign_shape_cache: dict = {}

    LOGGER.info(
        f"{len(alerts_to_analyze)} alert(s) collapsed into {len(groups)} distinct threat "
        f"pattern(s) (device+target+signature). Cache TTL={cache_ttl_seconds/3600:.1f}h, "
        f"max {max_queries_per_run} fresh Ollama call(s) this run."
    )

    cache_path = Path(config.get("state_path", "state/ids_state.json")).parent / "ollama_analysis_cache.json"
    cache = _load_cache(cache_path, cache_ttl_seconds)

    validator = DeterministicValidator()
    fp_engine = AutonomousFPEngine(config=config, state_dir=str(root_dir / "state"))

    # PHASE 14: mirrors middleware/routers/pihole_api.py's _ipc_immunize_logic() pattern --
    # a fresh StateManager + IPSMitigator per run, used only to release a Pi-hole block for
    # a domain this run just immunized. unblock_domain() makes a real Pi-hole API call
    # regardless of which process instantiated the client, so this has the same real-world
    # effect as the live pipeline calling it directly. Per explicit direction: an
    # autonomous correction should also undo containment that's no longer warranted, not
    # just stop future alerts -- block only what's absolutely necessary.
    state_manager = StateManager(state_path=str(Path(config.get("state_path", "state/ids_state.json"))))
    state_manager.load_from_disk()
    ips_mitigator = IPSMitigator(config=config, state_manager=state_manager)

    report_lines = [
        f"# 🛡️ Home-IDS Daily SOC Report",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Model:** {ollama_model}",
        f"**Alerts seen:** {len(alerts_to_analyze)} → **{len(groups)} distinct threat pattern(s)**",
        "",
        "## Analyzed Threats",
        ""
    ]

    new_transparency_logs = []
    pattern_outcomes = []
    queries_made = 0
    cache_hits = 0
    deferred = 0
    run_validated = defaultdict(int)  # classification -> count this run, for the cumulative relay metric

    # VERSION 10 (#15/#16): explicitly instructs independent reasoning from raw evidence
    # only, matching what the payload itself now actually contains (see
    # _build_evidence_only_payload) -- the model is never shown this system's own risk
    # score, signature name, or prior verdict, so it must derive a classification from
    # device/network_context/features itself rather than ratifying an existing one.
    #
    # PHASE 51 (structured evidence contract): the schema used to be just {classification,
    # confidence, reason, recommended_action} -- one free-text paragraph the model could
    # fill with "no TI hit, so probably benign" and nothing forced it to actually name what
    # it thinks is happening or list what it's basing that on. This mirrors the required/
    # supporting/contradicting shape every Hypothesis subclass in hypotheses/engine.py
    # already uses internally -- the model is now asked to reason the SAME way, in the
    # SAME vocabulary, so `hypothesis`/`supporting_evidence`/`contradicting_evidence` are
    # checkable claims (see ai_soc.py's DeterministicValidator, which now rejects a
    # "benign" verdict carrying no supporting_evidence at all, or one that lists its own
    # contradicting_evidence and recommends suppress anyway) rather than a paragraph that
    # can only be parsed for a handful of substrings ("telemetry", an exact risk-score
    # digit). `classification` itself stays the existing benign|malicious values --
    # every downstream branch in this file's main() already keys on exactly those two
    # strings; renaming it to a 3-way enum here would be a much larger, separate change
    # (see Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 4 entry).
    system_prompt = (
        "You are an autonomous Tier 2 SOC Analyst for a Home Intrusion Detection System. "
        "You are given RAW EVIDENCE ONLY for one network alert -- device info, connection "
        "details, and measured features (DNS query patterns, Zeek flow statistics, threat-"
        "intelligence/reputation scores such as ti_risk/abuse_risk/vt_risk). You are "
        "deliberately NOT told this system's own prior risk score, signature name, or "
        "verdict -- you must independently determine whether the activity is benign (e.g. "
        "telemetry, ads, routine device chatter) or malicious purely from the evidence "
        "given, not by assuming any classification already exists. "
        "Reason like a hypothesis test, not a vibe check: name the SPECIFIC benign or "
        "attack explanation you believe fits (use this system's own vocabulary when it "
        "applies -- benign: DEVICE_PROFILE_TELEMETRY, LOCAL_DEVICE_DISCOVERY, "
        "ADVERTISING_BURST; attack: NETWORK_INTRUSION, DNS_COVERT_TUNNELING, "
        "DGA_BOTNET_C2, CONNECTION_ABUSE, DATA_EXFILTRATION, C2_BEACONING, "
        "DNS_POLICY_BYPASS -- or a short specific name if none of these fit), then list "
        "the concrete evidence that supports it and the concrete evidence that argues "
        "against it. The ABSENCE of a threat-intel hit (ti_risk/abuse_risk/vt_risk all "
        "0.0) is NOT supporting evidence for benign -- it is simply unknown, and must not "
        "be the sole item in supporting_evidence. A 'benign' classification with an empty "
        "supporting_evidence list, or one whose supporting_evidence is only the absence of "
        "bad reputation, will be rejected. "
        "You must respond ONLY with a valid JSON object matching this schema: "
        "{\"hypothesis\": \"<specific named explanation, not just 'benign' or 'malicious'>\", "
        "\"classification\": \"benign|malicious\", \"confidence\": 0.0-1.0, "
        "\"reason\": \"<short executive summary>\", "
        "\"supporting_evidence\": [\"<concrete observation that supports the hypothesis>\", ...], "
        "\"contradicting_evidence\": [\"<concrete observation that argues against it, if any>\"], "
        "\"missing_evidence\": [\"<what would make you more confident, if anything>\"], "
        "\"recommended_action\": \"suppress|block|none\", "
        "\"ttl_seconds\": <how long this verdict should be trusted before re-evaluation, e.g. 86400>}"
    )

    for key in ordered_keys:
        members = groups[key]
        representative = members[0]  # most recent structure is representative enough for a pattern-level verdict
        # PHASE 57: the persistent on-disk cache is keyed more finely than the in-run
        # grouping key (`key`) -- see _persistent_cache_key()'s own docstring.
        pcache_key = _persistent_cache_key(representative)
        device_ip = representative.get("device", {}).get("ip", "unknown")
        # BUGFIX (live alert audit): device_id/alert_hostname used to only be extracted
        # deep inside the malicious/benign-suppress branches individually -- hoisted here
        # so every branch (including the new structured pattern_outcomes capture below)
        # has them without re-deriving.
        device_id = representative.get("device", {}).get("id", "unknown")
        alert_hostname = representative.get("device", {}).get("hostname", "unknown")
        risk = representative.get("risk", 0.0)
        target = _target_for_key(representative)

        cached = cache.get(pcache_key)
        if cached:
            response_json = {
                "hypothesis": cached.get("hypothesis", ""),
                "classification": cached.get("classification", "unknown"),
                "confidence": cached.get("confidence", 0.0),
                "reason": cached.get("reason", ""),
                # PHASE 51: absent for any cache entry written before the structured
                # contract existed -- defaults to [] rather than erroring, same
                # backward-compat treatment as every other new field here.
                "supporting_evidence": cached.get("supporting_evidence", []),
                "contradicting_evidence": cached.get("contradicting_evidence", []),
                "missing_evidence": cached.get("missing_evidence", []),
                "recommended_action": cached.get("recommended_action", "none"),
                "ttl_seconds": cached.get("ttl_seconds"),
            }
            is_valid = bool(cached.get("validator_passed", False))
            cache_hits += 1
            cache_age_h = (time.time() - float(cached.get("ts", time.time()))) / 3600.0
            LOGGER.info(f"[CACHE HIT] {device_ip} -> {target} ({len(members)} alert(s), cached {cache_age_h:.1f}h ago) -- skipping Ollama call.")
        elif queries_made >= max_queries_per_run:
            deferred += 1
            LOGGER.info(f"[DEFERRED] {device_ip} -> {target} ({len(members)} alert(s)) -- per-run query cap ({max_queries_per_run}) reached, will retry next run.")
            report_lines.append(f"### Target: `{target}` (Device: `{device_ip}`, {len(members)} alert(s))")
            report_lines.append("- **Status:** `DEFERRED` -- per-run Ollama query cap reached, will retry on the next scheduled run.")
            report_lines.append("")
            # BUGFIX (live alert audit): this pattern never got analyzed at all this run
            # (no LLM call, no cache hit) -- captured as its own outcome so the digest
            # doesn't silently drop it the way it used to.
            pattern_outcomes.append({
                "cache_key": key, "device_id": device_id, "hostname": alert_hostname,
                "device_ip": device_ip, "target": target, "target_asn_note": "",
                "signature": representative.get("signature", "unknown"), "classification": None,
                "llm_confidence": None, "llm_reason": "", "alerts_covered": len(members),
                "outcome": "deferred_query_cap", "outcome_detail": "per-run Ollama query cap reached, will retry next run",
            })
            continue
        else:
            # VERSION 10 (#15/#16): prompt built from the sanitized evidence-only view,
            # not the raw representative dict -- see _build_evidence_only_payload's own
            # comment for the incident this fixed.
            evidence_only_payload = _build_evidence_only_payload(representative)
            prompt_text = f"Alert Payload:\n{json.dumps(evidence_only_payload, indent=2)}"
            feats = representative.get("features", {}) or {}
            rep_value = max(
                float(feats.get("ti_risk", 0.0) or 0.0),
                float(feats.get("abuseipdb_risk", 0.0) or 0.0),
                float(feats.get("vt_risk", 0.0) or 0.0),
            )
            ev_store = []
            if rep_value > 0.0:
                ev_store.append(Evidence(
                    type="reputation", source="threat_intel", timestamp=representative.get("timestamp", time.time()),
                    device=device_ip, value=rep_value, confidence=0.95 if rep_value >= 4.0 else 0.8,
                    independence_group="reputation", provenance="ollama_soc:reconstructed_from_features",
                ))

            try:
                queries_made += 1
                LOGGER.info(f"[QUERY {queries_made}/{max_queries_per_run}] {device_ip} -> {target} ({len(members)} alert(s) collapsed into this one call)...")
                response_json = _query_ollama(ollama_url, ollama_model, prompt_text, system_prompt)
            except Exception as e:
                LOGGER.error(f"Failed to query Ollama for {device_ip} -> {target}: {e}")
                response_json = None

            if response_json is None:
                continue

            # PHASE 50: this alert's own original attack-vs-benign hypothesis competition,
            # as computed live by decision_engine.py when it was first published (see
            # pipeline.py's alert_payload comment) -- absent (empty dict) for alerts
            # published before this existed, in which case the validator's ground-truth
            # check below is a no-op and behavior is unchanged from before this phase.
            ground_truth = {
                "hypotheses": representative.get("hee_hypotheses", {}),
                "independent_sources": representative.get("hee_independent_sources", 0),
                "decision_path": representative.get("hee_decision_path", ""),
            }

            # VERSION 10 (#15/#16): original_risk lets the validator's defense-in-depth
            # check catch a response that suspiciously cites the exact score it was
            # never shown (see ai_soc.py's DeterministicValidator.validate()).
            is_valid = validator.validate(response_json, ev_store, original_risk=risk, ground_truth=ground_truth)
            cache[pcache_key] = {
                "cache_key": key,  # PHASE 57: human-readable grouping identity, for debugging/audit only
                "hypothesis": response_json.get("hypothesis", ""),
                "classification": response_json.get("classification", "unknown"),
                "confidence": response_json.get("confidence", 0.0),
                "reason": response_json.get("reason", ""),
                "supporting_evidence": response_json.get("supporting_evidence") or [],
                "contradicting_evidence": response_json.get("contradicting_evidence") or [],
                "missing_evidence": response_json.get("missing_evidence") or [],
                "recommended_action": response_json.get("recommended_action", "none"),
                "ttl_seconds": response_json.get("ttl_seconds"),
                "validator_passed": is_valid,
                "model": ollama_model,
                "ts": time.time(),
                "action_taken": False,
            }

        run_validated[response_json.get("classification", "unknown")] += 1

        # PHASE 9/11: one transparency log per PATTERN, not per repeat alert -- keeps
        # alerts.json growth bounded to the number of distinct threats, not the number of
        # times a noisy one happened to fire.
        new_transparency_logs.append({
            "type": "ollama_transparency",
            "component": "batch_analyzer",
            # BUGFIX (live alert audit): "hostname" and "target" were never on this entry
            # at all -- readable only by decoding cache_key or cross-referencing device_id
            # against alerts.json/state separately. Both are already local variables here.
            "device": {"id": device_id, "ip": device_ip, "hostname": alert_hostname},
            "target": target,
            "timestamp": time.time(),
            "original_alert_ts": representative.get("timestamp"),
            "risk": risk,
            "model": ollama_model,
            "cache_key": key,
            "alerts_covered": len(members),
            "response": response_json,
            "validator_passed": is_valid,
        })

        report_lines.append(f"### Target: `{target}` (Device: `{device_ip}`, {len(members)} alert(s) covered by this analysis)")
        # PHASE 51 (structured contract): hypothesis is shown alongside classification --
        # "BENIGN, hypothesis=DEVICE_PROFILE_TELEMETRY" is a checkable claim; bare
        # "BENIGN" was not. Empty for any cached entry written before this existed.
        llm_hypothesis = response_json.get("hypothesis") or ""
        hyp_note = f" — hypothesis: `{llm_hypothesis}`" if llm_hypothesis else ""
        report_lines.append(f"- **Classification:** `{response_json.get('classification', 'unknown').upper()}` (Confidence: {response_json.get('confidence', 0.0)}){hyp_note}")
        report_lines.append(f"- **Summary:** {response_json.get('reason', 'N/A')}")
        for label, field in (("Supporting evidence", "supporting_evidence"),
                              ("Contradicting evidence", "contradicting_evidence"),
                              ("Missing evidence", "missing_evidence")):
            items = response_json.get(field) or []
            if items:
                report_lines.append(f"- **{label}:** " + "; ".join(str(i) for i in items))
        report_lines.append(f"- **Recommended Action:** `{response_json.get('recommended_action', 'none')}`")
        report_lines.append(f"- **Validator Passed:** `{'YES' if is_valid else 'NO'}`")
        # PHASE 50: show the deterministic engine's own original finding for this alert,
        # named-family style (not a bare count) -- matches evidence.py's own
        # EVIDENCE_FAMILIES vocabulary rather than restating "N independent signal(s)".
        gt_hyp = representative.get("hee_hypotheses", {}) or {}
        if gt_hyp:
            gt_sources = representative.get("hee_independent_sources", 0)
            gt_families = representative.get("hee_evidence_families", [])
            families_note = f" ({', '.join(gt_families)})" if gt_families else ""
            report_lines.append(
                f"- **Original HEE finding:** attack=`{gt_hyp.get('attack', {}).get('name', '?')}` "
                f"(score={gt_hyp.get('attack', {}).get('score', 0):.1f}) vs. "
                f"benign=`{gt_hyp.get('benign', {}).get('name', '?')}` "
                f"(score={gt_hyp.get('benign', {}).get('score', 0):.1f}) — "
                f"{gt_sources} independent evidence famil{'y' if gt_sources == 1 else 'ies'}{families_note}, "
                f"decision_path=`{representative.get('hee_decision_path', 'n/a')}`"
            )

        # PHASE 9 FIX (autonomous action): calls fp_engine.mark_false_positive() -- the same
        # mechanism the "🛡️ Mark False Positive" Telegram button uses -- instead of writing
        # to safe_host_patterns (a device-hostname key, not a domain-suppression one; see the
        # Phase 9 history below for why that was always a no-op).
        # PHASE 11 FIX: only take this action ONCE per pattern (action_taken flag in the
        # cache entry), not on every cache-hit re-run of the same still-recurring pattern --
        # re-immunizing an already-immunized domain and re-widening an already-widened sigma
        # every 4 hours for the identical verdict is exactly the kind of redundant repeat
        # work this whole rewrite exists to eliminate.
        already_actioned = bool(cache.get(key, {}).get("action_taken"))
        signature = representative.get("signature", "unknown")
        spread = len(signature_device_counts.get(signature, ()))
        # PHASE 53: computed once per signature, reused across every target sharing it.
        if signature not in campaign_shape_cache:
            campaign_shape_cache[signature] = _is_campaign_corroborated(
                signature_members.get(signature, []), geoip_engine
            )
        campaign_corroborated = campaign_shape_cache[signature]
        # BUGFIX (live alert audit): outcome/outcome_detail feed the new structured
        # pattern_outcomes list below -- captures what actually happened (and why) for
        # EVERY pattern, not just malicious verdicts, so the run's Telegram digest can
        # show all of it. Defaults to "no_action_needed" for the case none of the
        # branches below fire (invalid verdict, or a classification/action combo that
        # isn't one of benign+suppress / malicious) -- previously silent even in the
        # .md report.
        outcome = "no_action_needed"
        outcome_detail = "" if is_valid else "validator rejected this LLM response (see report for detail)"
        # See should_still_withhold()'s own docstring / DEFAULT_MULTI_DEVICE_WITHHOLD_
        # AUTO_RESOLVE_AFTER's comment: once this exact pattern (this device+target+
        # signature key) has independently reconfirmed the identical benign/validator-
        # passed verdict this many times in a row, it stops re-withholding and falls
        # through to the normal immunize branch below -- streak_exhausted=True there
        # gets the report/outcome_detail worded distinctly from a same-day immediate
        # immunize.
        existing_withheld_count = len(cache.get(key, {}).get("withheld_history", []))
        # PHASE 53: streak_exhausted must ALSO require campaign_corroborated to have
        # been true in the first place -- otherwise a pattern that skipped the guard
        # via the campaign check (spread>=guard but scattered across reputable infra)
        # would be misreported as an exhausted-streak auto-resolve below, instead of
        # simply "never needed withholding at all."
        streak_exhausted = (
            not should_still_withhold(
                spread, multi_device_suppress_guard, existing_withheld_count,
                multi_device_withhold_auto_resolve_after, campaign_corroborated,
            )
            and spread >= multi_device_suppress_guard and campaign_corroborated
        )
        if is_valid and response_json.get('classification') == 'benign' and response_json.get('recommended_action') == 'suppress' and not already_actioned and should_still_withhold(
            spread, multi_device_suppress_guard, existing_withheld_count,
            multi_device_withhold_auto_resolve_after, campaign_corroborated,
        ):
            LOGGER.warning(
                f"[MULTI-DEVICE GUARD] '{signature}' is independently firing on {spread} distinct "
                f"devices right now (>= {multi_device_suppress_guard}), destinations concentrated or "
                f"unexplained (not scattered across reputable infra) -- withholding the autonomous "
                f"suppress/immunize action for {target!r} despite a benign LLM verdict. A pattern this "
                f"widespread deserves a human look, not a same-day auto-immunization; not marking "
                f"action_taken so it's reconsidered next run against then-current device spread."
            )
            report_lines.append(
                f"- **Autonomous Action Withheld:** LLM recommended suppress, but signature "
                f"`{signature}` is independently firing on {spread} distinct devices right now "
                f"(guard threshold {multi_device_suppress_guard}), and their destinations don't look "
                f"like independent, reputable infrastructure -- deferred to human review instead of "
                f"auto-immunizing."
            )
            outcome = "withheld_multi_device"
            # BUGFIX (live alert audit): the "traceable spread" requirement -- this used to
            # persist nothing at all (comment above already explained why action_taken
            # stays False), so a pattern withheld every run for weeks produced an
            # identical "withheld again" line every time, no memory of prior occurrences
            # or which devices were involved. cache[pcache_key] is guaranteed to already
            # exist here (written above on a fresh call, or already present on a cache hit).
            devices_now = signature_device_counts.get(signature, set())
            withheld_history = cache[pcache_key].setdefault("withheld_history", [])
            new_devices = devices_now - set(withheld_history[-1]["device_ids"]) if withheld_history else devices_now
            new_device_labels = sorted(dev_display_map.get(d, d) for d in new_devices)
            if not withheld_history:
                outcome_detail = f"first withheld, spreading to {len(devices_now)} device(s): {', '.join(sorted(dev_display_map.get(d, d) for d in devices_now)) or 'unknown'}"
            elif new_devices:
                spread_seq = "→".join(str(len(h["device_ids"])) for h in withheld_history) + f"→{len(devices_now)}"
                first_ts_human = datetime.fromtimestamp(withheld_history[0]["ts"]).strftime("%Y-%m-%d %H:%M")
                outcome_detail = (
                    f"withheld {len(withheld_history) + 1} time(s) — spread {spread_seq} devices "
                    f"since {first_ts_human} (newly joined: {', '.join(new_device_labels)})"
                )
            else:
                last_ts_human = datetime.fromtimestamp(withheld_history[-1]["ts"]).strftime("%Y-%m-%d %H:%M")
                outcome_detail = (
                    f"withheld {len(withheld_history) + 1} time(s) — still {len(devices_now)} device(s), "
                    f"no new spread since {last_ts_human}"
                )
            withheld_history.append({
                "ts": time.time(), "device_ids": sorted(devices_now),
                "display_names": sorted(dev_display_map.get(d, d) for d in devices_now),
            })
            cache[pcache_key]["withheld_history"] = withheld_history[-20:]  # own cap -- nothing else prunes this sub-field
        elif is_valid and response_json.get('classification') == 'benign' and response_json.get('recommended_action') == 'suppress' and not already_actioned:
            # Reached because spread < guard (the normal, first-time/low-spread case),
            # OR streak_exhausted (this pattern independently reconfirmed the identical
            # verdict multi_device_withhold_auto_resolve_after times in a row -- see
            # that constant's own comment), OR spread >= guard but campaign_corroborated
            # is False (PHASE 53: destinations scattered across individually-reputable
            # infra, not a real campaign) -- all three take the same corrective action
            # below; only the report/outcome_detail wording differs.
            streak_note = (
                f"auto-resolved after {existing_withheld_count} consistent withholds -- "
                if streak_exhausted else ""
            ) + (
                # PHASE 53: spread alone would have satisfied the multi-device guard,
                # but campaign correlation found the destinations scattered across
                # independently-reputable infra -- not a coordinated incident, so this
                # never actually withheld. Mutually exclusive with the streak_exhausted
                # note above (that one only ever fires once campaign_corroborated was
                # True, i.e. this pattern WAS withheld at least once).
                f"spread={spread} device(s) but destinations scattered across independently-"
                f"reputable infrastructure (not a coordinated campaign) -- "
                if spread >= multi_device_suppress_guard and not campaign_corroborated and not streak_exhausted
                else ""
            )
            target_domain = representative.get("network_context", {}).get("queried_domain", "") or ""
            if target_domain and target_domain != "unknown":
                # PHASE 13: tagged distinctly from a real Telegram operator tap, so
                # train_fp_classifier.py's threshold self-calibration can tell "the LLM
                # validated this, autonomously, every 4h" apart from "a human confirmed
                # this" — the former is now the PRIMARY, human-independent calibration
                # signal; the latter remains valid and optional on top.
                # PHASE 52: threads the LLM's own suggested ttl_seconds (Phase 51) through
                # as this specific immunization's TTL override -- fp_engine.mark_false_positive()
                # clamps it to a sane range and falls back to the 14-day default if absent/invalid.
                mark_result = fp_engine.mark_false_positive(
                    representative, alert_hostname, target_domain, source="llm_validated",
                    ttl_seconds=response_json.get("ttl_seconds"),
                )
                base_domain = mark_result.get("base_domain", "")
                if pcache_key in cache:
                    cache[pcache_key]["action_taken"] = True
                if base_domain:
                    # PHASE 14: an earlier cycle may have already blocked this domain in
                    # Pi-hole before the LLM had a chance to validate it as benign -- an
                    # immunization alone only stops FUTURE alerts, it doesn't undo an
                    # existing block.
                    # PHASE 16 FIX: was an exact-match check against base_domain itself, but
                    # Pi-hole blocks are keyed by the specific queried FQDN -- almost always a
                    # subdomain of base_domain, not base_domain literally. unblock_by_base_domain()
                    # sweeps every blocked entry under this base domain instead of missing all of them.
                    released = ips_mitigator.unblock_by_base_domain(base_domain)
                    unblocked_note = ""
                    if released:
                        unblocked_note = f" Released {len(released)} existing Pi-hole block(s)."
                        LOGGER.info(f"🔓 [OLLAMA-SOC] '{base_domain}' was immunized -- released {len(released)} existing Pi-hole block(s): {released}")
                    report_lines.append(
                        f"- **Autonomous Action Taken:** 🤖 {streak_note}Immunized `{base_domain}` in the "
                        f"FP trust cache and logged an operator-equivalent training correction "
                        f"(takes effect on soc.service's next restart).{unblocked_note}"
                    )
                    outcome = "immunized"
                    outcome_detail = f"{streak_note}domain immunized 14 days, sensitivity loosened for this device{unblocked_note}"
                else:
                    report_lines.append(
                        f"- **Autonomous Action Skipped:** could not safely extract a base domain "
                        f"from `{target_domain}` — no immunization applied."
                    )
                    outcome = "skipped"
                    outcome_detail = f"could not safely extract a base domain from '{target_domain}'"
            else:
                # BUGFIX (2026-09-01, live report: "is Ollama ever completing all the
                # alerts or is it just piling up"): this branch used to be a SILENT NO-OP
                # for any target with no resolved domain (an IP-only NETWORK_INTRUSION
                # target, the majority shape of what was piling up) -- the outer `if
                # target_domain:` gate meant neither immunize NOR skip ever ran, so
                # action_taken never got set and the pattern could never resolve, EVEN
                # on a first-time low-spread pass that never touched the multi-device
                # guard at all. mark_false_positive() already has a no-domain fallback
                # for two other signature shapes (DNS_EVASION -> immunize the raw IP,
                # CONNECTION_ABUSE -> raise this device's own arp_sweep threshold, see
                # fp_engine.py's PHASE 21D2 routing) -- NETWORK_INTRUSION isn't among
                # those, so this reuses the same device-level sensitivity-loosening
                # primitive the malicious/TUNE_UP branch below already calls, just in
                # the opposite direction, so an IP-only pattern still has SOMETHING
                # corrective happen and SOMETHING that marks it resolved.
                fp_engine._apply_sigma_shift(
                    device_id, alert_hostname, direction="TUNE_DOWN",
                    source="llm_validated_streak" if streak_exhausted else "llm_validated_no_domain",
                )
                if pcache_key in cache:
                    cache[pcache_key]["action_taken"] = True
                report_lines.append(
                    f"- **Autonomous Action Taken:** 🤖 {streak_note}No domain to immunize (IP-only "
                    f"target `{target}`) -- loosened this device's own detection sensitivity instead."
                )
                outcome = "immunized"
                outcome_detail = f"{streak_note}no domain to immunize -- device sensitivity loosened instead"
        elif is_valid and response_json.get('classification') == 'malicious' and not already_actioned:
            # BUGFIX (2026-08-27, third-party review): mirrors exactly what fp_engine's
            # own two hard-evidence confirmation paths already do together (Stage-1 hard-
            # stop, and pipeline.py's HIGH/CRITICAL bar) -- record_confirmed_threat() feeds
            # local_intel.py (so a DIFFERENT device touching the same dest_ip later gets an
            # immediate hard-stop) and the confirmed-threat counter, and _apply_sigma_shift
            # TUNE_UP tightens this device's own future sensitivity. base_domain
            # deliberately omitted (None) here -- ollama_soc.py has no evidence-linked
            # domain attribution the way pipeline.py's DGA/tunneling branches do, and this
            # codebase has already fixed the "coincidental most-frequent-domain in window"
            # poisoning bug once; dest_ip alone is the reliably-attributable part of this
            # verdict.
            dest_ip = representative.get("network_context", {}).get("destination_ip", "") or ""
            fp_engine.record_confirmed_threat(
                device_id, None, dest_ip, reason="LLM_VALIDATED_MALICIOUS", signature=signature,
            )
            fp_engine._apply_sigma_shift(device_id, alert_hostname, direction="TUNE_UP", source="llm_validated")
            if pcache_key in cache:
                cache[pcache_key]["action_taken"] = True
            report_lines.append(
                f"- **Autonomous Action Taken:** 🤖 Recorded as confirmed threat (local-intel + "
                f"sensitivity tuned up for {alert_hostname}); this target now hard-stops for any "
                f"other device that touches it."
            )
            outcome = "confirmed_threat"
            outcome_detail = "local confirmed-intel updated (any other device touching this now hard-stops), sensitivity tightened for this device"
        elif already_actioned:
            report_lines.append("- **Autonomous Action:** already applied for this pattern on a previous run — not repeated.")
            outcome = "already_actioned"
            outcome_detail = "already actioned on a previous run, not repeated"

        # BUGFIX (live alert audit): structured capture of every pattern's outcome (not
        # just malicious findings) feeds the new comprehensive run digest below --
        # replaces the old malicious-only validated_malicious_findings-based send.
        target_asn_note = _geo_note(geoip_engine, target) if target != "unknown" else ""
        pattern_outcomes.append({
            "cache_key": key, "device_id": device_id, "hostname": alert_hostname,
            "device_ip": device_ip, "target": target, "target_asn_note": target_asn_note,
            "signature": signature, "classification": response_json.get("classification"),
            "llm_confidence": response_json.get("confidence"), "llm_reason": response_json.get("reason", ""),
            "alerts_covered": len(members), "outcome": outcome, "outcome_detail": outcome_detail,
        })

        report_lines.append("")
        LOGGER.info(f"Analyzed {device_ip} -> {target} (Risk {risk}, {len(members)} alert(s)): {response_json.get('reason')}")

    report_lines.insert(
        6,
        f"**Ollama calls this run:** {queries_made} fresh, {cache_hits} served from cache, {deferred} deferred to next run.\n"
    )

    # 3. Persist the analysis cache
    _save_cache(cache_path, cache)

    # 4. Append transparency logs to alerts.json
    if new_transparency_logs:
        try:
            with open(alerts_path, "a", encoding="utf-8") as f:
                for log in new_transparency_logs:
                    f.write(json.dumps(log) + "\n")
        except Exception as e:
            LOGGER.error(f"Failed to write to alerts.json: {e}")

    # 5. Write Markdown Report
    reports_dir = root_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / f"soc_daily_report_{datetime.now().strftime('%Y%m%d')}.md"

    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
    LOGGER.info(
        f"Generated SOC Daily Report: {report_path} "
        f"({queries_made} fresh Ollama calls, {cache_hits} cache hits, {deferred} deferred)"
    )

    # BUGFIX (live alert audit): this used to only ever send Telegram for validated
    # malicious findings -- benign-suppress actions, multi-device-guard withholds, and
    # quiet "nothing new happened" runs were all invisible outside the .md report nobody
    # is prompted to open. Now fires once per run (whenever there was something to
    # analyze at all), covering every pattern's outcome, so a quiet run is visibly
    # confirmed healthy rather than silently absent -- matches the digest CL-AFPE's own
    # autonomous actions already get.
    if ordered_keys:
        full_msg = build_ollama_digest_message(pattern_outcomes, report_path.name)
        if full_msg:
            _send_telegram(config, full_msg)

    state_dir = root_dir / "state"
    _write_ollama_relay_stats(state_dir, calls_made=queries_made, cache_hits=cache_hits, deferred=deferred, run_validated=run_validated)
    write_job_health(state_dir, "ollama_soc", time.time() - run_start)

if __name__ == "__main__":
    main()
