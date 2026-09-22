"""
live_llm_review.py - schedules v13's own LLM-review (src/v13/llm_review/) against
`.94`'s own live graph (v13 full-architecture plan, Phase 5).

DESIGN DECISION (2026-09-07, user confirmed): batch-script shape (a separate scheduled
subprocess), NOT in-cycle invocation from pipeline.py. Lower risk, ships the
JSON-schema-constrained-decoding fix without touching the live 2s poll loop's timing
at all. In-cycle invocation stays a real, separately-scoped future option if it's ever
worth the added complexity.

v16: the sole Layer-3 LLM review engine. scripts/ollama_soc.py (and its dedicated
intelligence/ai_soc.py validator) were retired once this script reached feature
parity with it -- persistent alert dedup/grouping, cross-device campaign
correlation, Telegram digest building, and GeoIP-enriched reporting, all listed
below under their original Phase numbers, are now all wired in. Writes to
state/ollama_analysis_v13.jsonl (the filename predates the rename -- kept as-is,
matching this project's standing policy on renaming live data files for zero
functional benefit).

Advisory/reporting only, deliberately: an LLM verdict here does NOT autonomously
suppress or confirm anything. That decision-triggering authority was retired in
Release 15 Sheet 05 (scripts/ollama_soc.py's own OLLAMA_HAS_DECISION_AUTHORITY,
before this file existed) in favor of two independent, backtest-gated mechanisms
that don't route through an LLM or a human Telegram tap at all: the closed-loop
autotuner (argus/autotune/engine.py) and CL-AFPE composite trust
(argus/cl_afpe/composite_trust.py). Consolidating down to this one script does
not reopen that decision.

Gated by config.yaml's detection_engine.llm_review_enabled (default true) --
main() no-ops immediately if disabled, read fresh at the top of every scheduled
run since each run is a separate subprocess, not the long-running soc.service.

WHAT IT REVIEWS: v13's own decisions (state/v13_graph.db), not v-current's
alerts.json -- v13's DeterministicValidator.build_ground_truth() is already built to
consume a v13 DecisionEngine.evaluate() result + Evidence list directly (see that
module's own docstring), not v-current's alert_payload dict shape. Reviews every
SUSPICIOUS/HIGH/CRITICAL decision from the lookback window that hasn't been reviewed
yet (tracked by decision_id in the output file itself -- no separate cache needed),
up to a per-run cap.

RATE LIMITING: DEFAULT_MAX_QUERIES_PER_RUN (5) bounds a single run to a sane worst
case regardless of how many decisions are pending (each call can take up to
OllamaClient's own 900s worst-case timeout). Calls are made strictly one at a
time in a plain sequential loop -- never threaded/async -- respecting the standing
"never send more than one in-flight request to `.94`'s own Ollama (-np 1)" rule by
construction, not by an explicit lock (nothing in this process ever issues a second
request before the first returns).

v13 full-architecture plan, Phase 8 (added after this module's initial Phase 5
build): 8a pattern-level persistent caching (a recurring pattern across SEPARATE
decision rows is now served from cache, not re-queried -- see _persistent_cache_key()
below) and 8d a Telegram digest per run (build_llm_review_digest_message()), both
now wired in. 8b (alert dedup/grouping) is deliberately NOT a separate mechanism --
see _persistent_cache_key()'s own docstring for why 8a's design already provides it
for free, as a direct consequence rather than a second implementation of the same
idea. 8c (INDEPENDENCE_FAMILY_MAP validation) lives in its own module,
v13/ops/independence_family_report.py -- a genuinely separate concern (divergence-
data analysis, not LLM review), not this file's job.

NOT YET IMPLEMENTED (each a real, separately-scoped follow-up): local-model triage
pre-filtering (OllamaClient.query_triage() exists and is usable, but its own
docstring says specificity isn't validated yet -- deliberately gated on that open
validation question), job-health per-device breakdown.

Release 14, Workstream 4 (2026-09-07): cross-device campaign correlation and
GeoIP-enriched reporting are now both wired in.
- Cross-device correlation: a structural gap, not a missing feature -- this script
  reviews a decision's PERSISTED graph evidence (window.evidence_in_window()), but
  v13's own live decision path (live_engine.py's _inject_graph_derived_evidence())
  deliberately NEVER persists its synthetic coordinated_targeting/first_contact/
  reputation-propagation evidence (writing it would recreate the exact
  evidence-duplication bug Phase 1's own incident already fixed). So a decision
  that WAS informed by "another device touched this destination recently" left no
  trace of that fact anywhere the reviewer could see it. Fixed by RE-DERIVING
  coordinated_targeting fresh at review time (_inject_coordinated_targeting()),
  reusing the exact same graph/window.py query live_engine.py's own live path
  uses, anchored to the DECISION's own original timestamp (not "now") so the
  re-derived signal reflects what the original decision actually saw -- the same
  "re-derive, don't assume persistence" precedent independence_family_report.py
  (Phase 8c) already established. Scoped to coordinated_targeting only (the item
  named in the plan) -- first_contact/reputation-propagation are the same
  structural gap but a separate, not-yet-scoped follow-up.
- GeoIP: a `_geo_note()` copy (matching live_retro_hunter.py's/retro_hunter.py's
  own established "small per-script copy" convention) enriches the Telegram
  digest's per-rejection detail lines with a representative destination's
  Org/Country -- human-facing reporting only, never sent to the LLM itself,
  matching exactly how ollama_soc.py/live_retro_hunter.py already use it.
"""
import hashlib
import ipaddress
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from intelligence.geoip import GeoIPEngine  # noqa: E402
from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.graph.store import GraphStore  # noqa: E402
from argus.graph.window import RollingWindowView  # noqa: E402
from argus.hypotheses.independence import family_for, NON_ATTACK_FAMILIES  # noqa: E402
from argus.llm_review.ollama_client import OllamaClient, build_evidence_prompt  # noqa: E402
from argus.llm_review.validator import DeterministicValidator, build_ground_truth, VALIDATOR_SCHEMA_VERSION  # noqa: E402
from argus.ops.telegram import send_telegram  # noqa: E402

LOGGER = logging.getLogger("live_llm_review")

# Matches scripts/ollama_soc.py's own DEFAULT_MAX_QUERIES_PER_RUN exactly -- same
# reasoning (bounds one run to a sane worst-case wall-clock time regardless of how
# many decisions are pending). Phase 8a: this now caps REAL Ollama calls only -- a
# persistent-cache hit is nearly free (a local graph read + a dict lookup), so it
# no longer consumes the same budget a real 900s-worst-case call does.
DEFAULT_MAX_QUERIES_PER_RUN = 5

# Matches scripts/ollama_soc.py's own DEFAULT_CACHE_TTL_SECONDS exactly (7 days --
# "matches this codebase's other weekly cadence, fp_engine's own retrain loop").
PERSISTENT_CACHE_TTL_SECONDS = 7 * 24 * 3600

# Same character-budget discipline as ollama_soc.py's own _TELEGRAM_MSG_BUDGET
# (headroom under Telegram's real 4096-char hard limit).
_TELEGRAM_MSG_BUDGET = 3800

# How far back to look for SUSPICIOUS+ decisions worth reviewing -- wider than the
# 4-hour run cadence on purpose, so a run that hit the query cap last time still
# finds (and eventually catches up on) anything it deferred, via the
# already-reviewed check below, not a narrower time window that would silently drop
# a deferred decision once it ages out of a 4-hour lookback.
LOOKBACK_SECONDS = 24 * 3600

# What actually gets reviewed -- matches what v-current's own pipeline surfaces to
# ollama_soc.py in practice (published alerts), not BENIGN/ANOMALOUS noise.
_REVIEWABLE_STATES = frozenset({"SUSPICIOUS", "HIGH", "CRITICAL"})

_OUTPUT_FILENAME = "ollama_analysis_v13.jsonl"

# Matches live_engine.py's own constants exactly -- same signal, same thresholds,
# just re-derived at review time instead of read from live_engine.py's in-process
# state (see this module's own docstring for why re-deriving is necessary at all).
# RAISED alongside live_engine.py's own constant, 2026-09-09 -- see that module's
# comment for the live incidents this closes.
_COORDINATED_TARGETING_WINDOW_SECONDS = RollingWindowView.SHORT_WINDOW_SECONDS
_COORDINATED_TARGETING_MIN_OTHER_DEVICES = 2  # "3+ distinct devices" total = 2+ OTHER devices


def _load_already_reviewed(output_path: Path) -> Set[str]:
    """The output file IS the cache -- every decision_id that already has a line in
    it has already been reviewed, so no separate cache file/dict is needed. Fails
    safe to an empty set (re-reviewing a few decisions once is harmless; silently
    skipping everything because a read failed would not be)."""
    reviewed: Set[str] = set()
    if not output_path.exists():
        return reviewed
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                did = entry.get("decision_id")
                if did:
                    reviewed.add(did)
    except Exception as e:
        LOGGER.warning("Failed to read %s for already-reviewed decision_ids: %s", output_path, e)
    return reviewed


def _rep_tier_for(evidence_list) -> Optional[int]:
    """build_ground_truth() takes an optional rep_tier -- best-effort extraction
    from the highest-confidence 'reputation' evidence item present, matching how a
    device's own reputation context would inform the validator's tier-based checks.
    None (no opinion) when no reputation evidence is present at all."""
    rep_items = [e for e in evidence_list if e.evidence_type == "reputation"]
    if not rep_items:
        return None
    best = max(rep_items, key=lambda e: e.confidence)
    try:
        return int(best.value) if best.value is not None else None
    except (TypeError, ValueError):
        return None


def _inject_coordinated_targeting(store: GraphStore, window: RollingWindowView, device_id: str,
                                     evidence_list: List[Evidence], now: float) -> List[Evidence]:
    """Re-derives live_engine.py's own coordinated_targeting signal at REVIEW time,
    anchored to the decision's own original timestamp (`now` here IS
    decision["timestamp"], never the review's own current time -- a different
    anchor would ask "who else is targeting this destination right now", a
    different question than what the original decision actually saw). Returns a
    NEW list (never mutates the input) with any synthetic items appended; the
    original graph is never written to, matching the same "derived context, not a
    sensor observation" principle live_engine.py's own version documents. Best-
    effort: any failure degrades to the original evidence_list unchanged, never
    blocks the review."""
    try:
        destinations = {e.destination_id for e in evidence_list if e.destination_id and e.destination_id != NO_DESTINATION}
        if not destinations:
            return evidence_list
        synthetic: List[Evidence] = []
        for dest in destinations:
            others = window.devices_targeting(
                dest, _COORDINATED_TARGETING_WINDOW_SECONDS, now=now, exclude_device_id=device_id,
            )
            if len(others) >= _COORDINATED_TARGETING_MIN_OTHER_DEVICES:
                synthetic.append(Evidence(
                    device_id=device_id, destination_id=dest, evidence_type="coordinated_targeting",
                    independence_family="cross_device_correlation", timestamp=now,
                    source="live_llm_review", confidence=1.0, value=float(len(others) + 1),
                    provenance="live_llm_review:coordinated_targeting",
                    features={"other_devices": others},
                ))
        return evidence_list + synthetic if synthetic else evidence_list
    except Exception as e:
        LOGGER.warning("Failed to re-derive coordinated_targeting for device %r: %s", device_id, e)
        return evidence_list


def _representative_destination(evidence_list: List[Evidence]) -> str:
    """Best-effort pick of the one destination most worth naming in a human-facing
    report -- the highest-confidence real (non-NO_DESTINATION) destination among
    the evidence actually reviewed. v13 decisions are per-DEVICE, not per-
    destination the way v-current's alert_payload carries a single canonical
    target, so this is a first-pass heuristic, not a claim of a single "the"
    target -- documented as such rather than silently presented as authoritative."""
    real_items = [e for e in evidence_list if e.destination_id and e.destination_id != NO_DESTINATION]
    if not real_items:
        return ""
    return max(real_items, key=lambda e: e.confidence or 0.0).destination_id


def _geo_note(geoip_engine: Optional[GeoIPEngine], ip: str) -> str:
    """Matches scripts/retro_hunter.py's/v13/ops/live_retro_hunter.py's own
    _geo_note() exactly: ' (Org, Country)' for a raw IP via local mmdb lookups, or
    '' if unavailable/not an IP (e.g. a domain name, which this has no lookup
    path for). A small local copy, matching that script's own established
    convention of not importing another script's private helper across module
    boundaries."""
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


def _evidence_fingerprint(evidence_list) -> str:
    """v13-native analogue of ollama_soc.py's own _evidence_fingerprint(): a
    content hash of the ATTACK-shaped evidence actually present for this
    decision (family_for(...) not in NON_ATTACK_FAMILIES, matching
    decision/engine.py's own attack_evidence filter), so a genuinely NEW piece
    of evidence -- a fresh evidence_type appearing, or an existing one's
    confidence moving to a materially different bucket -- invalidates the
    persistent cache even when the pattern key below stayed the same. Presence
    (which evidence_types are present) plus confidence rounded to 1 decimal
    place (bucketed, so minor fluctuation doesn't invalidate the cache on
    every run) -- same two-part shape as v1's own real fingerprint, adapted to
    v13's Evidence model rather than v1's raw features dict."""
    attack_items = [e for e in evidence_list if family_for(e.evidence_type) not in NON_ATTACK_FAMILIES]
    presence = sorted({e.evidence_type for e in attack_items})
    bucketed = sorted(round(float(e.confidence or 0.0), 1) for e in attack_items)
    raw = json.dumps({"presence": presence, "bucketed": bucketed}, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _persistent_cache_key(decision: Dict[str, Any], device_id: str, evidence_list) -> str:
    """v13-native port of ollama_soc.py's own _persistent_cache_key() shape:
    a coarse "same pattern" key (device | winning attack hypothesis | decision
    path -- v13's analogue of v1's device|target|signature incident_key) plus
    the evidence fingerprint above plus VALIDATOR_SCHEMA_VERSION, so upgrading
    DeterministicValidator.validate()'s own logic makes every previously-cached
    verdict unreachable by lookup immediately rather than silently trusting a
    validator_accepted boolean computed under superseded rules. Deliberately
    ALSO serves Phase 8b's own goal ("multiple decisions describing the same
    recurring pattern get reviewed together, not once per decision row") --
    not as a second mechanism, but as a direct consequence of this key: the
    first decision matching a pattern in a run makes the real Ollama call and
    populates the in-memory cache immediately (see main()'s own loop below),
    so every LATER decision in the SAME run with the same key is already a
    cache hit by the time it's considered. A separate pre-grouping pass would
    reach the identical outcome through more code, not a different one."""
    payload = decision.get("raw_payload", {}) or {}
    attack_name = payload.get("hypotheses", {}).get("attack", {}).get("name", "unknown")
    pattern = f"{device_id}|{attack_name}|{decision.get('decision_path', 'unknown')}"
    return f"{pattern}|{_evidence_fingerprint(evidence_list)}|v{VALIDATOR_SCHEMA_VERSION}"


def _load_persistent_cache(output_path: Path, now: float,
                             ttl_seconds: float = PERSISTENT_CACHE_TTL_SECONDS) -> Dict[str, Dict[str, Any]]:
    """Builds {persistent_cache_key: most_recent_entry} from every past run's
    own output file -- the file IS the persistent cache, same "no separate
    cache store needed" design _load_already_reviewed() already uses for the
    decision_id-level dedup. Only entries that actually carry BOTH a
    persistent_cache_key (only written by this phase onward -- an entry from
    before this phase existed is gracefully skipped, not an error) and a real
    `recommendation` (an error entry never caches) are eligible; an entry
    older than ttl_seconds is excluded, matching v1's own TTL discipline.
    Iterates the file in its own natural (chronological, append-only) order
    and lets a later entry overwrite an earlier one sharing the same key, so
    the result is always the MOST RECENT still-valid verdict per pattern."""
    cache: Dict[str, Dict[str, Any]] = {}
    if not output_path.exists():
        return cache
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = entry.get("persistent_cache_key")
                if not key or "recommendation" not in entry:
                    continue
                reviewed_at = float(entry.get("reviewed_at", 0) or 0)
                if (now - reviewed_at) > ttl_seconds:
                    continue
                cache[key] = entry
    except Exception as e:
        LOGGER.warning("Failed to read %s for the persistent pattern cache: %s", output_path, e)
    return cache


# Phase 8d: v13-native adaptation of ollama_soc.py's own build_ollama_digest_message()
# shape (character-budgeted detail entries, never truncated mid-sentence -- entries
# that don't fit fold into a "...and N more" counter instead of a hard [:4000] slice
# cutting mid-entry, the exact live bug that function's own docstring documents fixing).
# NOT a line-for-line port: v1's version summarizes AutonomousFPEngine's own
# immunized/confirmed_threat/withheld/skipped auto-ACTION outcomes, which v13's
# reviewer doesn't have (it validates a verdict, it doesn't autonomously act on one) --
# this summarizes what v13's reviewer itself actually found: how many reviews were
# served from the persistent cache vs. a real Ollama call, how many the deterministic
# validator accepted vs. rejected, and the full detail for every REJECTION specifically
# (the single most actionable signal in this digest -- the LLM's own verdict disagreed
# with ground truth).
def build_llm_review_digest_message(entries: List[Dict[str, Any]],
                                       geoip_engine: Optional[GeoIPEngine] = None) -> Optional[str]:
    if not entries:
        return None

    reviewed = len(entries)
    cache_hits = sum(1 for e in entries if e.get("served_from_persistent_cache"))
    errors = sum(1 for e in entries if "llm_error" in e)
    accepted = sum(1 for e in entries if e.get("validator_accepted") is True)
    rejected = [e for e in entries if e.get("validator_accepted") is False]

    lines = [f"\U0001f916 <b>v13 LLM review run: {reviewed} decision(s) reviewed</b>", ""]
    if cache_hits:
        lines.append(f"⚡ {cache_hits} served from the persistent pattern cache (no Ollama call)")
    if accepted:
        lines.append(f"✅ {accepted} LLM verdict(s) accepted by the deterministic validator")
    if rejected:
        lines.append(f"\U0001f6a8 {len(rejected)} LLM verdict(s) REJECTED by the validator "
                      f"(LLM disagreed with ground truth)")
    if errors:
        lines.append(f"⚠️ {errors} error(s) (no usable LLM response)")
    lines.append("")

    detail_budget = 10
    detail_worthy = rejected[:detail_budget]
    included = 0
    running_len = len("\n".join(lines))
    for e in detail_worthy:
        rec = e.get("recommendation", {}) or {}
        geo_note = _geo_note(geoip_engine, e.get("destination", ""))
        dest_suffix = f" → <code>{e['destination']}</code>{geo_note}" if e.get("destination") else ""
        entry_lines = [
            f"• <code>{e.get('device_id', 'unknown')}</code> [{e.get('decision_path', 'unknown')}]"
            f"{dest_suffix} → LLM said '{rec.get('classification', 'unknown')}'",
        ]
        reason = rec.get("reason")
        if reason:
            entry_lines.append(f"  \"{reason}\"")
        entry_lines.append("")
        entry_text = "\n".join(entry_lines)
        if running_len + len(entry_text) > _TELEGRAM_MSG_BUDGET:
            break
        lines.extend(entry_lines)
        running_len += len(entry_text) + 1
        included += 1
    remaining = len(rejected) - included
    if remaining > 0:
        lines.append(f"...and {remaining} more rejection(s) (see {_OUTPUT_FILENAME})")

    return "\n".join(lines)[:4096]


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent

    # v16: config.yaml-driven on/off switch for this job -- see this module's own
    # docstring for why this is advisory/reporting-only either way (never gates an
    # autonomous action). Checked before anything else opens, so a disabled run
    # costs nothing beyond a config read and a job-health write.
    if not bool(CONFIG.get("llm_review_enabled", True)):
        write_job_health(state_dir, "live_llm_review", time.time() - run_start,
                          extra={"reviewed": 0, "skipped": "llm_review_disabled"})
        return

    db_path = state_dir / "v13_graph.db"
    output_path = state_dir / _OUTPUT_FILENAME

    if not db_path.exists():
        write_job_health(state_dir, "live_llm_review", time.time() - run_start,
                          extra={"reviewed": 0, "skipped": "no_db_yet"})
        return

    ollama_url = CONFIG.get("ollama_url", "")
    ollama_model = CONFIG.get("ollama_model", "")
    if not ollama_url or not ollama_model:
        LOGGER.warning("ollama_url/ollama_model not configured -- nothing to review against.")
        write_job_health(state_dir, "live_llm_review", time.time() - run_start,
                          extra={"reviewed": 0, "skipped": "ollama_not_configured"})
        return

    max_queries = int(CONFIG.get("ollama_v13_max_queries_per_run", DEFAULT_MAX_QUERIES_PER_RUN))

    try:
        store = GraphStore(str(db_path))
        window = RollingWindowView(store)
        client = OllamaClient(remote_url=ollama_url, remote_model=ollama_model)
        validator = DeterministicValidator()
        # Release 14, Workstream 4: human-facing digest enrichment only, never sent
        # to the LLM. GeoIPEngine fails safe internally (missing/unreadable mmdb ->
        # reader=None, every lookup then no-ops) -- matches ollama_soc.py's own
        # direct-construction convention, no extra try/except needed here.
        geoip_engine = GeoIPEngine(
            db_path=CONFIG.get("geoip_db", "models/GeoLite2-City.mmdb"),
            asn_db_path=CONFIG.get("geoip_asn_db", "models/GeoLite2-ASN.mmdb"),
        )

        now = time.time()
        already_reviewed = _load_already_reviewed(output_path)
        persistent_cache = _load_persistent_cache(output_path, now)
        candidates = [
            d for d in store.get_decisions_since(now - LOOKBACK_SECONDS)
            if d["state"] in _REVIEWABLE_STATES and d["decision_id"] not in already_reviewed
        ]
        # Oldest first -- review the longest-waiting decisions before newer ones,
        # matching a simple FIFO fairness policy across runs when the cap is hit.
        candidates.sort(key=lambda d: d["timestamp"])

        reviewed = 0
        errors = 0
        cache_hits = 0
        queries_made = 0
        new_entries: List[Dict[str, Any]] = []
        with open(output_path, "a", encoding="utf-8") as out_f:
            for decision in candidates:
                device_id = decision["device_id"]
                evidence_list = window.evidence_in_window(
                    device_id, RollingWindowView.LONG_WINDOW_SECONDS, now=decision["timestamp"],
                )
                # Release 14, Workstream 4: re-derive the cross-device correlation
                # signal live_engine.py's own live decision path computed but never
                # persisted -- see this module's own docstring for why. Anchored to
                # the decision's own timestamp, not "now". Injected BEFORE the cache
                # key/ground-truth/prompt below so all three consistently see it.
                evidence_list = _inject_coordinated_targeting(
                    store, window, device_id, evidence_list, decision["timestamp"],
                )
                # Phase 8a: pattern-level persistent cache -- checked BEFORE the
                # query cap below, so a cache hit (nearly free: a local graph
                # read + a dict lookup, no Ollama call) is never deferred just
                # because earlier candidates already used up this run's real-call
                # budget. See _persistent_cache_key()'s own docstring for why
                # this single mechanism also satisfies Phase 8b's grouping goal.
                cache_key = _persistent_cache_key(decision, device_id, evidence_list)
                cached = persistent_cache.get(cache_key)

                entry: Dict[str, Any] = {
                    "decision_id": decision["decision_id"],
                    "device_id": device_id,
                    "decision_timestamp": decision["timestamp"],
                    "state": decision["state"],
                    "decision_path": decision["decision_path"],
                    "reviewed_at": time.time(),
                    "persistent_cache_key": cache_key,
                    # Release 14, Workstream 4: a representative destination, purely
                    # for GeoIP-enriched human-facing reporting (see
                    # _representative_destination()'s own docstring for the "not
                    # THE target, a first-pass heuristic" caveat) -- never sent to
                    # the LLM itself.
                    "destination": _representative_destination(evidence_list),
                }

                if cached is not None:
                    entry["recommendation"] = cached["recommendation"]
                    entry["validator_accepted"] = cached.get("validator_accepted")
                    entry["served_from_persistent_cache"] = True
                    cache_hits += 1
                elif queries_made >= max_queries:
                    # Query budget exhausted this run and no cache hit available --
                    # deferred to next run, matching v1's own FIFO-fairness
                    # discipline (still a candidate next time, since nothing is
                    # written for it here).
                    continue
                else:
                    rep_tier = _rep_tier_for(evidence_list)
                    ground_truth = build_ground_truth(decision["raw_payload"], evidence_list, rep_tier=rep_tier)
                    prompt_text = build_evidence_prompt(
                        device_id, evidence_list,
                        candidate_hypotheses=ground_truth.get("candidate_hypotheses"),
                    )
                    recommendation = client.query_full_analysis(prompt_text)
                    queries_made += 1
                    if recommendation is None:
                        entry["llm_error"] = "no_response_or_unparseable"
                        errors += 1
                    else:
                        entry["recommendation"] = recommendation
                        entry["validator_accepted"] = validator.validate(
                            recommendation, evidence_list,
                            original_risk=decision.get("risk_score"),
                            ground_truth=ground_truth,
                        )
                        # Populate the in-memory cache immediately -- a LATER
                        # candidate in this SAME run sharing this key is already
                        # a cache hit by the time it's considered.
                        persistent_cache[cache_key] = entry

                out_f.write(json.dumps(entry) + "\n")
                reviewed += 1
                new_entries.append(entry)

        store.close()
        LOGGER.info(
            "LLM review complete: %d reviewed (%d from cache, %d real quer%s, %d error(s)), "
            "%d deferred to next run.", reviewed, cache_hits, queries_made,
            "y" if queries_made == 1 else "ies", errors, max(0, len(candidates) - reviewed),
        )
        write_job_health(state_dir, "live_llm_review", time.time() - run_start, extra={
            "reviewed": reviewed, "cache_hits": cache_hits, "queries_made": queries_made,
            "errors": errors, "deferred": max(0, len(candidates) - reviewed),
        })

        digest = build_llm_review_digest_message(new_entries, geoip_engine=geoip_engine)
        if digest:
            send_telegram(CONFIG, digest)
    except Exception as e:
        LOGGER.error("live_llm_review failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_llm_review", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
