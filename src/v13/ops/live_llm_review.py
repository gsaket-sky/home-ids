"""
live_llm_review.py - schedules v13's own LLM-review (src/v13/llm_review/) against
`.94`'s own live graph (v13 full-architecture plan, Phase 5).

DESIGN DECISION (2026-09-07, user confirmed): batch-script shape, mirroring how
scripts/ollama_soc.py already runs -- NOT in-cycle invocation from pipeline.py. Lower
risk, ships the JSON-schema-constrained-decoding fix without touching the live 2s
poll loop's timing at all. In-cycle invocation stays a real, separately-scoped future
option if the batch-script's own results (once compared against ollama_soc.py's) show
it's worth the added complexity.

RUNS ALONGSIDE scripts/ollama_soc.py, NOT a replacement for it (config key
"ollama_soc", still enabled, unchanged). ollama_soc.py has several real, currently-
used features this script deliberately does NOT have yet: persistent alert
dedup/grouping across noisy repeats, cross-device campaign correlation, Telegram
digest building, and GeoIP-enriched reporting. Writes to its OWN file
(state/ollama_analysis_v13.jsonl), never touching ollama_soc.py's own
state/ollama_analysis_cache.json, so the two can be compared on real decisions
without either overwriting the other -- the explicit point of this phase, per the
plan: confirm parity/improvement before ever considering retiring ollama_soc.py.

WHAT IT REVIEWS: v13's own decisions (state/v13_graph.db), not v-current's
alerts.json -- v13's DeterministicValidator.build_ground_truth() is already built to
consume a v13 DecisionEngine.evaluate() result + Evidence list directly (see that
module's own docstring), not v-current's alert_payload dict shape. Reviews every
SUSPICIOUS/HIGH/CRITICAL decision from the lookback window that hasn't been reviewed
yet (tracked by decision_id in the output file itself -- no separate cache needed),
up to a per-run cap.

RATE LIMITING: DEFAULT_MAX_QUERIES_PER_RUN mirrors ollama_soc.py's own
DEFAULT_MAX_QUERIES_PER_RUN (5) exactly, same reasoning (each call can take up to
OllamaClient's own 900s worst-case timeout, so 5 bounds a single run to a sane worst
case regardless of how many decisions are pending). Calls are made strictly one at a
time in a plain sequential loop -- never threaded/async -- respecting the standing
"never send more than one in-flight request to `.94`'s own Ollama (-np 1)" rule by
construction, not by an explicit lock (nothing in this process ever issues a second
request before the first returns).

NOT PORTED from ollama_soc.py in this pass, consistent with the plan's own scope cut
(each a real, separately-scoped follow-up once this basic wiring is confirmed
working): local-model triage pre-filtering (OllamaClient.query_triage() exists and is
usable, but its own docstring says specificity isn't validated yet -- skipping it
avoids risking a real miss for a filter that wouldn't reduce call volume much anyway),
persistent cross-run alert dedup/grouping, campaign correlation, Telegram
notification, job-health per-device breakdown.
"""
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, Optional, Set

import sys
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from config import CONFIG  # noqa: E402
from utils import write_job_health  # noqa: E402
from v13.graph.store import GraphStore  # noqa: E402
from v13.graph.window import RollingWindowView  # noqa: E402
from v13.llm_review.ollama_client import OllamaClient, build_evidence_prompt  # noqa: E402
from v13.llm_review.validator import DeterministicValidator, build_ground_truth  # noqa: E402

LOGGER = logging.getLogger("live_llm_review")

# Matches scripts/ollama_soc.py's own DEFAULT_MAX_QUERIES_PER_RUN exactly -- same
# reasoning (bounds one run to a sane worst-case wall-clock time regardless of how
# many decisions are pending).
DEFAULT_MAX_QUERIES_PER_RUN = 5

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


def main() -> None:
    run_start = time.time()
    state_dir = Path(CONFIG.get("state_path", "state/ids_state.json")).parent
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

        now = time.time()
        already_reviewed = _load_already_reviewed(output_path)
        candidates = [
            d for d in store.get_decisions_since(now - LOOKBACK_SECONDS)
            if d["state"] in _REVIEWABLE_STATES and d["decision_id"] not in already_reviewed
        ]
        # Oldest first -- review the longest-waiting decisions before newer ones,
        # matching a simple FIFO fairness policy across runs when the cap is hit.
        candidates.sort(key=lambda d: d["timestamp"])

        reviewed = 0
        errors = 0
        with open(output_path, "a", encoding="utf-8") as out_f:
            for decision in candidates[:max_queries]:
                device_id = decision["device_id"]
                evidence_list = window.evidence_in_window(
                    device_id, RollingWindowView.LONG_WINDOW_SECONDS, now=decision["timestamp"],
                )
                rep_tier = _rep_tier_for(evidence_list)
                ground_truth = build_ground_truth(decision["raw_payload"], evidence_list, rep_tier=rep_tier)
                prompt_text = build_evidence_prompt(
                    device_id, evidence_list,
                    candidate_hypotheses=ground_truth.get("candidate_hypotheses"),
                )

                recommendation = client.query_full_analysis(prompt_text)
                entry: Dict[str, Any] = {
                    "decision_id": decision["decision_id"],
                    "device_id": device_id,
                    "decision_timestamp": decision["timestamp"],
                    "state": decision["state"],
                    "decision_path": decision["decision_path"],
                    "reviewed_at": time.time(),
                }
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
                out_f.write(json.dumps(entry) + "\n")
                reviewed += 1

        store.close()
        LOGGER.info(
            "LLM review complete: %d reviewed (%d error(s)), %d deferred to next run "
            "(query cap %d).", reviewed, errors, max(0, len(candidates) - reviewed), max_queries,
        )
        write_job_health(state_dir, "live_llm_review", time.time() - run_start, extra={
            "reviewed": reviewed, "errors": errors,
            "deferred": max(0, len(candidates) - reviewed),
        })
    except Exception as e:
        LOGGER.error("live_llm_review failed: %s", e, exc_info=True)
        write_job_health(state_dir, "live_llm_review", time.time() - run_start, extra={"error": str(e)})


if __name__ == "__main__":
    main()
