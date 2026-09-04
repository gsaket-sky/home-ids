"""
Standalone runtime test for Phase 57: evidence fingerprint + validator-schema
versioning for ollama_soc.py's persistent on-disk cache
(state/ollama_analysis_cache.json).

Root cause this closes (Documentation/DECISION_LOGIC_DEPENDENCY_MAP.md's Gap 6 root
cause, found 2026-09-04 via live SSH investigation against the production box): the
cache-hit branch in main() (`is_valid = bool(cached.get("validator_passed", False))`)
never re-ran DeterministicValidator.validate() -- it trusted whatever boolean was
frozen in at a cache entry's ORIGINAL write time, indefinitely (up to
DEFAULT_CACHE_TTL_SECONDS, longer still for a pattern kept alive via
withheld_history, which never touches `ts`). Confirmed live: the 3 real
immunizations and all 43 distinct cache entries behind the 15 withheld patterns from
the 2026-09-03 SOC report were all missing the Phase 51 structured-contract fields
(hypothesis/supporting_evidence/contradicting_evidence/missing_evidence/ttl_seconds)
entirely, yet carried `validator_passed: True` from whichever validator version
first computed them -- a DeterministicValidator upgrade had zero effect on any
already-cached pattern.

The fix: _cache_key() stays exactly as before (device|target|signature_base) and
keeps its existing job -- THIS RUN's in-memory grouping (`groups[...]`), where
minor feature fluctuation deliberately should NOT fragment the group. A new,
separate _persistent_cache_key() -- device|target|signature_base +
_evidence_fingerprint() (content hash of attack-shaped-evidence presence + a few
bucketed risk/entropy signals) + the current VALIDATOR_SCHEMA_VERSION (ai_soc.py) --
is what's actually used for the persistent `cache` dict's reads/writes. A genuine
evidence change (e.g. arp_sweep newly appearing) OR a validator logic upgrade now
each produce a different key, so the old entry is simply never looked up again --
no separate invalidation/migration pass needed, it ages out via the existing TTL
prune in _load_cache() like any other unused entry.

Not part of the pytest suite -- run directly:
`.venv/Scripts/python.exe tests/test_phase57_evidence_fingerprint.py`

Sections:
  A. _evidence_fingerprint() -- deterministic, stable under non-evidence-bearing
     jitter (query_rate/unique_domains), stable under sub-0.1 float jitter on
     bucketed signals, CHANGES when an attack-shaped presence signal appears/
     disappears, CHANGES when a bucketed signal crosses a 0.1 boundary
  B. _persistent_cache_key() -- combines _cache_key() + fingerprint + version;
     changes when VALIDATOR_SCHEMA_VERSION changes; independent of _cache_key()'s
     own stability (two payloads with the same device/target/signature but
     different evidence get different persistent keys)
  C. Source-level wiring checks in ollama_soc.py's main() -- every persistent
     cache read/write site uses pcache_key, not the bare grouping key; in-run
     grouping (`groups[...]`) still uses the bare key, unchanged
"""
import sys
import copy
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


import ollama_soc
from ollama_soc import _evidence_fingerprint, _persistent_cache_key, _cache_key
from intelligence.ai_soc import VALIDATOR_SCHEMA_VERSION


def _payload(device_id="dev1", ip="192.168.1.52", domain=None, signature="NETWORK_INTRUSION",
             features=None):
    return {
        "device": {"id": device_id, "ip": "192.168.1.99", "hostname": "some_device"},
        "network_context": {"destination_ip": ip, "queried_domain": domain},
        "signature": signature,
        "features": features or {},
    }


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: _evidence_fingerprint()
# ═══════════════════════════════════════════════════════════════════════════════════
print("--- Section A: _evidence_fingerprint() ---")

p_base = _payload(features={"ti_risk": 0.0, "abuseipdb_risk": 0.0, "vt_risk": 0.0,
                             "query_rate": 1.4, "unique_domains": 4})
fp_base = _evidence_fingerprint(p_base)

check("deterministic -- same payload content produces the same fingerprint",
      _evidence_fingerprint(copy.deepcopy(p_base)) == fp_base)

p_jittered_noise = _payload(features={"ti_risk": 0.0, "abuseipdb_risk": 0.0, "vt_risk": 0.0,
                                       "query_rate": 9.9, "unique_domains": 40})
check("stable under non-evidence-bearing feature jitter (query_rate/unique_domains "
      "aren't in the fingerprint's presence/bucketed key sets)",
      _evidence_fingerprint(p_jittered_noise) == fp_base)

p_jittered_bucket = _payload(features={"ti_risk": 0.04, "abuseipdb_risk": 0.0, "vt_risk": 0.0,
                                        "query_rate": 1.4, "unique_domains": 4})
check("stable under sub-0.1 float jitter on a bucketed signal (0.04 rounds to the "
      "same 0.0 bucket as the base payload's ti_risk)",
      _evidence_fingerprint(p_jittered_bucket) == fp_base)

p_new_attack_evidence = _payload(features={"ti_risk": 0.0, "abuseipdb_risk": 0.0, "vt_risk": 0.0,
                                            "query_rate": 1.4, "unique_domains": 4,
                                            "zeek_lateral_moves": 1})
fp_new_attack = _evidence_fingerprint(p_new_attack_evidence)
check("CHANGES when an attack-shaped presence signal newly appears (zeek_lateral_moves) "
      "-- the exact 'Fire TV suddenly does an ARP sweep' case this phase exists for",
      fp_new_attack != fp_base)

p_bucket_crossed = _payload(features={"ti_risk": 3.5, "abuseipdb_risk": 0.0, "vt_risk": 0.0,
                                       "query_rate": 1.4, "unique_domains": 4})
check("CHANGES when a bucketed signal crosses a real 0.1 boundary (ti_risk 0.0 -> 3.5)",
      _evidence_fingerprint(p_bucket_crossed) != fp_base)

check("fingerprint is a short, stable-length hex digest (not the full sha256, doesn't "
      "need to be -- collision risk is irrelevant here, this only needs to detect "
      "'did the evidence change', not serve as a cryptographic identity)",
      isinstance(fp_base, str) and len(fp_base) == 16
      and all(c in "0123456789abcdef" for c in fp_base))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B: _persistent_cache_key()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section B: _persistent_cache_key() ---")

pk_base = _persistent_cache_key(p_base)
pk_new_attack = _persistent_cache_key(p_new_attack_evidence)

check("_persistent_cache_key() embeds _cache_key()'s own grouping identity verbatim "
      "as a prefix -- doesn't discard the device|target|signature identity",
      pk_base.startswith(_cache_key(p_base) + "|"))

check("_persistent_cache_key() embeds the current VALIDATOR_SCHEMA_VERSION",
      pk_base.endswith(f"|v{VALIDATOR_SCHEMA_VERSION}"))

check("two payloads sharing the SAME _cache_key() (device/target/signature) but "
      "DIFFERENT evidence (new attack-shaped signal) get DIFFERENT persistent cache "
      "keys -- this is the actual fix: a stale cached verdict is no longer reachable "
      "once the underlying evidence genuinely changes",
      _cache_key(p_base) == _cache_key(p_new_attack_evidence)
      and pk_base != pk_new_attack)

check("two payloads with identical evidence but sharing the same _cache_key() "
      "produce the SAME persistent key (no spurious invalidation)",
      _persistent_cache_key(copy.deepcopy(p_base)) == pk_base)

_orig_version = ollama_soc.VALIDATOR_SCHEMA_VERSION
try:
    ollama_soc.VALIDATOR_SCHEMA_VERSION = _orig_version + 1
    pk_bumped = _persistent_cache_key(p_base)
    check("bumping VALIDATOR_SCHEMA_VERSION changes the persistent key for an "
          "otherwise-identical payload -- this is what makes every already-cached "
          "verdict unreachable the instant DeterministicValidator's logic changes, "
          "closing the Gap 6 root-cause bug (cache hits previously never re-validated)",
          pk_bumped != pk_base)
finally:
    ollama_soc.VALIDATOR_SCHEMA_VERSION = _orig_version


# ═══════════════════════════════════════════════════════════════════════════════════
# Section C: source-level wiring checks in ollama_soc.py's main()
# ═══════════════════════════════════════════════════════════════════════════════════
print("\n--- Section C: source-level wiring in main() ---")

_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")

check("pcache_key is computed once per loop iteration, from the representative payload",
      "pcache_key = _persistent_cache_key(representative)" in _src)

check("the persistent cache read uses pcache_key, not the bare grouping key",
      "cached = cache.get(pcache_key)" in _src)

check("the fresh-query cache write uses pcache_key",
      "cache[pcache_key] = {" in _src)

check("withheld_history read/write use pcache_key",
      'withheld_history = cache[pcache_key].setdefault("withheld_history", [])' in _src
      and 'cache[pcache_key]["withheld_history"] = withheld_history[-20:]' in _src)

check("every action_taken write uses pcache_key (3 sites: immunize-with-domain, "
      "immunize-no-domain/sigma-tune-down, confirmed-threat/sigma-tune-up)",
      _src.count('cache[pcache_key]["action_taken"] = True') == 3)

check("no leftover raw `cache[key]` or `cache.get(key)` persistent-cache access "
      "remains (in-run grouping via `groups[key]`/`groups[...]` is untouched and "
      "correctly still keys on the bare _cache_key(), not pcache_key)",
      "cache[key]" not in _src and "cache.get(key)" not in _src
      and "if key in cache" not in _src)

check("in-run grouping still uses the bare, coarse _cache_key() (unchanged -- repeat "
      "firings of the identical pattern within one run must still collapse into one "
      "Ollama call regardless of minor feature fluctuation)",
      "groups[_cache_key(payload)].append(payload)" in _src)

check("VALIDATOR_SCHEMA_VERSION is imported from ai_soc.py, not redefined locally "
      "(single source of truth)",
      "from intelligence.ai_soc import DeterministicValidator, VALIDATOR_SCHEMA_VERSION" in _src)

_ai_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "intelligence" / "ai_soc.py").read_text(encoding="utf-8")
check("VALIDATOR_SCHEMA_VERSION is actually defined in ai_soc.py",
      "VALIDATOR_SCHEMA_VERSION = " in _ai_soc_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 57 evidence-fingerprint checks PASSED.")
