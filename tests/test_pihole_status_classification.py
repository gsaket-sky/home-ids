"""
Pi-hole NXDOMAIN / blocked classification and the automatic re-learn of everything learned from the old one
(master TODO B, W-04 finding; 2026-10-05).

- NXDOMAIN is reply_type 2 only. FTL status 3 ("answered from cache") and 12/13 (retries) used to count as NXDOMAIN.
- Blocked is Pi-hole's documented set (adds 9, 11, 15, 16, 18), and wins over an NXDOMAIN reply.
- Stores that learned the two ratios under the old scheme start over on their own: per-device EWMA baselines,
  IsolationForest models, argus Beta trackers (versioned keys). All re-learn in the quiet direction.

Not part of the pytest suite -- run directly:
`venv/Scripts/python.exe tests/test_pihole_status_classification.py`
"""
import sqlite3
import sys
import tempfile
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from extractors.pihole_codes import (  # noqa: E402
    BLOCKED_STATUSES, NXDOMAIN_STATUSES, DNS_RATIO_SCHEME, classify_status, ratio_metric_key,
)
from extractors import dns_features  # noqa: E402
from extractors.dns_features import PiHoleCollector  # noqa: E402
from core.state import DeviceState, EWMABaseline  # noqa: E402

FORWARDED, CACHE, RETRIED, RETRIED_DNSSEC, STALE_CACHE = 2, 3, 12, 13, 17
REPLY_IP, REPLY_NXDOMAIN, REPLY_NODATA = 4, 2, 1


def is_nx(status, reply):
    return classify_status(status, reply) in NXDOMAIN_STATUSES


def is_blocked(status, reply):
    return classify_status(status, reply) in BLOCKED_STATUSES


# --- the classification ---------------------------------------------------------------------------------------------

check("a cache hit with an answer is not NXDOMAIN (the old bug: status 3 counted)", not is_nx(CACHE, REPLY_IP))
check("retried queries with an answer are not NXDOMAIN (old bug: 12/13 counted)",
      not is_nx(RETRIED, REPLY_IP) and not is_nx(RETRIED_DNSSEC, REPLY_IP))
check("a forwarded query answered NXDOMAIN is NXDOMAIN", is_nx(FORWARDED, REPLY_NXDOMAIN))
check("a cached NXDOMAIN answer is NXDOMAIN", is_nx(CACHE, REPLY_NXDOMAIN))
check("a stale-cache NXDOMAIN answer is NXDOMAIN", is_nx(STALE_CACHE, REPLY_NXDOMAIN))
check("NODATA (the name exists, no record of that type) is not NXDOMAIN", not is_nx(FORWARDED, REPLY_NODATA))
check("a gravity block answered with NXDOMAIN (blocking mode) is blocked, not NXDOMAIN",
      is_blocked(1, REPLY_NXDOMAIN) and not is_nx(1, REPLY_NXDOMAIN))
check("Pi-hole's documented blocked statuses are all blocked (adds CNAME 9/11, busy 15, special 16, EDE15 18)",
      all(is_blocked(s, REPLY_IP) for s in (1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18)))
check("allowed statuses are never blocked",
      not any(is_blocked(s, REPLY_IP) for s in (0, 2, 3, 12, 13, 14, 17)))
check("without a reply_type (older FTL) nothing is NXDOMAIN -- no signal, not a guess",
      not is_nx(FORWARDED, 0) and not is_nx(CACHE, None))
check("junk values classify safely", classify_status(None, "x") == 0 and classify_status("2", "2") in NXDOMAIN_STATUSES)
check("the reader-assigned NXDOMAIN code can never be an FTL status", all(s < 0 for s in NXDOMAIN_STATUSES))
check("dns_features uses the shared sets", dns_features.BLOCKED is BLOCKED_STATUSES
      and dns_features.NXDOMAIN is NXDOMAIN_STATUSES)

# --- the reader, against a real FTL-shaped database -------------------------------------------------------------------

tmpdir = _PathForSysPath(tempfile.mkdtemp(prefix="pihole_codes_test_"))
db = tmpdir / "pihole-FTL.db"
conn = sqlite3.connect(str(db))
conn.execute("PRAGMA journal_mode=WAL")   # FTL's database is WAL; the reader opens it read-only and expects that
conn.execute("CREATE TABLE queries (id INTEGER PRIMARY KEY, timestamp INTEGER, type INTEGER, status INTEGER, "
             "domain TEXT, client TEXT, forward TEXT, reply_type INTEGER)")
conn.execute("CREATE TABLE network_addresses (ip TEXT, name TEXT)")
rows = [  # (status, reply_type, domain)
    (CACHE, REPLY_IP, "cached.example"),
    (RETRIED, REPLY_IP, "retried.example"),
    (FORWARDED, REPLY_NXDOMAIN, "missing.example"),
    (1, REPLY_NXDOMAIN, "ads.example"),
    (9, REPLY_IP, "cname-blocked.example"),
    (FORWARDED, REPLY_IP, "txt.example"),
    (FORWARDED, REPLY_IP, "null.example"),
]
QTYPES = {"txt.example": 7, "null.example": 110}     # FTL numbering: TXT = 7, NULL (wire 10) = 100 + 10
for i, (st, rt, dom) in enumerate(rows, start=1):
    conn.execute("INSERT INTO queries (id, timestamp, type, status, domain, client, reply_type) VALUES (?,?,?,?,?,?,?)",
                 (i, int(time.time()), QTYPES.get(dom, 1), st, dom, "192.0.2.10", rt))
conn.commit()
conn.close()

collector = PiHoleCollector(db_path=str(db), excluded_ips=[], excluded_patterns=[])
collector._last_heartbeat_write = time.time()   # no heartbeat file written by the test
polled = {r["domain"]: r for r in collector.poll()}
check("the reader returns every row", len(polled) == len(rows), str(sorted(polled)))
check("reader: cache hit and retry are neither NXDOMAIN nor blocked",
      all(polled[d]["status"] not in NXDOMAIN_STATUSES | BLOCKED_STATUSES for d in ("cached.example", "retried.example")))
check("reader: an NXDOMAIN answer is NXDOMAIN", polled["missing.example"]["status"] in NXDOMAIN_STATUSES)
check("reader: a block answered NXDOMAIN stays blocked", polled["ads.example"]["status"] in BLOCKED_STATUSES)
check("reader: a deep-CNAME block counts as blocked", polled["cname-blocked.example"]["status"] in BLOCKED_STATUSES)
check("reader: the raw FTL status is kept alongside", polled["cached.example"]["ftl_status"] == CACHE)
check("reader: the FTL query type is read from the type column",
      polled["txt.example"]["qtype"] == 7 and polled["null.example"]["qtype"] == 110
      and polled["cached.example"]["qtype"] == 1)

# --- dns_txt_null_ratio uses the query type, not the reply type ---------------------------------------------------------

from extractors.pihole_codes import TXT_NULL_QTYPES  # noqa: E402
check("TXT/NULL/ANY/MX/CNAME in FTL numbering", TXT_NULL_QTYPES == {7, 110, 3, 9, 105})
check("A and AAAA are not tunnel-shaped query types", not ({1, 2} & TXT_NULL_QTYPES))


def _txt_null_ratio(events):
    """events: (qtype, reply_type) per query; ratio computed by the real extractor over the 1-hour window."""
    st = DeviceState(device_id="d2", client_ip="192.0.2.20", hostname="h")
    now = time.time()
    for i, (qt, rt) in enumerate(events):
        st.rolling.long_events.append((now - 30, f"q{i}.example.net", classify_status(2, rt), qt))
    return dns_features.FeatureExtractor().compute(st, now, 300)["dns_txt_null_ratio"]


check("answered A queries with reply types 5 (DOMAIN) and 10 (OTHER) no longer count (the old mismeasure)",
      _txt_null_ratio([(1, 5)] * 5 + [(1, 10)] * 5) == 0.0)
check("TXT queries count whatever the reply was", _txt_null_ratio([(7, 4)] * 5 + [(1, 4)] * 5) == 0.5)
check("NULL (110) and ANY (3) queries count", _txt_null_ratio([(110, 4), (3, 4), (1, 4), (2, 4)]) == 0.5)
check("a database without the type column yields 0, not a guess", _txt_null_ratio([(0, 4)] * 6) == 0.0)

# --- re-learn: per-device EWMA baselines --------------------------------------------------------------------------------

learned = DeviceState(device_id="dev1", client_ip="192.0.2.10", hostname="h")
for _ in range(50):
    learned.nxdomain_baseline.update(0.35, 9)
    learned.blocked_baseline.update(0.10, 9)
    learned.rate_baseline.update(5.0, 9)
old = learned.to_dict()
old.pop("dns_ratio_scheme")  # a state saved before the scheme existed

restored = DeviceState.from_dict(old)
fresh = EWMABaseline()
check("old-scheme NXDOMAIN baseline starts over",
      restored.nxdomain_baseline.to_dict() == fresh.to_dict())
check("old-scheme blocked baseline starts over", restored.blocked_baseline.to_dict() == fresh.to_dict())
check("other baselines are kept", restored.rate_baseline.to_dict() == learned.rate_baseline.to_dict())
check("a saved state records the scheme", restored.to_dict().get("dns_ratio_scheme") == DNS_RATIO_SCHEME)
same = DeviceState.from_dict(learned.to_dict())
check("a current-scheme state keeps its NXDOMAIN/blocked baselines",
      same.nxdomain_baseline.to_dict() == learned.nxdomain_baseline.to_dict()
      and same.blocked_baseline.to_dict() == learned.blocked_baseline.to_dict())

# --- re-learn: IsolationForest models ------------------------------------------------------------------------------------

import joblib  # noqa: E402
from intelligence.ml_engine import MultiDeviceMLEngine, DeviceMLEngine, _SCHEME_ATTR  # noqa: E402

model_dir = tmpdir / "models"
ml = MultiDeviceMLEngine(model_dir=str(model_dir))
dev = DeviceMLEngine("devA")
feats = {"query_rate": 1.0, "entropy_avg": 2.0, "unique_domains": 3.0, "nxdomain_ratio": 0.1, "blocked_ratio": 0.0,
         "zeek_outbound_bytes": 0, "zeek_lateral_moves": 0, "zeek_s0_rej_count": 0, "zeek_app_protocol_weight": 0.2}
snapshot = [dev._extract_vector({**feats, "query_rate": float(i % 7)}) for i in range(80)]
dev._fit_worker(snapshot)
check("a fitted model records the scheme it learned under", getattr(dev.model, _SCHEME_ATTR, None) == DNS_RATIO_SCHEME)

joblib.dump(dev.model, model_dir / "devA.pkl")
legacy = dev.model
delattr(legacy, _SCHEME_ATTR)
joblib.dump(legacy, model_dir / "devB.pkl")
ml.load_models()
check("a current-scheme device model is loaded", "devA" in ml.devices and ml.devices["devA"].warmed_up)
check("an old-scheme device model is discarded and its file removed",
      "devB" not in ml.devices and not (model_dir / "devB.pkl").exists())
check("with no warm model the device scores 0 (quiet while re-learning)", ml.score("devB", feats) == 0.0)

# --- re-learn: argus Beta trackers use versioned keys ----------------------------------------------------------------

check("ratio metric keys are versioned", ratio_metric_key("nxdomain_ratio") == f"nxdomain_ratio_v{DNS_RATIO_SCHEME}")
from argus.ops import live_engine  # noqa: E402
check("the live Beta baselines store under the versioned keys",
      set(live_engine._BETA_INPUT_KEYS) == {ratio_metric_key("nxdomain_ratio"), ratio_metric_key("blocked_ratio")}
      and set(live_engine._BETA_INPUT_KEYS.values()) == {"nxdomain_ratio", "blocked_ratio"})

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
else:
    print("All Pi-hole status classification checks PASSED.")
