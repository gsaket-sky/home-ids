"""
pihole_codes.py – Pi-hole FTL query-database codes, and the one classification of a query row that every DNS
feature uses (dns_features.py, pipeline.py, identity.py).

Source: https://docs.pi-hole.net/database/query-database/ (checked 2026-10-05).
- `status` says how Pi-hole handled the query. Blocked: 1 gravity, 4 regex, 5 exact denylist, 6-8 upstream,
  9-11 deep CNAME inspection, 15 database busy, 16 special domain, 18 upstream (EDE 15). Allowed: 2 forwarded,
  3 cache, 12-14 retried, 17 stale cache. A status says nothing about whether the name exists.
- `reply_type` says what the answer was: 2 = NXDOMAIN (the name does not exist), whatever `status` is.

Before 2026-10-05 the reader counted statuses {3, 12, 13} as NXDOMAIN -- every cache hit and retry -- and missed the
blocked statuses 9, 11, 15, 16 and 18 (and a query blocked with an NXDOMAIN reply counted as NXDOMAIN, not blocked).
Everything learned from nxdomain_ratio / blocked_ratio under that scheme is re-learned automatically: see
DNS_RATIO_SCHEME.
"""

# FTL's own query-type numbering (the `queries.type` column), NOT DNS wire numbers: 1 A, 2 AAAA, 3 ANY, 4 SRV, 5 SOA,
# 6 PTR, 7 TXT, 8 NAPTR, 9 MX, 10 DS, 11 RRSIG, 12 DNSKEY, 13 NS, 14 OTHER, 15 SVCB, 16 HTTPS; any other type is stored
# as 100 + its wire number (NULL, wire 10, is 110; CNAME, wire 5, is 105).
QTYPE_ANY, QTYPE_TXT, QTYPE_MX = 3, 7, 9
QTYPE_OTHER_OFFSET = 100
# Query types DNS tunnels favour (large free-form answers): TXT, NULL, ANY, MX, CNAME.
TXT_NULL_QTYPES = frozenset({QTYPE_TXT, QTYPE_OTHER_OFFSET + 10, QTYPE_ANY, QTYPE_MX, QTYPE_OTHER_OFFSET + 5})

BLOCKED_STATUSES = frozenset({1, 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 18})
REPLY_NXDOMAIN = 2

# Reader-assigned status for "not blocked, answered NXDOMAIN". Negative, so it can never collide with an FTL status.
NXDOMAIN_STATUS = -2
NXDOMAIN_STATUSES = frozenset({NXDOMAIN_STATUS})

# Version of how nxdomain_ratio and blocked_ratio are measured. Every store that learns from them records the version
# it learned under and starts over when it differs -- the per-device EWMA baselines (core/state.py), the
# IsolationForest models (intelligence/ml_engine.py) and the argus Beta baselines (ratio_metric_key()). No human step.
# Bump it whenever the classification below changes what the two ratios count.
DNS_RATIO_SCHEME = 2


def classify_status(ftl_status, reply_type) -> int:
    """The status the DNS features count: the FTL status when the query was blocked (even when the block was
    answered with NXDOMAIN), NXDOMAIN_STATUS when it was answered NXDOMAIN, otherwise the FTL status unchanged.
    Without a reply_type (older FTL databases) nothing is NXDOMAIN -- no signal rather than a guess."""
    try:
        status = int(ftl_status or 0)
    except (TypeError, ValueError):
        status = 0
    if status in BLOCKED_STATUSES:
        return status
    try:
        reply = int(reply_type or 0)
    except (TypeError, ValueError):
        reply = 0
    return NXDOMAIN_STATUS if reply == REPLY_NXDOMAIN else status


def ratio_metric_key(name: str) -> str:
    """Storage key for a learned baseline of nxdomain_ratio / blocked_ratio, versioned so a new scheme starts fresh
    instead of reading a change of measurement as a change of behaviour."""
    return f"{name}_v{DNS_RATIO_SCHEME}"
