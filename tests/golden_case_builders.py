"""Authoring source of the golden decision cases (src/argus/golden/cases.json). Not a test file (no test_ prefix).
The hand-written cases are built below; the scenario catalogue's cases (ids "scn:...") are compiled from
src/argus/golden/scenarios.json.

Each builder returns a GoldenCase WITHOUT a pin; `--out` decides every case with the current code, records the pin,
and writes the result to a separate file for review. cases.json itself only ever changes by a reviewed commit (see
argus/golden/guard.py). Running this again after a builder edit shows, per case, whether the frozen INPUT would change
-- an input change is reviewed like a pin change.

  python tests/golden_case_builders.py --out <scratch>/cases.json --reason "initial golden set"

Network-agnostic test data only: RFC 5737 / RFC 3849 addresses and RFC 2606 names.
"""
import argparse
import dataclasses
import json
import sys
from pathlib import Path
from types import MappingProxyType

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from argus.evidence.model import Evidence, NO_DESTINATION  # noqa: E402
from argus.golden import guard, scenarios  # noqa: E402
from argus.golden.guard import Expectation, GoldenCase  # noqa: E402
from argus.hypotheses.independence import family_for  # noqa: E402
from argus.ops.live_engine import CHAMPION_DEFAULTS, GatheredCycle, PeerStats, _ReputationCandidate  # noqa: E402
from intelligence.reputation.classifier import ReputationClassifier  # noqa: E402

T0 = 1_800_000_000.0
DEV = "golden-device"
C2 = "c2.example.net"
OTHER = "cdn.example.org"
FILES = "files.example.com"
EXT_IP = "203.0.113.45"
EXT_IP2 = "198.51.100.23"
LAN_PEER = "192.0.2.10"         # stands in for an internal target (documentation range, not RFC1918, on purpose)

_rc = ReputationClassifier()

# the attack-reaching bounds used below
ALERTS = Expectation(state_at_least="SUSPICIOUS")
NO_CONTAINMENT = (None,)
SINGLE_SOURCE = ("Known defect: one source alerts (SUSPICIOUS); owner decision 2026-10-14 puts a single source on the "
                 "watch list -- P2/P3 changes this pin.")


def ev(evidence_type, dest=NO_DESTINATION, value=1.0, confidence=0.9, age=0.0, provenance="", features=None):
    return Evidence(device_id=DEV, destination_id=dest, evidence_type=evidence_type,
                    independence_family=family_for(evidence_type), timestamp=T0 - age, source="golden",
                    confidence=confidence, value=value, provenance=provenance, features=dict(features or {}))


def rep(domain, **scores):
    """The reputation vector as the pipeline builds it (ReputationClassifier.classify on the raw scores)."""
    return _rc.classify(domain, **scores)


def neutral():
    return rep("unlisted.example")


def cycle(fresh=(), *, rep_vector=None, device_type="laptop", features=None, is_safe=False, familiarity=0.0,
          windowed=(), derived=(), peer=None, baseline=(), domain_age=()):
    return GatheredCycle(
        device_id=DEV, ts=T0, device_type=device_type, is_safe=is_safe, baseline_familiarity=familiarity,
        features=MappingProxyType(dict(features if features is not None else {"zeek_honeypot_hits": 0})),
        rep_vector=rep_vector if rep_vector is not None else neutral(), fresh_v2=tuple(fresh),
        windowed_v2=tuple(windowed), graph_derived=tuple(derived), peer_stats=peer, baseline_v2=tuple(baseline),
        domain_age_v2=tuple(domain_age),
        sources=MappingProxyType(scenarios.registry_sources("on")))


def case(case_id, title, kind, origin, gathered, expect, note=""):
    return GoldenCase(case_id=case_id, title=title, kind=kind, origin=origin, gathered=gathered,
                      params=CHAMPION_DEFAULTS, expect=expect, note=note)


def beacon(dest, confidence=0.95, subtag="persistent_single_target"):
    return ev("zeek_beaconing", dest, value=0.9, confidence=confidence,
              provenance=f"detector:threat_signals:zeek_beaconing:{subtag}:interval regular")


def tunnel(dest, subtag, confidence=0.95):
    return ev("dns_tunnel_v2", dest, value=1.0, confidence=confidence,
              provenance=f"detector:threat_signals:dns_tunnel_v2:{subtag}:shape")


def evasion(subtag, confidence=0.9):
    return ev("dns_evasion_anomaly", EXT_IP, value=1.0, confidence=confidence,
              provenance=f"detector:dns_evasion:{subtag}:unexplained connection")


def build_cases():
    cases = []
    add = cases.append

    # --- owner-named single-signal exceptions (honeypot, ARP spoofing, curated feed) -----------------------------
    add(case("exception_honeypot_contact", "A device contacts the internal decoy", "attack",
             "decision engine hard stop; owner decision 2026-10-14 (single-signal exception)",
             cycle([ev("honeypot_access", LAN_PEER)], features={"zeek_honeypot_hits": 1}),
             Expectation(state_at_least="CRITICAL", containment=("honeypot",))))
    add(case("exception_honeypot_verified_safe_device", "A verified-safe address touching the decoy", "boundary",
             "U2 (2026-10-14): only the verified address exempts, never a hostname",
             cycle([ev("honeypot_access", LAN_PEER)], features={"zeek_honeypot_hits": 1}, is_safe=True),
             Expectation(containment=NO_CONTAINMENT)))
    add(case("exception_arp_spoofing_fresh", "ARP spoofing seen this cycle", "attack",
             "decision engine hard stop; owner decision 2026-10-14",
             cycle([ev("arp_spoofing", LAN_PEER, confidence=1.0)]),
             Expectation(state_at_least="CRITICAL", containment=("arp_spoof",))))
    add(case("exception_arp_spoofing_stale", "ARP spoofing seen 200 s ago (past the 120 s hard-stop freshness)",
             "boundary", "hard-stop freshness (_HARD_STOP_FRESHNESS_SECONDS)",
             cycle([ev("arp_spoofing", LAN_PEER, confidence=1.0, age=200.0)]),
             Expectation(containment=NO_CONTAINMENT)))
    add(case("exception_verified_feed_ioc", "A curated feed names the exact destination", "attack",
             "tier-5 verified IOC (ti score above the floor); owner decision 2026-10-14",
             cycle([ev("zeek_beaconing", C2, confidence=0.5,
                       provenance="detector:threat_signals:zeek_beaconing:low_and_slow:x")],
                   rep_vector=rep(C2, ti_score=3.5)),
             Expectation(state_at_least="CRITICAL", containment=("verified_feed_ioc",))))

    # --- reputation without a feed match ---------------------------------------------------------------------------
    add(case("reputation_abuse_score_only", "A crowd-sourced abuse score alone (tier 5, not a feed)", "boundary",
             "tier5_uncorroborated (third-party review 2026-09-09)",
             cycle([], rep_vector=rep(EXT_IP, abuse_score=4.5)),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("reputation_abuse_score_corroborated",
             "A crowd-sourced abuse score (tier 5) on the address a device exfiltrates to, with its own reputation hit",
             "attack", "tier5_corroborated (CRITICAL needs the same two families as HIGH)",
             cycle([ev("zeek_exfiltration", EXT_IP, value=5e8, confidence=0.95), ev("reputation", EXT_IP, value=5.0)],
                   rep_vector=rep(EXT_IP, abuse_score=4.5)),
             Expectation(state_at_least="HIGH")))
    add(case("reputation_weak_single_score", "One weak reputation score (tier 4) and nothing else", "boundary",
             "tier4_unconfirmed; real-world regression 'GOLDEN CASE' (abuse 3.78 below the 4.0 bar)",
             cycle([], rep_vector=rep(EXT_IP, abuse_score=3.78)),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT),
             note="Known defect, owner decision 2026-10-14: a single source belongs on the watch list, not an alert "
                  "-- P2/P3 moves this to the watch list; that pin change is expected then."))
    add(case("reputation_weak_signal_plus_feed_score",
             "One weak DNS-rate signal plus a threat-intel score of 1.5", "boundary",
             "MASTER_TODO 0d 'Found while working' (measured while building U7)",
             cycle([ev("dns_rate", value=30.0, confidence=0.8)], rep_vector=rep(EXT_IP, ti_score=1.5)),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT),
             note="Known defect: SUSPICIOUS on one weak signal + one feed score; the owner decision puts this on the "
                  "watch list (P2/P3)."))

    # --- corroboration-gated hard stops (geofence, Suricata) -------------------------------------------------------
    add(case("geofence_alone", "A geofencing policy violation with no behavioural evidence", "boundary",
             "real alert paperless Geofencing x4; G6 fix",
             cycle([ev("geofencing_violation", EXT_IP, confidence=1.0)]),
             Expectation(state_at_most="HIGH", containment=NO_CONTAINMENT)))
    add(case("geofence_with_beacon", "Geofence violation plus a regular beacon to the same address", "attack",
             "phase 38 section I (corroborated geofence)",
             cycle([ev("geofencing_violation", EXT_IP, confidence=1.0), beacon(EXT_IP)]),
             ALERTS))
    add(case("suricata_lone_severity1", "One severity-1 Suricata rule match, nothing else", "boundary",
             "policy 2026-09-10 (a lone rule match never blocks); real-world regression SYNTHETIC Suricata",
             cycle([ev("suricata_signature_match", EXT_IP, confidence=0.95)]),
             Expectation(state_at_most="HIGH", containment=NO_CONTAINMENT)))
    add(case("suricata_with_lateral_scan", "Suricata match plus an internal lateral scan", "attack",
             "real-world regression SYNTHETIC Suricata (corroborated)",
             cycle([ev("suricata_signature_match", EXT_IP, confidence=0.95),
                    ev("zeek_lateral_scan", NO_DESTINATION, value=12.0, confidence=0.9)]),
             Expectation(state_at_least="HIGH")))

    # --- behaviour: single family stays below HIGH, two related families reach it ---------------------------------
    add(case("dga_alone", "A strong DGA burst with no corroborating family", "boundary",
             "phase 38 section K (single source stays SUSPICIOUS)",
             cycle([ev("dns_dga_burst", C2, value=18.0, confidence=0.95),
                    ev("dns_rate", value=150.0, confidence=0.9)]),
             Expectation(state_at_least="SUSPICIOUS", state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("dga_with_reputation_same_domain", "DGA burst and a reputation hit on the same domain", "attack",
             "phase 38 section K (corroborated)",
             cycle([ev("dns_dga_burst", C2, value=18.0, confidence=0.95), ev("reputation", C2, value=4.0)],
                   rep_vector=rep(C2, vt_score=1.0)),
             Expectation(state_at_least="HIGH")))
    add(case("dga_with_reputation_other_domain", "DGA burst plus a reputation hit about a DIFFERENT domain",
             "boundary", "Gap-64 destination linkage (phase 38 section K, 'the fix')",
             cycle([ev("dns_dga_burst", C2, value=18.0, confidence=0.95), ev("reputation", OTHER, value=4.0)],
                   rep_vector=rep(OTHER, vt_score=1.0)),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("lateral_scan_with_arp_sweep", "Internal lateral scan corroborated by an ARP host sweep", "attack",
             "phase 38 section G", cycle([ev("zeek_lateral_scan", NO_DESTINATION, value=12.0, confidence=0.9),
                                          ev("arp_sweep", NO_DESTINATION, value=30.0, confidence=0.9)]),
             Expectation(state_at_least="HIGH", containment=("corroborated",))))
    add(case("lateral_scan_alone", "Internal lateral scan, one family", "boundary", "phase 38 section G guard",
             cycle([ev("zeek_lateral_scan", NO_DESTINATION, value=12.0, confidence=0.9)]),
             Expectation(state_at_least="SUSPICIOUS", state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("exfil_with_beacon_same_sensor", "Exfiltration volume and beaconing to one address (both Zeek)",
             "boundary", "B6 (2026-10-01): Zeek-derived families count once",
             cycle([ev("zeek_exfiltration", EXT_IP, value=5e8, confidence=0.95), beacon(EXT_IP)]),
             Expectation(state_at_least="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("exfil_with_reputation_same_destination", "Exfiltration to an address with its own reputation hit",
             "attack", "DATA_EXFILTRATION anchor rule (2026-09-28)",
             cycle([ev("zeek_exfiltration", EXT_IP, value=5e8, confidence=0.95), ev("reputation", EXT_IP, value=4.0)],
                   rep_vector=rep(EXT_IP, vt_score=1.0)),
             Expectation(state_at_least="HIGH")))
    add(case("exfil_with_reputation_unrelated", "Exfiltration, plus a reputation hit on an unrelated destination",
             "boundary", "real alert: DATA_EXFILTRATION 'corroborated' by an unrelated storage bucket (2026-09-28)",
             cycle([ev("zeek_exfiltration", EXT_IP, value=5e8, confidence=0.95),
                    ev("reputation", FILES, value=4.0)], rep_vector=rep(FILES, vt_score=1.0)),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("exfil_young_domain_lift", "Corroborated exfiltration to a domain registered just before first use",
             "attack", "domain age lift (2b, MASTER_TODO M2)",
             cycle([ev("zeek_exfiltration", FILES, value=5e8, confidence=0.7), ev("reputation", FILES, value=4.0)],
                   rep_vector=rep(FILES, vt_score=1.0),
                   domain_age=[ev("domain_age_young", FILES, confidence=0.5)]),
             Expectation(state_at_least="HIGH")))
    add(case("beacon_with_malicious_ja3", "A regular beacon plus a known-bad TLS fingerprint on the same flow",
             "attack", "C2_BEACONING corroboration",
             cycle([beacon(C2), ev("malicious_ja3", C2, confidence=0.9, provenance="ja3:0123456789abcdef")]),
             ALERTS, note="B6: tls_fingerprint and data_transfer_pattern are one sensor (Zeek) and count once."))
    add(case("dns_tunnel_two_signals_with_reputation", "Two distinct DNS-tunnel shapes plus a reputation hit",
             "attack", "real alert home-router DNS_COVERT_TUNNELING (corroborated variant)",
             cycle([tunnel(C2, "encoded_labels"), tunnel(C2, "entropy_fanout"), ev("reputation", C2, value=4.0)],
                   rep_vector=rep(C2, vt_score=1.0)),
             Expectation(state_at_least="HIGH")))
    add(case("dns_tunnel_single_shape", "One DNS-tunnel shape, nothing else", "boundary",
             "real alert home-router DNS_COVERT_TUNNELING (single)",
             cycle([tunnel(C2, "encoded_labels", confidence=0.7)]),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("dns_policy_bypass_alone", "Direct DNS to an unknown resolver, nothing else", "boundary",
             "phase 38 section F (naming split)", cycle([evasion("policy_bypass")]),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("dns_attribution_gap_alone", "Ambiguous DNS attribution gap (capped)", "boundary",
             "DNS_ATTRIBUTION_GAP cap (third-party review 2026-09-09)", cycle([evasion("partial_attribution_gap")]),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))

    # --- cross-device and cohort signals ---------------------------------------------------------------------------
    add(case("coordinated_targeting_with_dga", "Three devices reach the same new domain; this one also shows DGA",
             "attack", "N4 coordinated targeting",
             cycle([ev("dns_dga_burst", C2, value=18.0, confidence=0.95)],
                   derived=[Evidence(device_id=DEV, destination_id=C2, evidence_type="coordinated_targeting",
                                     independence_family="cross_device_correlation", timestamp=T0,
                                     source="v13_live_engine", confidence=1.0, value=3.0,
                                     provenance="v13_live_engine:coordinated_targeting",
                                     features={"other_devices": ["golden-peer-1", "golden-peer-2"]})]),
             ALERTS))
    add(case("peer_deviation_alone", "Talks to far more destinations than its peers, nothing attack-shaped",
             "benign", "owner decision 2026-10-03 (peer deviation is context only)",
             cycle([], peer=PeerStats("laptop", 120, 10.0, 5)),
             Expectation(state_at_most="ANOMALOUS", containment=NO_CONTAINMENT)))
    add(case("peer_deviation_with_port_scan", "Peer deviation together with an outbound port scan", "attack",
             "real alert test-device-1 PEER_COHORT_DEVIATION (corroborated shape)",
             cycle([ev("zeek_conn_abuse", NO_DESTINATION, value=40.0, confidence=0.9)],
                   peer=PeerStats("laptop", 120, 10.0, 5)),
             ALERTS))

    # --- time: what is old does not count -------------------------------------------------------------------------
    add(case("stale_window_evidence_not_counted",
             "One fresh DGA burst; the second family is a 20-min-old window item", "boundary",
             "freshness filter on the counted families (2026-09-10); real-world regression 'one stale'",
             cycle([ev("dns_dga_burst", C2, value=18.0, confidence=0.95)],
                   windowed=[ev("zeek_lateral_scan", NO_DESTINATION, value=12.0, confidence=0.9, age=1200.0)]),
             Expectation(state_at_most="SUSPICIOUS", containment=NO_CONTAINMENT)))
    add(case("propagated_reputation_within_ttl", "A cached tier-5 reputation for this destination, 2 h old",
             "boundary", "reputation propagation (Phase 1a), TTL a tunable",
             cycle([ev("dns_dga_burst", C2, value=18.0, confidence=0.95)],
                   derived=[_ReputationCandidate(C2, 5.0, T0 - 7200.0)]),
             Expectation(state_at_least="SUSPICIOUS"),
             note="Carry-over the design removes (R2, design E: no 24 h carry-over) -- P1/P2 change this pin."))

    # --- harmless confounders ---------------------------------------------------------------------------------------
    add(case("benign_smart_tv_local_service", "A smart TV's routine high DNS rate to a local-name service", "benign",
             "phase 38 section A (expected high-volume category, trusted destination)",
             cycle([ev("dns_rate", value=35.0, confidence=0.8)], device_type="smart_tv",
                   rep_vector=rep("media-hub.home.arpa")),
             Expectation(state_at_most="ANOMALOUS", containment=NO_CONTAINMENT)))
    add(case("benign_familiar_destination_iot", "An IoT device's usual destination (familiarity 0.8)", "benign",
             "phase 38 section B (learned familiarity)",
             cycle([ev("dns_rate", value=35.0, confidence=0.8)], device_type="iot", familiarity=0.8),
             Expectation(state_at_most="ANOMALOUS", containment=NO_CONTAINMENT)))
    add(case("benign_weak_zeek_notices", "Only weak Zeek notices (capture artefacts)", "benign",
             "weak notice tier (2026-09-09; 68,575 real rows of one artefact)",
             cycle([ev("zeek_notice_weak", EXT_IP, confidence=0.5, provenance="weird:data_before_established"),
                    ev("zeek_notice_weak", EXT_IP2, confidence=0.5, provenance="weird:data_before_established")]),
             Expectation(state_at_most="ANOMALOUS", containment=NO_CONTAINMENT)))
    add(case("benign_local_discovery", "Local discovery traffic (mDNS/SSDP)", "benign",
             "LocalDeviceDiscoveryHypothesis", cycle([ev("local_device_discovery", NO_DESTINATION, value=4.0)]),
             Expectation(state_at_most="ANOMALOUS", containment=NO_CONTAINMENT)))
    add(case("benign_context_only", "First contact with a young domain and a baseline deviation, nothing else",
             "benign", "context families never corroborate (NON_ATTACK_FAMILIES)",
             cycle([], derived=[ev("first_contact", FILES)],
                   baseline=[ev("baseline_deviation", NO_DESTINATION, value=3.2, confidence=0.7,
                                provenance="baseline:gaussian:dns_rate")],
                   domain_age=[ev("domain_age_young", FILES, confidence=0.5)]),
             Expectation(state_at_most="ANOMALOUS", containment=NO_CONTAINMENT)))
    add(case("benign_ml_anomaly_only", "An ML anomaly score alone", "benign", "ml_anomaly path",
             cycle([ev("ml_anomaly", NO_DESTINATION, value=0.95, confidence=0.9)]),
             Expectation(state_at_most="ANOMALOUS", containment=NO_CONTAINMENT)))
    add(case("benign_nothing", "No evidence at all", "benign", "baseline",
             cycle([]), Expectation(state_at_most="BENIGN", containment=NO_CONTAINMENT)))

    # the cases that alert today on one counted source -- each pin moves when the watch list arrives (P2/P3)
    single_source = {
        "reputation_abuse_score_only", "dga_alone", "dga_with_reputation_other_domain", "lateral_scan_alone",
        "exfil_with_beacon_same_sensor", "exfil_with_reputation_unrelated", "dns_tunnel_single_shape",
        "dns_policy_bypass_alone", "dns_attribution_gap_alone", "stale_window_evidence_not_counted",
        "peer_deviation_with_port_scan",
    }
    return [dataclasses.replace(c, note=" ".join(filter(None, (c.note, SINGLE_SOURCE))))
            if c.case_id in single_source else c for c in cases]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, help="where to write the proposed cases file (never cases.json)")
    parser.add_argument("--reason", required=True, help="recorded on every new or changed pin")
    args = parser.parse_args(argv)
    if Path(args.out).resolve() == guard.DEFAULT_CASES_PATH.resolve():
        parser.error("write a proposal elsewhere; review it; then replace cases.json in a commit")
    # hand-written cases + every active scenario of the catalogue, compiled (argus/golden/scenarios.py)
    built = build_cases() + scenarios.compile_all(scenarios.load_scenarios())
    try:
        existing = {c.case_id: c for c in guard.load_cases()}
    except FileNotFoundError:
        existing = {}
    out = []
    for c in built:
        old = existing.get(c.case_id)
        if old is not None:
            if json.dumps(guard.gathered_to_json(old.gathered), sort_keys=True) != \
                    json.dumps(guard.gathered_to_json(c.gathered), sort_keys=True):
                print(f"{c.case_id}: INPUT CHANGED (review the gathered diff)")
            c = dataclasses.replace(c, pinned=old.pinned, pinned_reason=old.pinned_reason)
        result = guard.run_case(c, check_pins=True)
        if not result.summary:
            print(f"{c.case_id}: decide() failed: {result.violations}")
            return 1
        if result.pin_diff:
            c = dataclasses.replace(c, pinned=result.summary, pinned_reason=args.reason)
        s = result.summary
        flag = " BOUNDS VIOLATED: " + "; ".join(guard.check_expectation(c.expect, s)) \
            if guard.check_expectation(c.expect, s) else ""
        print(f"{c.case_id:45s} {s['state']:10s} {s['decision_path']:26s} src={s['independent_sources']} "
              f"fam={s['evidence_families']} contain={s['containment_basis']} "
              f"atk={s['attack_hypothesis']} ben={s['benign_hypothesis']}{flag}")
        out.append(c)
    removed = sorted(set(existing) - {c.case_id for c in out})
    for case_id in removed:
        print(f"{case_id}: REMOVED (no builder)")
    Path(args.out).write_text(guard.dump_cases(out), encoding="utf-8", newline="\n")
    print(f"{len(out)} case(s) written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
