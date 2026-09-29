"""
threat_signals.py - PHASE 1: Evidence detector for the scoring.py-derived signal
categories that previously had no path into the live hypothesis/evidence pipeline at all.

scoring.py computed DGA/algorithmic-domain bursts, real DNS tunneling signals (TXT/NULL
abuse, long labels, suspicious TLDs), exfiltration byte bursts, C2 beaconing periodicity,
and TCP connection-abuse/port-scan patterns — but scoring.py is dead code, never imported
by the live pipeline (confirmed via `grep -rn "RiskScorer" src/ tests/`). The live risk
path only ever went through DecisionEngine + HypothesisEngine, which only ever saw
dns_rate / dns_entropy / dns_unique_ratio / malicious_ja3 / malicious_ja4 / zeek_notice
evidence. Every one of those richer signal categories was being computed every cycle
(dns_extractor.compute() and zeek_fx.get_features() already produce all the raw numbers
below) and then silently discarded.

This detector reads that same already-computed `features` dict — no new feature
extraction, no new I/O — and turns each category into Evidence objects so the new
Phase 1 Hypothesis subclasses (DGAHypothesis, ExfiltrationHypothesis, BeaconingHypothesis,
DNSTunnelingV2Hypothesis, ConnectionAbuseHypothesis) in hypotheses/engine.py can actually
see them.
"""
import ipaddress
import time
from typing import Any, Dict, List, Optional

from intelligence.hypotheses.evidence import Evidence
from utils import is_telemetry_domain, _is_cdn_or_cloud_domain

# Same small curated list scoring.py used for "this outbound burst is probably a
# legitimate cloud-vendor sync, not exfiltration" — kept narrow and explicit rather than
# reusing the much broader general CDN allowlist, since this one specifically dampens an
# exfiltration signal and a broad match here would create a real blind spot.
_VENDOR_CLOUD_API_DOMAINS = (
    "coinbase.com", "microsoft.com", "apple.com", "amazonaws.com", "google.com",
    "azure.com", "cloudflare.com", "fritz.box", "github.com", "sentry.io",
)


def _is_local_dest(ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_link_local or ip_obj.is_loopback or ip_obj.is_reserved:
            return True
        if ip_obj.version == 4 and str(ip_obj).endswith(".255"):
            return True
        return False
    except ValueError:
        return False


class ThreatSignalDetector:
    def detect(self, device: str, features: Dict[str, Any], top_domain: Optional[str] = None,
               arp_sweep_threshold: int = 8, conn_abuse_unique_ip_threshold: int = 5,
               long_conn_duration_threshold: float = 14400.0, ti_engine=None) -> List[Evidence]:
        ev_list: List[Evidence] = []
        now = time.time()

        top_domain = (top_domain or "").lower().strip(".")
        # BUGFIX (live audit): is_telemetry_domain() alone is the same hardcoded-list
        # shape as the CDN check above. ti_engine.is_pihole_gravity_domain() (optional,
        # None-safe) adds your OWN Pi-hole's already-maintained ad/tracker gravity
        # classification -- a domain Pi-hole itself already recognizes as ad/telemetry
        # is real, regularly-updated evidence this is routine traffic, not a hardcoded
        # guess. A gravity lookup failure (Pi-hole unreachable, timeout) returns None,
        # not False -- correctly falls through to just the static list, never treated
        # as "confirmed not telemetry."
        is_telemetry = bool(top_domain) and (
            is_telemetry_domain(top_domain) or bool(ti_engine and ti_engine.is_pihole_gravity_domain(top_domain))
        )
        is_vendor_cloud_api = bool(top_domain) and any(top_domain.endswith(d) for d in _VENDOR_CLOUD_API_DOMAINS)

        # BUGFIX (live audit): _is_cdn_or_cloud_domain() alone is a fully hardcoded,
        # disconnected check -- kept needing one-off patches every time a legitimate
        # domain wasn't already enumerated (nflximg.com, samsungqbe.com, both found only
        # after already false-positiving live). ti_engine.is_allowlisted() layers in the
        # live Tranco popularity feed + the persisted CL-AFPE self-healing trust cache
        # (a domain corrected once via "Mark False Positive" stops needing a manual
        # code patch here), same pattern dns_evasion.py's _reverse_dns_explains() now
        # uses. ti_engine is optional (None-safe) so this stays a no-op for any caller
        # that doesn't have one wired.
        def is_known_safe_domain(domain: Optional[str]) -> bool:
            if not domain:
                return False
            if _is_cdn_or_cloud_domain(domain):
                return True
            return bool(ti_engine and ti_engine.is_allowlisted(domain))

        def add(etype: str, value: float, confidence: float, group: str, note: str,
                subtag: Optional[str] = None, domain: Optional[str] = None) -> None:
            # `subtag` is a STABLE category tag (e.g. "txt_null_abuse") distinct from the
            # free-text `note`, which contains cycle-to-cycle-varying numbers. Hypotheses
            # that need to count how many *distinct signal categories* fired (e.g.
            # DNSTunnelingV2Hypothesis's strong-score bonus for corroborating sub-signals)
            # must key off `subtag`, not raw provenance text — before this fix, every
            # dns_tunnel_v2 evidence item shared the exact same provenance prefix
            # ("detector:threat_signals:dns_tunnel_v2:") regardless of which of the three
            # tunneling checks fired, so the "2+ distinct categories" bonus could never
            # actually trigger (caught by test_phase1_hypotheses.py).
            tag = subtag or etype
            ev_list.append(Evidence(
                type=etype, source="threat_signals", timestamp=now, device=device,
                value=value, confidence=max(0.0, min(1.0, confidence)),
                independence_group=group, provenance=f"detector:threat_signals:{etype}:{tag}:{note}",
                domain=domain,
            ))

        # ── DGA / algorithmic-domain burst ──────────────────────────────────────────
        # BUGFIX (found via a third-party review of the full alerts.json history,
        # verified with a live repro): this whole block used to be gated on `is_telemetry`
        # -- computed from `top_domain`, the SAME unreliable "most notable domain in the
        # whole window" value flagged elsewhere in this file, not from any domain actually
        # involved in this evidence. That cut both ways: a device could have its DGA
        # evidence wrongly SUPPRESSED because some unrelated domain elsewhere in its
        # window happened to be telemetry-recognized (confirmed live: top_domain=
        # "mask.icloud.com" silently zeroed out evidence for a totally unrelated,
        # genuinely-suspicious domain), and conversely a real telemetry domain could still
        # get flagged if a DIFFERENT domain in the window wasn't telemetry-recognized.
        # suspicious_domains/suspicious_domain_examples now exclude telemetry domains at
        # the source (dns_features.py's per-domain loop, matching the pattern
        # tunneling_domains/fanout_by_base already used) -- so the two domain-example
        # branches below no longer need any device-wide gate at all. Only the pure
        # classifier-score branch (no specific domain, nothing to check at the source)
        # still needs SOME telemetry awareness, so it keeps its own explicit condition.
        sd = float(features.get("suspicious_domains", 0.0) or 0.0)
        entropy_avg = float(features.get("entropy_avg", 0.0) or 0.0)
        dga_score = float(features.get("dga_score", 0.0) or 0.0)
        # BUGFIX: dns_dga_burst is a device-wide AGGREGATE (a count of how many
        # recent domains looked DGA-like), so it never had any specific domain to
        # attach -- the alert's displayed target was always the unrelated "most
        # frequent domain in window" fallback (pipeline.py's _select_target_domain()),
        # no causal connection to which domain(s) actually looked suspicious.
        # dns_features.py's compute() now collects real examples in the SAME loop
        # that counts them (mirroring dns_tunneling_domain_examples for the sibling
        # dns_tunnel_v2 signal above) -- attach one here so pipeline.py's alert-
        # building can prefer it, same as it already does for DNS_COVERT_TUNNELING.
        dga_domain_examples = features.get("suspicious_domain_examples", []) or []
        dga_evidence_domain = dga_domain_examples[0] if dga_domain_examples else None
        dga_examples_note = f" e.g.={','.join(dga_domain_examples)}" if dga_domain_examples else ""
        if sd >= 15:
            add("dns_dga_burst", sd, min(1.0, 0.6 + sd / 50.0), "dns_behavior",
                f"absolute burst {int(sd)} domains{dga_examples_note}", domain=dga_evidence_domain)
        elif sd >= 5 and entropy_avg > 3.5:
            add("dns_dga_burst", sd, 0.6, "dns_behavior",
                f"elevated {int(sd)} domains entropy={entropy_avg:.2f}{dga_examples_note}", domain=dga_evidence_domain)
        elif not is_telemetry and dga_score > 0.40:
            # Pure classifier-score branch, not the per-domain loop above -- no
            # specific domain to attach here, unlike the two branches above it, and no
            # per-domain source protection either -- keep the device-wide gate for
            # this one branch only.
            add("dns_dga_burst", dga_score, min(1.0, dga_score), "dns_behavior",
                f"classifier score {dga_score:.2f}")

        # ── Real DNS tunneling signals (distinct from the existing rate/entropy-based
        #    "DNS_TUNNELING" hypothesis, which is really a burst detector) ────────────
        # BUGFIX: same class of fix as the DGA block above -- tunnel_domains/fanout_domain
        # already exclude telemetry at the source (dns_features.py), and max_label's own
        # CDN/telemetry protection now lives in the evidence_domain check just below
        # (this file's own earlier fix), so this block no longer needs the unreliable
        # device-wide `is_telemetry` gate either. Only txt_null_ratio/susp_tld_ratio (pure
        # aggregate ratios, no specific domain to check at the source) still need it.
        max_label = float(features.get("max_label_length", 0.0) or 0.0)
        max_label_domain = str(features.get("max_label_domain", "") or "")
        tunnel_domains = float(features.get("dns_tunneling_domains", 0.0) or 0.0)
        tunnel_domain_examples = features.get("dns_tunneling_domain_examples", []) or []
        txt_null_ratio = float(features.get("dns_txt_null_ratio", 0.0) or 0.0)
        susp_tld_ratio = float(features.get("suspicious_tld_ratio", 0.0) or 0.0)
        fanout_count = float(features.get("subdomain_fanout_count", 0.0) or 0.0)
        fanout_domain = str(features.get("subdomain_fanout_domain", "") or "")
        # VERSION 11 (P2, review #17 "parent-domain model"): average label entropy
        # across the fanout parent's own children (dns_features.py) -- see below for
        # how this scales confidence beyond raw count alone.
        fanout_label_entropy = float(features.get("fanout_label_entropy", 0.0) or 0.0)

        # A live-data audit found the alert's displayed "Target" domain often has no
        # causal relationship to which domain actually produced this evidence (e.g. a
        # 19-char domain reported alongside "max_label=57" measured on a DIFFERENT
        # domain elsewhere in the same window) -- pipeline.py's target-domain picker
        # scans the whole window for "most notable," independent of which evidence
        # fired. Attaching the real domain here (Evidence.domain, always present on
        # the dataclass but never previously populated) lets the alert/reasoning trail
        # show the domain this specific evidence actually came from.
        #
        # BUGFIX (found via a third-party review of the full alerts.json history,
        # verified against real post-fix production data): the CDN/cloud-safe
        # exemption below used to check `top_domain` -- the SAME unreliable
        # "most notable domain in the whole window" value the comment above already
        # calls out as causally unrelated to this specific evidence -- instead of the
        # domain that actually produced the long-label/tunnel-domain hit. Confirmed
        # live: a Synology QuickConnect DDNS hostname (*.quickconnect.to, already in
        # _SYSTEM_SAFE_BASE_DOMAINS) and an Amazon Minerva telemetry hash-subdomain
        # (*.a2z.com, also already safe-listed) both tripped dns_tunnel_v2 because
        # top_domain -- some unrelated domain elsewhere in the window -- wasn't
        # CDN-recognized, even though the domain that actually triggered max_label>55
        # was. The exemption must test the evidence's own domain, not a bystander.
        evidence_domain = max_label_domain if max_label > 55 else (tunnel_domain_examples[0] if tunnel_domain_examples else None)
        if (tunnel_domains >= 2 or max_label > 55) and not is_known_safe_domain(evidence_domain):
            examples_note = f" e.g.={','.join(tunnel_domain_examples)}" if tunnel_domain_examples else ""
            add("dns_tunnel_v2", max_label, min(1.0, 0.5 + tunnel_domains * 0.15), "dns_tunnel_v2",
                f"encoded/long labels max={int(max_label)} domain={max_label_domain or '?'} count={int(tunnel_domains)}{examples_note}",
                subtag="encoded_labels", domain=evidence_domain)
        # Sliding-window subdomain fanout: many distinct labels sharing one registrable
        # parent within the window is the classic tunneling shape (unlike the
        # rotating-whole-domain DGA pattern above, which max_label/tunnel_domains
        # already covers) -- distinct evidence, distinct subtag, so the hypothesis
        # engine's "2+ corroborating categories" bonus can count it independently.
        # BUGFIX: same class of bug as above -- a legitimate CDN/cloud parent domain
        # (e.g. a content-hash-per-request CDN pattern) can also produce many distinct
        # labels under one parent; this never had any CDN exemption at all. Uses
        # fanout_domain (the parent this evidence is actually about), not top_domain.
        if fanout_count >= 8 and not is_known_safe_domain(fanout_domain):
            # VERSION 11 (P2, review #17): fanout COUNT alone can't distinguish "many
            # meaningfully-named subdomains" (legitimate multi-tenant SaaS) from "many
            # randomized/encoded chunks" (real tunneling) -- a high average label
            # entropy among the fanout parent's own children pushes confidence up on
            # top of the count-based baseline, capped so entropy alone (with a low
            # count just above the 8 floor) can't dominate the score.
            entropy_bonus = min(0.3, max(0.0, fanout_label_entropy - 3.0) * 0.2)
            add("dns_tunnel_v2", fanout_count, min(1.0, 0.4 + fanout_count * 0.04 + entropy_bonus), "dns_tunnel_v2",
                f"{int(fanout_count)} distinct subdomains under one parent domain={fanout_domain or '?'} in-window "
                f"(avg label entropy={fanout_label_entropy:.2f})",
                subtag="subdomain_fanout", domain=fanout_domain)
        if not is_telemetry and txt_null_ratio > 0.15:
            # Pure aggregate ratio, no specific domain to check at the source -- keep
            # the device-wide gate for this one, same reasoning as the dga_score branch.
            add("dns_tunnel_v2", txt_null_ratio, min(1.0, txt_null_ratio * 2.0), "dns_tunnel_v2",
                f"txt/null ratio {txt_null_ratio:.2f}", subtag="txt_null_abuse")
        if not is_telemetry and susp_tld_ratio > 0.15:
            add("dns_tunnel_v2", susp_tld_ratio, min(1.0, susp_tld_ratio * 2.0), "dns_tunnel_v2",
                f"suspicious tld ratio {susp_tld_ratio:.2f}", subtag="suspicious_tld")

        # ── Exfiltration byte bursts ─────────────────────────────────────────────────
        # BUGFIX (live audit): this had no destination-scope check at all -- purely raw
        # byte volume/z-score, regardless of where the bytes went. Confirmed live: a
        # smart-TV/monitor-class device's own local multicast group traffic (LAN
        # discovery/casting protocols like DIAL/SmartView commonly use 224.0.0.x) tripped
        # this 3x with z-scores in the thousands. Multicast/broadcast/private/loopback
        # traffic (_is_local_dest(),
        # already defined above and already used by the beaconing check just below)
        # structurally cannot leave the LAN, so no volume of it can be exfiltration.
        outbound_z = float(features.get("outbound_bytes_z", 0.0) or 0.0)
        outbound_bytes = float(features.get("zeek_outbound_bytes", 0.0) or 0.0)
        exfil_dest_ip = str(features.get("last_dest_ip", "unknown") or "unknown")
        is_local_exfil_dest = _is_local_dest(exfil_dest_ip)
        if is_local_exfil_dest:
            pass
        elif outbound_z > 5.0 and outbound_bytes > 2500000:
            # BUGFIX (v13 full-architecture plan, Phase 9): domain= was never passed
            # here, unlike the dns_tunnel_v2 blocks above -- exfil_dest_ip is already
            # computed and already used for the _is_local_dest() gate just above, so
            # this is a real destination this Evidence item can carry, not a new
            # computation. Benefits v-current's own alert display directly (the same
            # class of fix dns_tunnel_v2 already got) and lets v13's evidence ingest
            # receive a real .domain at the source instead of needing
            # live_engine.py's fallback_context workaround (which stays in place as
            # a safety net regardless, not removed by this fix).
            #
            # BUGFIX (2026-09-10, AUDIT_V14_REVIEW_RESPONSE.md §2.4): this used to be
            # `and not is_vendor_cloud_api` -- a hard gate producing ZERO evidence for
            # a multi-megabyte, z>5 (wildly abnormal for this device) burst to
            # github.com/amazonaws.com/etc., unlike the "elevated" tier just below,
            # which already dampens confidence instead of suppressing outright. A
            # genuinely extreme burst to one of these domains is real signal worth
            # SOME weight, even reduced -- dampen the same way, don't zero it.
            conf = 0.5 if is_vendor_cloud_api else 0.9
            add("zeek_exfiltration", outbound_z, conf, "zeek_network",
                f"massive burst Z={outbound_z:.2f} bytes={int(outbound_bytes)}",
                domain=exfil_dest_ip)
        elif outbound_z > 3.5 and outbound_bytes > 250000 and not is_telemetry:
            conf = 0.35 if is_vendor_cloud_api else 0.6
            add("zeek_exfiltration", outbound_z, conf, "zeek_network",
                f"elevated Z={outbound_z:.2f} bytes={int(outbound_bytes)}",
                domain=exfil_dest_ip)
        # BUGFIX (external architecture review, 2026-09-09): this branch used to fire
        # on raw absolute volume alone, with NO reference to the device's own
        # baseline at all -- unlike the two branches above it, which both gate on
        # outbound_bytes_z (a real z-score, i.e. genuinely baseline-relative). A
        # device whose normal traffic legitimately includes large transfers (a NAS
        # doing its own backups, a PC on a big game/OS-update download that isn't in
        # the narrow _VENDOR_CLOUD_API_DOMAINS/telemetry allowlists) could clear 50MB
        # on a routine day with a NEGATIVE or near-zero z-score -- i.e. this specific
        # transfer wasn't even unusual FOR THAT DEVICE -- and still fire here. Added
        # `outbound_z > 0` as a minimal floor: cheapest possible baseline-awareness
        # (merely "elevated at all relative to this device's own history"), not the
        # same rigor as the two branches above -- deliberately conservative given no
        # live tuning data exists yet for what a stricter bar should be here
        # specifically (see Documentation/AUDIT_REVIEW_FOLLOWUP.md).
        elif outbound_bytes > 50000000 and outbound_z > 0 and not is_telemetry:
            # BUGFIX (2026-09-10, AUDIT_V14_REVIEW_RESPONSE.md §2.4): same dampen-not-
            # suppress fix as the massive-burst tier above -- this used to also hard-gate
            # on `not is_vendor_cloud_api`.
            conf = 0.25 if is_vendor_cloud_api else 0.55
            add("zeek_exfiltration", outbound_bytes, conf, "zeek_network",
                f"absolute volume bytes={int(outbound_bytes)} Z={outbound_z:.2f}",
                domain=exfil_dest_ip)

        # ── C2 beaconing periodicity ──────────────────────────────────────────────────
        beacon_c2_1h = float(features.get("beaconing_c2_1h", 0.0) or 0.0)
        beacon_tdr = float(features.get("beacon_tdr", 0.0) or 0.0)
        beacon_total = float(features.get("beacon_total", 0.0) or 0.0)
        c2_jitter = float(features.get("beaconing_c2_count", 0.0) or 0.0)
        last_dest_ip = str(features.get("last_dest_ip", "unknown") or "unknown")

        # BUGFIX (v13 full-architecture plan, Phase 9): domain= added to all three
        # branches below, same reasoning as zeek_exfiltration above -- last_dest_ip
        # is already computed and already used by the third branch's own
        # _is_local_dest() gate. NOTE (deliberately not "fixed" beyond this phase's
        # actual scope): the first two branches don't gate on _is_local_dest() before
        # firing, unlike the third -- so domain=last_dest_ip here could occasionally
        # attach a private/local IP as the destination. This is no worse than today's
        # fallback_context workaround (which already does the same thing
        # unconditionally for these two evidence types), so not a regression.
        # BUGFIX (external architecture review, 2026-09-09): subtag= was never passed
        # to any of these 3 branches -- BeaconingHypothesis (hypotheses/engine.py) had
        # no way to tell "genuine interval-regularity evidence" (the tdr branch below,
        # matching the audit's own "regular/near-regular intervals + similar byte
        # counts" bar) apart from two much thinner signals (a raw sequence count, a
        # raw jitter-hit count, neither requiring any actual regularity), yet all 3
        # reached the SAME 2.0->3.0->4.0 ceiling. Tagged now the same way
        # DNSTunnelingV2Hypothesis's own sub-signals already are (add()'s own
        # docstring) -- BeaconingHypothesis's own comment, just below this file, caps
        # the ceiling for the two thinner tags the same way DNS_ATTRIBUTION_GAP's
        # ambiguous case is already capped elsewhere in this codebase.
        if beacon_c2_1h > 0 and not is_telemetry:
            add("zeek_beaconing", beacon_c2_1h, 0.7, "zeek_network",
                f"low-and-slow c2 periodicity {int(beacon_c2_1h)} sequences",
                subtag="low_and_slow", domain=last_dest_ip)
        elif beacon_tdr > 0.75 and beacon_total >= 15:
            conf = min(1.0, beacon_tdr) * (0.1 if is_telemetry else 1.0)
            if conf > 0:
                add("zeek_beaconing", beacon_tdr, conf, "zeek_network",
                    f"persistent single-target beaconing tdr={beacon_tdr:.2f} total={int(beacon_total)}",
                    subtag="persistent_single_target", domain=last_dest_ip)
        elif c2_jitter > 0 and not is_telemetry and not _is_local_dest(last_dest_ip):
            conf = 0.3 if outbound_bytes == 0 else 0.55
            add("zeek_beaconing", c2_jitter, conf, "zeek_network",
                f"uniform check-in jitter {int(c2_jitter)} hits",
                subtag="uniform_jitter", domain=last_dest_ip)

        # ── TCP connection abuse / port scan ─────────────────────────────────────────
        # BUGFIX (live audit): this only ever looked at raw counts -- 165 rejected
        # connections across just 6 unique IPs (a 27x-repeat-per-IP shape, the OPPOSITE
        # of a scan's "many IPs, 1-2 attempts each" shape) scored identically to a real
        # broad scan. Confirmed live: a smart-TV/monitor-class device generated 245
        # CONNECTION_ABUSE alerts this way, correlated in the SAME cycles with 40-44% of its own
        # DNS queries being Pi-hole-blocked and 51-67% NXDOMAIN -- i.e. its own name
        # resolution was substantially failing/blocked right then, the classic signature
        # of a device retrying now-unreachable/blocked endpoints, not probing new
        # targets. A high per-IP repetition ratio ALONE can't safely distinguish that
        # from a real single-target brute-force (which also repeats against few IPs) --
        # what actually distinguishes them is THIS device's own blocked/nxdomain ratio
        # being elevated in the same window, so that's the dampener, not the ratio
        # alone. s0_rej_unique_threshold is per-device LEARNED (fp_engine.py's
        # get_device_conn_abuse_unique_ip_threshold(), same self-healing shape as the
        # existing arp_sweep_threshold parameter) rather than the old hardcoded 5.
        s0_rej = float(features.get("zeek_s0_rej_count", 0.0) or 0.0)
        s0_rej_unique = float(features.get("zeek_s0_rej_unique_ips", 0.0) or 0.0)
        if s0_rej > 25 and s0_rej_unique > conn_abuse_unique_ip_threshold:
            conf = 0.9 if s0_rej_unique > 15 else 0.6
            blocked_ratio = float(features.get("blocked_ratio", 0.0) or 0.0)
            nxdomain_ratio = float(features.get("nxdomain_ratio", 0.0) or 0.0)
            rejects_per_unique_ip = s0_rej / max(s0_rej_unique, 1.0)
            is_retry_storm_shaped = rejects_per_unique_ip >= 10.0
            own_dns_failing = (blocked_ratio + nxdomain_ratio) >= 0.5
            note = f"rejected connections {int(s0_rej)} across {int(s0_rej_unique)} unique IPs"
            if is_retry_storm_shaped and own_dns_failing:
                # Halve confidence rather than suppress outright -- this device's own
                # DNS being substantially blocked/failing right now is real corroborating
                # context for "retrying dead endpoints," not proof; a second independent
                # source can still legitimately push this to HIGH.
                conf *= 0.5
                note += (f" (dampened: {rejects_per_unique_ip:.1f}x repeat-per-IP + this "
                         f"device's own blocked_ratio={blocked_ratio:.2f}/nxdomain_ratio="
                         f"{nxdomain_ratio:.2f} suggest retrying blocked/dead endpoints, "
                         f"not probing new targets)")
            rej_ip_examples = features.get("zeek_s0_rej_ip_examples", []) or []
            rej_evidence_ip = rej_ip_examples[0] if rej_ip_examples else None
            if rej_ip_examples:
                note += f"; e.g.={','.join(rej_ip_examples)}"
            add("zeek_conn_abuse", s0_rej, conf, "zeek_network", note, domain=rej_evidence_ip)

        # ── ARP host-discovery sweep (recon precursor) ───────────────────────────────
        # PHASE 21B: broadcast-visible, so this reaches WiFi devices the same way MAC
        # correlation already does -- doesn't need the reactive Fritzbox capture at all.
        # Deliberately NOT a hard-stop (some IoT discovery protocols behave similarly) --
        # corroborates ConnectionAbuseHypothesis, needs a second independent source to
        # reach HIGH.
        arp_sweep_count = float(features.get("zeek_arp_sweep_count", 0.0) or 0.0)
        if arp_sweep_count >= arp_sweep_threshold:
            conf = min(1.0, 0.5 + (arp_sweep_count - arp_sweep_threshold) * 0.05)
            # BUGFIX (live audit): no domain= was ever attached here -- an arp_sweep-
            # driven CONNECTION_ABUSE alert had nothing evidence-linked to show, so
            # pipeline.py's attribution override (which checks `ev.domain`) silently
            # never matched, and the alert fell back to a coincidental, unrelated
            # domain/port from the device's own last connection. One representative
            # swept IP (not "the" target -- a sweep touches many) is still far more
            # honest than an unrelated bystander domain; the full example list goes in
            # the note text for the "WHY" reasoning detail.
            swept_examples = features.get("zeek_arp_swept_ip_examples", []) or []
            rep_swept_ip = swept_examples[0] if swept_examples else None
            note = f"ARP-requested {int(arp_sweep_count)} distinct targets (host-discovery sweep)"
            if swept_examples:
                note += f"; e.g.={','.join(swept_examples)}"
            add("arp_sweep", arp_sweep_count, conf, "lan_recon", note, domain=rep_swept_ip)

        # ── Long-lived / covert-tunnel connections ───────────────────────────────────
        max_dur = float(features.get("zeek_max_duration", 0.0) or 0.0)
        if max_dur > 43200:
            add("zeek_long_conn", max_dur, 0.85, "zeek_network", f"extreme duration {int(max_dur)}s")
        elif max_dur > long_conn_duration_threshold:
            add("zeek_long_conn", max_dur, 0.5, "zeek_network", f"long duration {int(max_dur)}s")

        return ev_list
