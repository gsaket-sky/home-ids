"""
Standalone runtime test for a bug found via a third-party review of the full
alerts.json history (8,776 records, 2026-08-17 -> 2026-08-23), verified against real
production data before fixing. Not part of the pytest suite -- run directly:
`python3 tests/test_phase33_tunneling_dga_domain_attribution.py`.

BUGFIX #1 (false positive): threat_signals.py's dns_tunnel_v2 CDN/cloud-safe exemption
checked `top_domain` -- the SAME unreliable "most notable domain in the whole window"
value (_select_target_domain()) that earlier phases already found causally unrelated to
a given piece of evidence -- instead of the domain that actually produced the
long-label/tunnel-domain/fanout hit. Confirmed live: a Synology QuickConnect DDNS
hostname (*.quickconnect.to, already in _SYSTEM_SAFE_BASE_DOMAINS) and an Amazon
Minerva telemetry hash-subdomain (*.a2z.com, also already safe-listed) both tripped
dns_tunnel_v2 because top_domain -- some unrelated domain elsewhere in the window --
wasn't CDN-recognized, even though the domain that actually triggered max_label>55 was.
max_label/max_label_domain themselves (dns_features.py) are computed with NO CDN/
telemetry filtering at all -- the threat_signals.py exemption is the ONLY line of
defense for that specific path, unlike tunnel_domains/fanout_by_base which already
exclude CDN+telemetry at the source.

BUGFIX #2 (false negative, found while verifying #1): the DGA and DNS-tunneling blocks
were ALSO gated by a device-wide `is_telemetry` flag computed from that same unreliable
top_domain -- so genuine, unrelated evidence could be silently suppressed whenever
top_domain (some OTHER domain in the window) happened to be telemetry-recognized.
Confirmed live with top_domain="mask.icloud.com" (a real, common top_domain value in
production data) zeroing out evidence for a completely unrelated, genuinely-suspicious
.ru domain. Fixed by removing the device-wide gate from the domain-example-driven
branches (which now have real per-domain source protection) and keeping it only on the
two branches that have no per-domain source protection at all (the DGA classifier-score
branch, and the txt_null_ratio/susp_tld_ratio aggregate-ratio branches).

Covers:
  A. dns_features.py -- suspicious_dga() domain counting now excludes telemetry domains
     at the source, matching tunneling_domains/fanout_by_base's existing pattern.
  B. threat_signals.py -- the dns_tunnel_v2 CDN exemption uses the real evidence domain,
     not top_domain (both the max_label/tunnel_domains path and the fanout path).
  C. threat_signals.py -- the is_telemetry false-negative is gone for domain-example-
     driven DGA/tunneling evidence, while the classifier-score/ratio branches (no
     per-domain protection) still respect telemetry gating.
  D. Regression guards: genuine (non-safe, non-telemetry) tunneling/DGA/fanout evidence
     still fires exactly as before.
"""
import sys
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

FAILURES = []

def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section A: dns_features.py -- suspicious_dga() domain counting excludes telemetry
# ═══════════════════════════════════════════════════════════════════════════════════
from utils import is_telemetry_domain, suspicious_dga

# mask.icloud.com is a real telemetry-recognized domain seen in production as a
# frequent top_domain value. Confirm the source module actually recognizes it, so the
# regression guard below is testing something real.
check("SOURCE FACT: mask.icloud.com is telemetry-recognized (is_telemetry_domain)",
      is_telemetry_domain("mask.icloud.com"))


# ═══════════════════════════════════════════════════════════════════════════════════
# Section B/C: threat_signals.py -- CDN exemption uses the real evidence domain, and
# is_telemetry no longer false-negatives domain-example-driven evidence.
# ═══════════════════════════════════════════════════════════════════════════════════
from intelligence.detectors.threat_signals import ThreatSignalDetector

det = ThreatSignalDetector()

def _tunnel_evidence(feats, top_domain):
    ev = det.detect("devX", feats, top_domain=top_domain)
    return [(e.type, e.domain) for e in ev if e.type == "dns_tunnel_v2"]

def _dga_evidence(feats, top_domain):
    ev = det.detect("devX", feats, top_domain=top_domain)
    return [(e.type, e.domain) for e in ev if e.type == "dns_dga_burst"]

_BASE_TUNNEL_FEATS = {
    "max_label_length": 0.0, "max_label_domain": "",
    "dns_tunneling_domains": 0.0, "dns_tunneling_domain_examples": [],
    "suspicious_tld_ratio": 0.0, "dns_txt_null_ratio": 0.0,
    "subdomain_fanout_count": 0.0, "subdomain_fanout_domain": "",
}
_BASE_DGA_FEATS = {
    "suspicious_domains": 0.0, "entropy_avg": 0.0, "dga_score": 0.0,
    "suspicious_domain_examples": [],
}

# THE CORE FIX #1: a safe-listed long-label domain (Synology QuickConnect DDNS) no
# longer trips dns_tunnel_v2 just because an unrelated top_domain isn't CDN-recognized.
quickconnect_feats = dict(_BASE_TUNNEL_FEATS,
    max_label_length=57.0,
    max_label_domain="syn6-abcdefghijklmnopqrstuvwxyiaaaaaaaaaaaaaaaaaaaaaaaaaa.exampleuser.direct.quickconnect.to")
check("THE CORE FIX: a safe-listed QuickConnect DDNS long label no longer false-positives "
      "dns_tunnel_v2 via an unrelated top_domain",
      _tunnel_evidence(quickconnect_feats, "some-unrelated-domain.example") == [])

# THE CORE FIX #1 (second real example): Amazon Minerva hash-subdomain, same shape.
minerva_feats = dict(_BASE_TUNNEL_FEATS,
    max_label_length=63.0,
    max_label_domain="9171f26e5c1fc238b809d6415de0a3ac9a002131321c2231afe4d46dcb0ab14.us-east-1.prod.service.minerva.devices.a2z.com")
check("THE CORE FIX: a safe-listed Amazon Minerva hash-subdomain no longer "
      "false-positives dns_tunnel_v2 via an unrelated top_domain",
      _tunnel_evidence(minerva_feats, "mask.icloud.com") == [])

# THE CORE FIX #2 (false negative): a genuinely suspicious long-label .ru domain still
# fires even when top_domain (an unrelated domain) is telemetry-recognized.
evil_feats = dict(_BASE_TUNNEL_FEATS,
    max_label_length=60.0,
    max_label_domain="qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm12345.evil-tunnel.ru",
    dns_tunneling_domains=3.0,
    dns_tunneling_domain_examples=["qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm12345.evil-tunnel.ru"])
evil_ev = _tunnel_evidence(evil_feats, "mask.icloud.com")
check("THE CORE FIX: a genuine tunneling domain is no longer silently suppressed just "
      "because an unrelated top_domain is telemetry-recognized",
      evil_ev == [("dns_tunnel_v2", "qwertyuiopasdfghjklzxcvbnmqwertyuiopasdfghjklzxcvbnm12345.evil-tunnel.ru")],
      f"got {evil_ev}")

# REGRESSION GUARD: genuine subdomain fanout on a non-CDN parent still fires.
fanout_feats = dict(_BASE_TUNNEL_FEATS, subdomain_fanout_count=10.0, subdomain_fanout_domain="evil-tunnel.ru")
check("REGRESSION GUARD: genuine subdomain fanout on a non-CDN parent still fires",
      _tunnel_evidence(fanout_feats, "mask.icloud.com") == [("dns_tunnel_v2", "evil-tunnel.ru")])

# THE FIX (extended): subdomain fanout on a CDN parent is now exempted too (previously
# had no exemption check of any kind).
fanout_cdn_feats = dict(_BASE_TUNNEL_FEATS, subdomain_fanout_count=10.0, subdomain_fanout_domain="cloudfront.net")
check("THE FIX: subdomain fanout on a recognized CDN parent (cloudfront.net) is exempted",
      _tunnel_evidence(fanout_cdn_feats, "mask.icloud.com") == [])

# THE CORE FIX #2 (DGA side): a genuine DGA burst still fires even when top_domain is
# telemetry-recognized -- this used to be silently zeroed out entirely.
dga_feats = dict(_BASE_DGA_FEATS, suspicious_domains=20.0, entropy_avg=2.0,
                  suspicious_domain_examples=["qwertyuiopasdfgh123.ru"])
dga_ev = _dga_evidence(dga_feats, "mask.icloud.com")
check("THE CORE FIX: a genuine DGA domain-example burst is no longer silently "
      "suppressed just because an unrelated top_domain is telemetry-recognized",
      dga_ev == [("dns_dga_burst", "qwertyuiopasdfgh123.ru")], f"got {dga_ev}")

# REGRESSION GUARD: the classifier-score-only DGA branch (no per-domain source
# protection) still correctly respects is_telemetry.
classifier_feats = dict(_BASE_DGA_FEATS, dga_score=0.75)
check("REGRESSION GUARD: the pure classifier-score DGA branch is still suppressed when "
      "top_domain IS the telemetry domain in question (no per-domain protection exists "
      "for this branch, so the device-wide gate is intentionally retained)",
      _dga_evidence(classifier_feats, "mask.icloud.com") == [])
check("REGRESSION GUARD: the same classifier-score branch still fires for a non-"
      "telemetry top_domain",
      _dga_evidence(classifier_feats, "some-unrelated-domain.example") == [("dns_dga_burst", None)])

# REGRESSION GUARD: txt_null_ratio/susp_tld_ratio (no per-domain source protection)
# still respect telemetry gating.
txt_null_feats = dict(_BASE_TUNNEL_FEATS, dns_txt_null_ratio=0.30)
check("REGRESSION GUARD: txt_null_ratio evidence is still suppressed for a telemetry "
      "top_domain",
      _tunnel_evidence(txt_null_feats, "mask.icloud.com") == [])
check("REGRESSION GUARD: txt_null_ratio evidence still fires for a non-telemetry "
      "top_domain",
      len(_tunnel_evidence(txt_null_feats, "some-unrelated-domain.example")) == 1)


# ═══════════════════════════════════════════════════════════════════════════════════
# Section D: source-level fix in dns_features.py itself -- suspicious_dga() counting
# now excludes telemetry domains, matching the existing tunneling_domains/fanout_by_base
# pattern (verified by reading the module source, since get_features() requires a full
# ZeekFeatureExtractor/rolling-window setup out of scope for this standalone check).
# ═══════════════════════════════════════════════════════════════════════════════════
import inspect
from extractors import dns_features as _dns_features_module

_dns_features_src = inspect.getsource(_dns_features_module)
check("SOURCE-GUARD: suspicious_dga() domain counting now excludes telemetry domains "
      "at the source, same as tunneling_domains/fanout_by_base",
      "if suspicious_dga(domain) and not is_telemetry_domain(domain):" in _dns_features_src)


print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All tunneling/DGA domain-attribution checks PASSED.")
