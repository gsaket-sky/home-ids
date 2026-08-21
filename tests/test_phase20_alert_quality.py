"""
Standalone runtime test for Phase 20 alert-quality fixes, found via a live-data audit of
a 50-alert / 9-device DGA-shaped domain pattern (xkqz289dfj10dj-NNN.ru):

1. dns_features.py: the alert's displayed evidence value (e.g. max_label_length) had no
   way to say WHICH domain in the window produced it -- now tracked and exposed.
2. dns_features.py: a new sliding-window subdomain-fanout feature for the classic "many
   distinct labels under one shared parent" tunneling shape, excluding CDN/telemetry
   parents the same way the existing tunneling_domains check already does.
3. threat_signals.py: Evidence.domain (existed on the dataclass, never populated) is now
   set for dns_tunnel_v2's sub-signals, and the new subdomain-fanout evidence.
4. ollama_soc.py: a multi-device spread guard withholds autonomous suppress/immunize
   actions when the same signature is independently firing on several distinct devices
   right now -- exactly the situation where a single-alert LLM call has no visibility
   into the wider pattern and can (confirmed live, 1.0 confidence) call it benign wrongly.

Not part of the pytest suite (no fixtures needed) -- run directly:
`python3 test_phase20_alert_quality.py`.
"""
import re
import sys
import time
from pathlib import Path as _PathForSysPath
sys.path.insert(0, str(_PathForSysPath(__file__).resolve().parent.parent / "src"))

from core.state import DeviceState
from extractors.dns_features import FeatureExtractor
from intelligence.detectors.threat_signals import ThreatSignalDetector

FAILURES = []


def check(name, cond, detail=""):
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


# ── Test 1: max_label_length now carries which domain produced it ──────────────────
state1 = DeviceState(device_id="d1", client_ip="192.168.1.50", hostname="test-host")
now = time.time()
short_domain = "netflix.com"
long_domain = "a" * 60 + ".evil-tunnel.ru"
for dom in (short_domain, long_domain):
    state1.rolling.events.append((now, dom, 0))
    state1.rolling.domains[dom] += 1
    state1.rolling.domain_timestamps[dom].append(now)

feats1 = FeatureExtractor().compute(state1, now, window_seconds=300)
check("max_label_length reflects the actually-longest label", feats1["max_label_length"] == 60,
      f"got {feats1['max_label_length']}")
check("max_label_domain attributes it to the real domain, not the short one",
      feats1["max_label_domain"] == long_domain, f"got {feats1['max_label_domain']!r}")


# ── Test 2: subdomain fanout -- many distinct labels under one shared parent ───────
state2 = DeviceState(device_id="d2", client_ip="192.168.1.51", hostname="test-host2")
parent = "evil-tunnel.ru"
for i in range(12):
    dom = f"chunk{i:04d}.{parent}"
    state2.rolling.events.append((now, dom, 0))
    state2.rolling.domains[dom] += 1
    state2.rolling.domain_timestamps[dom].append(now)

feats2 = FeatureExtractor().compute(state2, now, window_seconds=300)
check("subdomain_fanout_count counts the 12 distinct chunks under one parent",
      feats2["subdomain_fanout_count"] == 12, f"got {feats2['subdomain_fanout_count']}")
check("subdomain_fanout_domain attributes the fanout to the real shared parent",
      feats2["subdomain_fanout_domain"] == parent, f"got {feats2['subdomain_fanout_domain']!r}")


# ── Test 3: subdomain fanout must NOT fire on legitimate CDN infrastructure ────────
state3 = DeviceState(device_id="d3", client_ip="192.168.1.52", hostname="test-host3")
for i in range(20):
    dom = f"edge-node-{i:04d}.cloudfront.net"
    state3.rolling.events.append((now, dom, 0))
    state3.rolling.domains[dom] += 1
    state3.rolling.domain_timestamps[dom].append(now)

feats3 = FeatureExtractor().compute(state3, now, window_seconds=300)
check("REGRESSION GUARD: 20 distinct cloudfront.net edge nodes do NOT trip subdomain fanout",
      feats3["subdomain_fanout_count"] == 0, f"got {feats3['subdomain_fanout_count']}")


# ── Test 4: threat_signals.py attaches the real domain to encoded_labels evidence ──
detector = ThreatSignalDetector()
features4 = {
    "max_label_length": 57.0, "max_label_domain": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.example.com",
    "dns_tunneling_domains": 0, "dns_tunneling_domain_examples": [],
    "dns_txt_null_ratio": 0.0, "suspicious_tld_ratio": 0.0, "subdomain_fanout_count": 0,
    "subdomain_fanout_domain": "",
}
ev4 = detector.detect(device="d4", features=features4, top_domain="unrelated-short-domain.ru")
encoded = [e for e in ev4 if e.type == "dns_tunnel_v2" and "encoded_labels" in e.provenance]
check("encoded_labels evidence fires on a real long label", len(encoded) == 1, f"got {len(encoded)}")
if encoded:
    check("THE CORE FIX: evidence.domain is the domain that actually had the long label, "
          "not the unrelated top_domain shown in the alert's Target line",
          encoded[0].domain == features4["max_label_domain"], f"got {encoded[0].domain!r}")


# ── Test 5: new subdomain_fanout evidence fires above threshold, with domain attached ──
features5 = dict(features4)
features5.update({
    "max_label_length": 10.0, "max_label_domain": "",
    "subdomain_fanout_count": 15.0, "subdomain_fanout_domain": "evil-tunnel.ru",
})
ev5 = detector.detect(device="d5", features=features5, top_domain="")
fanout = [e for e in ev5 if e.type == "dns_tunnel_v2" and "subdomain_fanout" in e.provenance]
check("subdomain_fanout evidence fires when count >= 8", len(fanout) == 1, f"got {len(fanout)}")
if fanout:
    check("subdomain_fanout evidence carries the shared-parent domain",
          fanout[0].domain == "evil-tunnel.ru", f"got {fanout[0].domain!r}")

features5b = dict(features5)
features5b["subdomain_fanout_count"] = 3.0  # below the threshold
ev5b = detector.detect(device="d5b", features=features5b, top_domain="")
fanout_b = [e for e in ev5b if e.type == "dns_tunnel_v2" and "subdomain_fanout" in e.provenance]
check("subdomain_fanout evidence does NOT fire below threshold (count=3)", len(fanout_b) == 0)


# ── Test 6: ollama_soc.py multi-device suppress guard (source-level + mirror logic) ──
ollama_soc_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "scripts" / "ollama_soc.py").read_text(encoding="utf-8")
check("ollama_soc.py builds a signature -> distinct-device-count map",
      "signature_device_counts" in ollama_soc_src)
check("ollama_soc.py's guard is keyed on signature, not the exact (never-repeating) domain string",
      "sig = payload.get(\"signature\"" in ollama_soc_src)
check("ollama_soc.py checks device spread against a configurable threshold before suppressing",
      "spread >= multi_device_suppress_guard" in ollama_soc_src)
_guard_branch_match = re.search(
    r'if is_valid.*?spread >= multi_device_suppress_guard:\n(.*?)\n        elif',
    ollama_soc_src, re.DOTALL,
)
check("a withheld suppress's branch does NOT set action_taken=True (so it's reconsidered next run)",
      bool(_guard_branch_match) and 'action_taken"] = True' not in _guard_branch_match.group(1))


def should_withhold_suppress(spread: int, guard_threshold: int, already_actioned: bool) -> bool:
    """Mirrors the real decision in ollama_soc.py's main() loop."""
    return (not already_actioned) and spread >= guard_threshold


check("THE CORE FIX: a signature spread across 9 distinct devices (the real xkqz case) "
      "withholds auto-suppress against the default guard of 3",
      should_withhold_suppress(spread=9, guard_threshold=3, already_actioned=False) is True)
check("a signature seen on only 1 device (the normal case) is NOT withheld",
      should_withhold_suppress(spread=1, guard_threshold=3, already_actioned=False) is False)
check("an already-actioned pattern is never re-withheld regardless of spread",
      should_withhold_suppress(spread=9, guard_threshold=3, already_actioned=True) is False)
check("spread exactly AT the threshold withholds (>=, not >)",
      should_withhold_suppress(spread=3, guard_threshold=3, already_actioned=False) is True)


# ── Test 7: pipeline.py alert-text source guards (Phase 20 cosmetic + transparency fixes) ──
# PHASE 21-ALERT-REDESIGN superseded the original mechanism these three checks targeted
# (a raw "`group: type` (value)" evidence dump) with _describe_evidence() -- a
# plain-language sentence per evidence group, with no raw magnitude to mislabel as a
# probability in the first place, and Evidence.domain still surfaced when present.
# Updated to assert the CURRENT implementation of the same underlying Phase 20 intent
# (no group/type stutter, domain surfaced, no raw-value-as-probability confusion)
# rather than the specific old code that implemented it.
pipeline_src = (_PathForSysPath(__file__).resolve().parent.parent / "src" / "core" / "pipeline.py").read_text(encoding="utf-8")
check("pipeline.py's WHY section uses plain-language evidence descriptions, not a raw "
      "'group: type (value)' stutter-prone dump",
      "why_lines = [_describe_evidence(ev) for ev in" in pipeline_src)
check("_describe_evidence() surfaces Evidence.domain when the detector attached one",
      'domain_suffix = f" — `{ev.domain}`" if getattr(ev, "domain", None) else ""' in pipeline_src)
check("the WHY section shows plain-language sentences with no raw per-signal magnitude at "
      "all, so there's no number left to misread as a probability (Phase 20's underlying "
      "concern, now structurally impossible rather than just labeled)",
      "text = _EVIDENCE_PLAIN_LANGUAGE.get(ev.type" in pipeline_src)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED: {FAILURES}")
    sys.exit(1)
else:
    print("All Phase 20 alert-quality checks PASSED.")
