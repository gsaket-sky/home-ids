"""U5 (DETECTION_CORE_REWORK, handover 2026-10-14): a device's CL-AFPE threshold profile is raised in bounded steps and
never past a ceiling -- 1.5x the default for the engine's own (automatic) corrections, 2x for a person's. Human feedback is
optional, so the system self-tunes; the cap keeps it from blinding a detector. INTERIM: redo in P3b (harmless-pattern memory).

mark_false_positive() raised the device's ARP-sweep (+4), rejected-connection unique-IP (+4) and long-connection (x1.5)
thresholds on EVERY non-refused CONNECTION_ABUSE / scan correction -- including the engine's own `autonomous_stage23` /
`autonomous_local_origin` corrections -- with no cap: ten automatic corrections took the ARP-sweep threshold from 8 to 88
and those detectors went blind for that device. Now: the same steps, capped at 1.5x the default (the default each getter
already uses) for automatic corrections and 2x for a person's.

Run directly: `python tests/test_argus_cl_afpe_profile_ceiling.py`"""
import sys
import tempfile
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from argus.graph.store import GraphStore  # noqa: E402
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402

store = GraphStore(str(_P(tempfile.mkdtemp(prefix="clafpe_ceiling_")) / "t.db"))
cl = ClAfpeEngine(store)
NOW = 1_000_000.0
ALERT = {"signature": "CONNECTION_ABUSE", "device": {"id": "dev_x", "hostname": "host-x"}, "network_context": {},
         "features": {"zeek_s0_rej_count": 30, "zeek_s0_rej_unique_ips": 50, "zeek_max_duration": 90000.0,
                      "zeek_arp_sweep_count": 20}}
store.upsert_device("dev_x", timestamp=NOW)


def values(dev):
    return (cl.get_device_arp_sweep_threshold(dev), cl.get_device_conn_abuse_unique_ip_threshold(dev),
            cl.get_device_long_conn_duration_threshold(dev))


for src in ("autonomous_stage23", "autonomous_local_origin"):
    for _ in range(10):
        cl.mark_false_positive(ALERT, source=src, now=NOW)
check("10 automatic corrections of each kind stop at 1.5x the default (12, 7.5, 21600), not 88 / 53 / 109,350",
      values("dev_x") == (12.0, 7.5, 21600.0), str(values("dev_x")))

store.upsert_device("dev_p", timestamp=NOW)
alert_p = dict(ALERT, device={"id": "dev_p", "hostname": "host-p"})
cl.mark_false_positive(alert_p, source="operator", now=NOW)
check("a person's first correction raises each threshold one step (8+4, 5+4, 14400x1.5)",
      values("dev_p") == (12.0, 9.0, 21600.0), str(values("dev_p")))
for _ in range(10):
    cl.mark_false_positive(alert_p, source="operator", now=NOW)
check("repeated person corrections stop at 2x the default (16, 10, 28800)",
      values("dev_p") == (16.0, 10.0, 28800.0), str(values("dev_p")))

# a value already above the ceiling (raised by the old uncapped code) is never LOWERED by a correction
store.upsert_device("dev_old", timestamp=NOW)
cl.apply_device_fp_profile("dev_old", "arp_sweep_unique_targets_threshold", 48.0, baseline=8.0, set_by="autonomous_stage23",
                           reason="legacy", now=NOW)
cl.mark_false_positive(dict(ALERT, device={"id": "dev_old", "hostname": "h"}), source="operator", now=NOW)
cl.mark_false_positive(dict(ALERT, device={"id": "dev_old", "hostname": "h"}), source="autonomous_stage23", now=NOW)
check("an existing inflated value is neither lowered nor raised by a correction, person or automatic",
      cl.get_device_arp_sweep_threshold("dev_old") == 48.0, str(cl.get_device_arp_sweep_threshold("dev_old")))

print("PROFILE CEILING", "OK" if not FAILURES else f"FAILED {FAILURES}")
sys.exit(1 if FAILURES else 0)
