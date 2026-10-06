"""
ZeekFeatureExtractor shared between the main loop and the reactive-capture thread (runtime trace run 2, finding 4.3;
audit A-05).

On .94 the reactive-capture dispatcher thread ingested a burst's Zeek logs into the live extractor
(fritzbox_capture.ingest_zeek_logs -> zeek_fx.ingest) while the main loop's get_features() iterated the same per-IP
deques: "deque mutated during iteration" unwound out of EnginePipeline._step and aborted the cycle for every device.
Covers: concurrent ingest (conn + DHCP MAC flips, i.e. _bind_mac) on one thread while the other thread runs
get_features / prune / the getters raises nothing; the consume-once spoof records are popped in one step.

Run directly: `venv/Scripts/python.exe tests/test_zeek_extractor_thread_safety.py`
"""
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from extractors.zeek_features import ZeekFeatureExtractor  # noqa: E402

zfx = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
DEVICES = [f"192.168.1.{i}" for i in range(10, 20)]
STATES = ["S0", "REJ", "SF", "S1"]
stop = threading.Event()
errors = []


def _capture_thread():
    """What fritzbox_capture.ingest_zeek_logs does: a stream of conn events plus DHCP rebinding (MAC flips)."""
    n = 0
    try:
        while not stop.is_set():
            n += 1
            now = time.time()
            src = DEVICES[n % len(DEVICES)]
            zfx.ingest({"_zeek_type": "conn", "id.orig_h": src, "id.resp_h": f"203.0.113.{n % 250}",
                        "id.resp_p": 443 + (n % 50), "proto": "tcp", "conn_state": STATES[n % 4],
                        "duration": 0.5, "orig_bytes": 100, "resp_bytes": 200, "ts": now})
            if n % 7 == 0:
                zfx.ingest({"_zeek_type": "dhcp", "client_addr": src, "mac": f"aa:bb:cc:00:00:{n % 256:02x}",
                            "ts": now})
            if n % 500 == 0:
                zfx.prune(now, 1)  # the capture side never prunes, but an empty-then-refill churn widens the window
    except Exception as e:  # pragma: no cover - the failure being tested
        errors.append(("capture", repr(e)))


t = threading.Thread(target=_capture_thread, daemon=True)
t.start()
deadline = time.time() + 4.0
reads = 0
try:
    while time.time() < deadline:
        for dev in DEVICES:
            zfx.get_features([dev])
            zfx.get_dest_ips(dev)
            zfx.get_dest_ports(dev)
            zfx.get_scanned_ports(dev)
            zfx.get_alerts([dev])
            zfx.get_ja4_set(dev)
            zfx.pop_layer2_spoof(dev)
            zfx.pop_pending_spoof(dev)
            reads += 1
        zfx.prune(time.time(), 300)
except Exception as e:
    errors.append(("main", repr(e)))
finally:
    stop.set()
    t.join(5)

check("main loop and capture thread share the extractor for 4 s without an exception",
      not errors, str(errors[:3]))
check("the main side really ran (non-trivial number of reads)", reads > 100, str(reads))

# --- consume-once spoof records ---------------------------------------------------------------------------------
z2 = ZeekFeatureExtractor(home_subnets=["192.168.1.0/24"])
IP = "192.168.1.77"
t0 = time.time()
z2.ingest({"_zeek_type": "dhcp", "client_addr": IP, "mac": "aa:aa:aa:aa:aa:01", "ts": t0})
z2.ingest({"_zeek_type": "dhcp", "client_addr": IP, "mac": "aa:aa:aa:aa:aa:02", "ts": t0 + 10})
first = z2.pop_pending_spoof(IP)
check("a first genuine flip is consumed once as a pending record",
      first is not None and first["new"] == "aa:aa:aa:aa:aa:02" and z2.pop_pending_spoof(IP) is None)
z2.ingest({"_zeek_type": "dhcp", "client_addr": IP, "mac": "aa:aa:aa:aa:aa:03", "ts": t0 + 20})
confirmed = z2.pop_layer2_spoof(IP)
check("a second genuine flip within 600 s is consumed once as a confirmed spoof",
      confirmed is not None and confirmed["new"] == "aa:aa:aa:aa:aa:03" and z2.pop_layer2_spoof(IP) is None)
check("nothing to pop for an unknown address", z2.pop_layer2_spoof("192.168.1.1") is None
      and z2.pop_pending_spoof("192.168.1.1") is None)

if FAILURES:
    print(f"\n{len(FAILURES)} check(s) FAILED")
    sys.exit(1)
print("\nAll Zeek extractor thread-safety checks PASSED.")
