"""
Domain age, part 2: the young-domain gate, trust scope and the lookup scheduler (MASTER_TODO M2).

Covers: a young domain never counts as "already in use" (is_preexisting), however long it is used, for the domain and
every name under it, judged at first use (still young a year later); old, undated or unknown domains keep today's
behaviour; an established name is unaffected; CL-AFPE keeps automatic trust for a young domain device-scoped; the
scheduler sends nothing while off; normal mode asks only about learning-period names; filters (established,
non-registrable, country domains, static allowlist, already answered, local names the ledger recorded before the
local suffix was configured); switching on re-verifies every device,
round-robin, with progress, and completes; switching off stops it; switching on again restarts without re-asking.

Run directly: `venv/Scripts/python.exe tests/test_argus_domain_age_gate.py`
"""
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from intelligence.local_popularity import LocalPopularity, YOUNG_DAYS  # noqa: E402
from intelligence.rdap_age import RdapAgeService, BOOTSTRAP_URL, MIN_INTERVAL_SECONDS, DISABLED  # noqa: E402
from intelligence.domain_age_scheduler import DomainAgeScheduler  # noqa: E402
from utils import etld1, etld1_strict  # noqa: E402

DAY = 86400.0
T0 = 1_800_000_000.0
tmp = Path(tempfile.mkdtemp(prefix="domain_age_gate_"))


def iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ======================================================================================================================
# 1. The gate (LocalPopularity.is_preexisting / is_young)
# ======================================================================================================================
clock = [T0]
pop = LocalPopularity(tmp / "pop.db", etld1_fn=etld1, now_fn=lambda: clock[0])
# 8 active days of network history, so novelty can be judged at all.
for i in range(8):
    pop.observe("filler", f"day{i}.example.org", T0 + i * DAY)
# The camera uses its C2 (and a subdomain of it) and an old vendor cloud on 5 different days.
for i in range(5):
    pop.observe("camera", "beacon.evil-c2.com", T0 + i * DAY)
    pop.observe("camera", "api.vendor-cloud.com", T0 + i * DAY)
clock[0] = T0 + 9 * DAY
pop.flush()
first_use = T0

ages = {}
pop.age_fn = lambda base: ages.get(base)

check("without a date, a name used on 5 days is in use (today's behaviour)",
      pop.is_preexisting("beacon.evil-c2.com", device_id="camera") is True)
ages["evil-c2.com"] = first_use - 10 * DAY          # registered 10 days before first use
ages["vendor-cloud.com"] = first_use - 3000 * DAY   # an old domain
pop._history_cache.clear()
check("a young domain's name never counts as in use, however long it was used",
      pop.is_preexisting("beacon.evil-c2.com", device_id="camera") is False)
check("the same for the registrable domain itself", pop.is_preexisting("evil-c2.com", device_id="camera") is False)
check("an old domain stays in use", pop.is_preexisting("api.vendor-cloud.com", device_id="camera") is True)
check("is_young: young base, old base, unknown base",
      pop.is_young("x.evil-c2.com") and not pop.is_young("vendor-cloud.com") and not pop.is_young("never-seen.net"))
ages["evil-c2.com"] = first_use - (YOUNG_DAYS + 1) * DAY
check("registered just over YOUNG_DAYS before first use is not young", not pop.is_young("evil-c2.com"))
ages["evil-c2.com"] = first_use + 2 * DAY
check("registered after first use (re-registered) counts as young", pop.is_young("evil-c2.com"))
ages["evil-c2.com"] = first_use - 10 * DAY
clock[0] = T0 + 365 * DAY
check("judged at first use: still young a year later", pop.is_young("evil-c2.com"))
clock[0] = T0 + 9 * DAY
pop.age_fn = lambda base: (_ for _ in ()).throw(RuntimeError("db"))
check("an age-source error is 'not young', never a crash", pop.is_young("evil-c2.com") is False
      and pop.is_preexisting("beacon.evil-c2.com", device_id="camera") is True)
pop.age_fn = None
check("without an age source: exactly today's behaviour", pop.is_preexisting("beacon.evil-c2.com", device_id="camera") is True)

# Established names are unaffected.
pop2 = LocalPopularity(tmp / "pop2.db", etld1_fn=etld1, now_fn=lambda: T0 + 20 * DAY)
for i in range(8):
    for dev in ("a", "b", "c"):
        pop2.observe(dev, "new-but-everyone.com", T0 + i * DAY)
pop2.flush()
pop2.age_fn = lambda base: T0 - DAY
check("an established name (3+ devices, 7+ days) stays in use even when young",
      pop2.is_preexisting("new-but-everyone.com", device_id="a") is True)

# ======================================================================================================================
# 2. CL-AFPE trust scope
# ======================================================================================================================
from argus.cl_afpe.engine import ClAfpeEngine  # noqa: E402


class _P:
    def __init__(self, young):
        self.young = young

    def is_young(self, d):
        return d in self.young


eng = ClAfpeEngine.__new__(ClAfpeEngine)
eng.popularity = _P({"evil-c2.com"})
check("CL-AFPE: a young domain is device-scoped for automatic trust", eng.domain_young("evil-c2.com") is True)
check("CL-AFPE: an old or unknown domain is not", eng.domain_young("vendor-cloud.com") is False)
eng.popularity = None
check("CL-AFPE: without the ledger, unchanged", eng.domain_young("evil-c2.com") is False)

# ======================================================================================================================
# 3. The scheduler
# ======================================================================================================================
sclock = [T0 + 9 * DAY]
enabled = [False]
asked = []
REG = {}


def http(url, headers, timeout):
    if url == BOOTSTRAP_URL:
        return 200, json.dumps({"services": [[["com", "net", "org", "sky", "box"], ["https://rdap.example/"]]]}), {}
    name = url.rsplit("/", 1)[1]
    asked.append(name)
    if name in REG:
        return 200, json.dumps({"events": [{"eventAction": "registration", "eventDate": iso(REG[name])}]}), {}
    return 404, "{}", {}


def setup(learning_devices, warm=True):
    """A ledger: 'cam' used 4 rare names during its learning period, 'tv' 1 rare name after learning, 'pc' 3 rare
    names after learning; plus an established name, a subdomain, a country domain and a static-allowlisted one."""
    d = Path(tempfile.mkdtemp(prefix="sched_", dir=tmp))
    p = LocalPopularity(d / "pop.db", etld1_fn=etld1, now_fn=lambda: sclock[0],
                        learning_fn=lambda dev: dev in learning_devices)
    if warm:
        for i in range(8):
            p.observe("filler", f"f{i}.com", T0 + i * DAY)
            for dev in ("x", "y", "z"):
                p.observe(dev, "everyone.com", T0 + i * DAY)
    for n in ("c1.com", "c2.com", "c3.com", "c4.com"):
        p.observe("cam", n, T0 + 8 * DAY)
    p.observe("tv", "t1.net", T0 + 8 * DAY)
    for n in ("p1.org", "p2.org", "p3.org"):
        p.observe("pc", n, T0 + 8 * DAY)
    p.observe("cam", "www.sub.example.com", T0 + 8 * DAY)
    p.observe("cam", "rare.de", T0 + 8 * DAY)
    p.observe("cam", "allowed.com", T0 + 8 * DAY)
    p.flush()
    rdap = RdapAgeService(d / "rdap.db", lambda: enabled[0], http_get=http, now_fn=lambda: sclock[0])
    s = DomainAgeScheduler(rdap, p, registrable_fn=etld1_strict, known_good_fn=lambda n: n == "allowed.com",
                           now_fn=lambda: sclock[0])
    return p, rdap, s


def run(s, steps):
    out = []
    for _ in range(steps):
        out.append(s.tick())
        sclock[0] += MIN_INTERVAL_SECONDS
    return out


# --- off: nothing ---
pop_s, rdap_s, sched = setup({"cam"})
asked.clear()
enabled[0] = False
check("off: the scheduler sends nothing", run(sched, 5) == [DISABLED] * 5 and asked == [])

# --- normal mode only (already on before, so no re-verify) ---
rdap_s.set_meta("enabled_seen", "1")
enabled[0] = True
asked.clear()
run(sched, 12)
check("normal mode asks only about names first used during a learning period (a subdomain as its registrable base)",
      sorted(asked) == ["c1.com", "c2.com", "c3.com", "c4.com", "example.com"], str(asked))
check("never a full host name, a country domain, an allowlisted or an established name",
      not any(n in asked for n in ("www.sub.example.com", "sub.example.com", "rare.de", "allowed.com", "everyone.com")))
n = len(asked)
run(sched, 5)
check("once answered, nothing is asked again and the unit goes quiet", len(asked) == n)

# --- switched on a year later (nobody learning): every device re-verified, devices taking turns ---
owners = {"c1.com": "cam", "c2.com": "cam", "c3.com": "cam", "c4.com": "cam", "example.com": "cam", "t1.net": "tv",
          "p1.org": "pc", "p2.org": "pc", "p3.org": "pc", **{f"f{i}.com": "filler" for i in range(8)}}
pop_s, rdap_s, sched = setup(set())
enabled[0] = True
asked.clear()
run(sched, 4)
check("switching on re-verifies every device, taking turns: the first 4 lookups cover all 4 devices",
      {owners.get(n) for n in asked} == {"cam", "tv", "pc", "filler"}, str(asked))
st = sched.status()["reverify"]
check("progress is reported while it runs", st["active"] is True and st["devices_total"] == 4
      and st["devices_done"] < 4, str(st))
run(sched, 30)
check("every rare name of every device is checked, whenever it was adopted",
      sorted(asked) == sorted(owners), str(sorted(asked)))
sched._built_at = -1e18
run(sched, 2)
st = sched.status()["reverify"]
check("the re-verify completes and says so", st["active"] is False and st["completed_at"] is not None
      and st["devices_total"] == 4 and st["devices_done"] == 4, str(st))

# --- off stops, on again restarts without re-asking ---
enabled[0] = False
run(sched, 1)
check("switching off stops the re-verify", sched.status()["reverify"]["active"] is False)
pop_s.observe("pc", "p4.org", sclock[0])
pop_s.flush()
asked.clear()
enabled[0] = True
run(sched, 6)
check("switching on again restarts it, asking only about what was never answered", asked == ["p4.org"], str(asked))

# --- end to end: a young answer lifts the exemption ---
pop_e, rdap_e, sched_e = setup({"cam"})
REG.clear()
REG["c1.com"] = T0 + 8 * DAY - 5 * DAY       # registered 5 days before the camera first used it
REG["c2.com"] = T0 - 2000 * DAY
pop_e.age_fn = rdap_e.registration_ts
enabled[0] = True
for _ in range(3):                             # c1 used on 3+ days, so it would be "in use"
    pop_e.observe("cam", "c1.com", sclock[0])
    pop_e.observe("cam", "c2.com", sclock[0])
    sclock[0] += DAY
pop_e.flush()
pop_e._history_cache.clear()
check("before the lookup, the camera's C2 counts as in use", pop_e.is_preexisting("c1.com", device_id="cam") is True)
run(sched_e, 12)
pop_e._history_cache.clear()
check("after it, the young C2 no longer does; the novelty detectors judge it",
      pop_e.is_preexisting("c1.com", device_id="cam") is False)
check("the old domain is unaffected", pop_e.is_preexisting("c2.com", device_id="cam") is True)
enabled[0] = False
check("switching the setting off restores today's behaviour at once",
      pop_e.is_preexisting("c1.com", device_id="cam") is True)

# --- local names already in the ledger (recorded before `local_domain_suffixes` was set) are never asked about ---
from config import CONFIG  # noqa: E402
_saved_suffixes = CONFIG.get("local_domain_suffixes")


def set_local(value):
    with CONFIG._lock:
        CONFIG._config["local_domain_suffixes"] = value


set_local([])
pop_l, rdap_l, sched_l = setup({"cam"})
for n in ("grafana.sky", "_https.sky", "fritz.box", "my.fritz.box", "shop.box"):
    pop_l.observe("cam", n, T0 + 8 * DAY)
pop_l.flush()
set_local(["sky", "fritz.box"])
rdap_l.set_meta("enabled_seen", "1")
enabled[0] = True
asked.clear()
run(sched_l, 15)
check("the scheduler never asks about a local name the ledger already holds",
      not any(n.endswith(".sky") or n.endswith("fritz.box") for n in asked), str(asked))
check("a public name under the same gTLD is still asked about", "shop.box" in asked, str(asked))
set_local(_saved_suffixes)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("All domain-age gate and scheduler checks PASSED.")
