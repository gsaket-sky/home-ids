"""
RDAP domain-age client (src/intelligence/rdap_age.py), part 1 of the domain-age build. No network: a fake HTTP layer.

Covers: nothing sent while switched off, and the setting is read live; gTLD-only; the registration date is parsed and
kept; answers are reused (date and no-date lifetimes); 404 is "no date"; errors and refusals never become answers;
never a local name (configured suffixes, even under a real gTLD); the 10-second gap, the daily cap, and 429 back-off per registry honouring Retry-After; the registry list is fetched
once, kept, refreshed weekly, survives a failed refresh, and with none nothing is looked up; only the name is sent.

Run directly: `venv/Scripts/python.exe tests/test_argus_rdap_age.py`
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


from intelligence import rdap_age  # noqa: E402
from intelligence.rdap_age import (RdapAgeService, CACHED, LOOKED_UP, DISABLED, NOT_GTLD, LOCAL, NO_SERVER,  # noqa: E402
                                   DAILY_LIMIT, TOO_SOON, BACKOFF, ERROR, DAILY_CAP, MIN_INTERVAL_SECONDS,
                                   DATE_TTL_DAYS, NO_DATA_TTL_DAYS, BOOTSTRAP_URL, BOOTSTRAP_REFRESH_SECONDS,
                                   is_gtld_name)

T0 = 1_800_000_000.0
clock = [T0]
enabled = [True]
calls = []
BOOTSTRAP = {"services": [[["com", "net"], ["http://rdap.verisign.example/", "https://rdap.verisign.example/com/v1/"]],
                          [["xyz"], ["https://rdap.xyz.example/"]], [["de"], ["https://rdap.denic.example/"]],
                          [["sky", "box"], ["https://rdap.nic.example/"]]]}
registered_at = {"young.com": "2026-09-20T10:11:12Z", "old.net": "2009-01-02T00:00:00+00:00"}
script = {}     # url -> (code, body, headers) overrides
boot_ok = [True]


def fake_http(url, headers, timeout):
    calls.append((url, dict(headers)))
    if url == BOOTSTRAP_URL:
        return (200, json.dumps(BOOTSTRAP), {}) if boot_ok[0] else (500, "", {})
    if url in script:
        return script[url]
    name = url.rsplit("/", 1)[1]
    if name in registered_at:
        return 200, json.dumps({"objectClassName": "domain",
                                "events": [{"eventAction": "last changed", "eventDate": "2026-10-01T00:00:00Z"},
                                           {"eventAction": "registration", "eventDate": registered_at[name]}]}), {}
    return 404, "{}", {}


def fresh():
    clock[0] = T0
    calls.clear()
    script.clear()
    boot_ok[0] = True
    enabled[0] = True
    return RdapAgeService(Path(tempfile.mkdtemp(prefix="rdap_")) / "rdap.db", lambda: enabled[0], http_get=fake_http,
                          now_fn=lambda: clock[0])


def lookups():
    return [c for c in calls if c[0] != BOOTSTRAP_URL]


def advance(seconds):
    clock[0] += seconds


# --- gTLD rule ---------------------------------------------------------------------------------------------------------
check("gTLD names qualify", all(is_gtld_name(n) for n in ("a.com", "a.b.shop", "x.xyz", "A.Com.")))
check("country-code, IDN country-code and dotless names do not",
      not any(is_gtld_name(n) for n in ("a.de", "a.co.uk", "a.xn--p1ai", "localhost", "", "com")))

# --- switched off: nothing is sent ---------------------------------------------------------------------------------------
svc = fresh()
enabled[0] = False
check("off: lookup sends nothing and says so", svc.lookup("young.com") == DISABLED and calls == [])
check("off: registration_ts answers None", svc.registration_ts("young.com") is None)
enabled[0] = True
check("the setting is read live (on now)", svc.lookup("young.com") == LOOKED_UP)
enabled[0] = False
check("a stored answer is hidden again while switched off", svc.registration_ts("young.com") is None)
enabled[0] = True

# --- looking up, parsing, privacy ---------------------------------------------------------------------------------------
svc = fresh()
check("a lookup goes out and is stored", svc.lookup("young.com") == LOOKED_UP and len(lookups()) == 1)
want = datetime(2026, 9, 20, 10, 11, 12, tzinfo=timezone.utc).timestamp()
check("the registration event date is parsed (Z suffix) to epoch", svc.registration_ts("Young.COM.") == want,
      str(svc.registration_ts("young.com")))
url, headers = lookups()[0]
check("the https registry URL is used with the bare name", url == "https://rdap.verisign.example/com/v1/domain/young.com", url)
check("only a generic User-Agent and Accept go out", set(headers) == {"Accept", "User-Agent"} and headers["User-Agent"] == "Home-IDS")
check("a second ask is answered from the store without sending", svc.lookup("young.com") == CACHED and len(lookups()) == 1)
advance(MIN_INTERVAL_SECONDS + 1)
check("an offset date (+00:00) parses too", svc.lookup("old.net") == LOOKED_UP
      and svc.registration_ts("old.net") == datetime(2009, 1, 2, tzinfo=timezone.utc).timestamp())

# --- not looked up -------------------------------------------------------------------------------------------------------
advance(MIN_INTERVAL_SECONDS + 1)
check("a country domain is never looked up", svc.lookup("example.de") == NOT_GTLD and not any("example.de" in c[0] for c in calls))
check("a gTLD without a registry in the list is not looked up", svc.lookup("example.shop") == NO_SERVER)

# --- local names: never sent, even when the local suffix is a real gTLD (.sky, fritz.box under .box) --------------------
from config import CONFIG  # noqa: E402
_saved_suffixes = CONFIG.get("local_domain_suffixes")
with CONFIG._lock:
    CONFIG._config["local_domain_suffixes"] = ["sky", "fritz.box"]
svc = fresh()
check("a name under a configured local suffix is never looked up",
      all(svc.lookup(n) == LOCAL for n in ("grafana.sky", "_https.sky", "fritz.box", "my.fritz.box"))
      and lookups() == [], str(lookups()))
check("a public name under the same gTLD is still looked up", svc.lookup("shop.box") == LOOKED_UP)
check("a built-in local suffix is refused too", svc.lookup("printer.internal") in (LOCAL, NOT_GTLD)
      and not any("printer" in c[0] for c in calls))
with CONFIG._lock:
    CONFIG._config["local_domain_suffixes"] = _saved_suffixes

# --- 404 and failures ---------------------------------------------------------------------------------------------------
svc = fresh()
check("404 is stored as 'no date', not an error", svc.lookup("ghost.com") == LOOKED_UP and svc.registration_ts("ghost.com") is None
      and svc.has_fresh_answer("ghost.com"))
advance(MIN_INTERVAL_SECONDS + 1)
script["https://rdap.verisign.example/com/v1/domain/broken.com"] = (500, "oops", {})
check("a server error is not stored", svc.lookup("broken.com") == ERROR and not svc.has_fresh_answer("broken.com"))
advance(MIN_INTERVAL_SECONDS + 1)
script["https://rdap.verisign.example/com/v1/domain/nodate.com"] = (200, json.dumps({"events": []}), {})
check("a reply without a registration event is 'no date'", svc.lookup("nodate.com") == LOOKED_UP
      and svc.registration_ts("nodate.com") is None and svc.has_fresh_answer("nodate.com"))
advance(MIN_INTERVAL_SECONDS + 1)
script["https://rdap.verisign.example/com/v1/domain/junk.com"] = (200, "not json", {})
check("an unparsable reply is 'no date', never a crash", svc.lookup("junk.com") == LOOKED_UP and svc.registration_ts("junk.com") is None)

# --- answer lifetimes ---------------------------------------------------------------------------------------------------
svc = fresh()
svc.lookup("young.com")
advance(MIN_INTERVAL_SECONDS + 1)
svc.lookup("ghost.com")
advance((NO_DATA_TTL_DAYS - 1) * 86400)
check("a 'no date' answer is kept for its lifetime", svc.has_fresh_answer("ghost.com"))
advance(2 * 86400)
check("and expires after it", not svc.has_fresh_answer("ghost.com"))
check("a date is kept far longer", svc.registration_ts("young.com") is not None and svc.has_fresh_answer("young.com"))
advance((DATE_TTL_DAYS) * 86400)
check("after its lifetime a date may be asked again (re-registration)", not svc.has_fresh_answer("young.com"))
check("but stays readable: an old C2 domain must not turn 'unknown' and become normal again",
      svc.registration_ts("young.com") is not None and svc.has_answer("young.com"))
check("a name never asked about has no answer", not svc.has_answer("never.com"))

# --- pacing and the daily cap ---------------------------------------------------------------------------------------------
svc = fresh()
svc.lookup("a1.com")
check("a second lookup inside the minimum gap waits", svc.lookup("a2.com") == TOO_SOON and svc.seconds_until_next_allowed() > 0)
advance(MIN_INTERVAL_SECONDS)
check("after the gap it goes out", svc.lookup("a2.com") == LOOKED_UP)
check("the gap survives a restart", RdapAgeService(svc.db_path, lambda: True, http_get=fake_http, now_fn=lambda: clock[0])
      .lookup("a3.com") == TOO_SOON)

svc = fresh()
sent = 0
for i in range(DAILY_CAP + 5):
    out = svc.lookup(f"n{i}.com")
    if out == LOOKED_UP:
        sent += 1
    advance(MIN_INTERVAL_SECONDS)
check("no more than the daily cap goes out in a day", sent == DAILY_CAP and svc.used_today() == DAILY_CAP, f"{sent}")
check("and the next lookup says so", svc.lookup("over.com") == DAILY_LIMIT)
advance(86400)
check("the next day it starts again", svc.lookup("over.com") == LOOKED_UP)

# --- 429 back-off ------------------------------------------------------------------------------------------------------
svc = fresh()
script["https://rdap.verisign.example/com/v1/domain/slow.com"] = (429, "", {"retry-after": "120"})
check("429 backs the registry off", svc.lookup("slow.com") == BACKOFF and not svc.has_fresh_answer("slow.com"))
advance(MIN_INTERVAL_SECONDS + 1)
n = len(lookups())
check("while backed off nothing else goes to that registry", svc.lookup("other.com") == BACKOFF and len(lookups()) == n)
check("another registry is not affected", (advance(0) or svc.lookup("fine.xyz")) == LOOKED_UP)
advance(125)
check("after Retry-After it resumes", svc.lookup("other.com") == LOOKED_UP)
svc = fresh()
script["https://rdap.verisign.example/com/v1/domain/slow.com"] = (429, "", {})
svc.lookup("slow.com")
advance(3000)
check("without Retry-After the default back-off applies (an hour)", svc.lookup("other.com") == BACKOFF)
advance(700)
check("and ends", svc.lookup("other.com") == LOOKED_UP)

# --- the registry list --------------------------------------------------------------------------------------------------
svc = fresh()
svc.lookup("a.com")
advance(MIN_INTERVAL_SECONDS)
svc.lookup("b.com")
check("the registry list is fetched once and kept", sum(1 for c in calls if c[0] == BOOTSTRAP_URL) == 1)
svc2 = RdapAgeService(svc.db_path, lambda: True, http_get=fake_http, now_fn=lambda: clock[0])
advance(MIN_INTERVAL_SECONDS)
n = sum(1 for c in calls if c[0] == BOOTSTRAP_URL)
svc2.lookup("c.com")
check("and read from the database after a restart", sum(1 for c in calls if c[0] == BOOTSTRAP_URL) == n)
advance(BOOTSTRAP_REFRESH_SECONDS + 1)
svc2.lookup("d.com")
check("it is refreshed weekly", sum(1 for c in calls if c[0] == BOOTSTRAP_URL) == n + 1)
boot_ok[0] = False
advance(BOOTSTRAP_REFRESH_SECONDS + 1)
check("a failed refresh keeps the last copy", svc2.lookup("e.com") == LOOKED_UP)

svc = fresh()
boot_ok[0] = False
check("with no registry list at all nothing is looked up", svc.lookup("a.com") == NO_SERVER and lookups() == [])

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) FAILED:")
    for f in FAILURES:
        print(f"   - {f}")
    sys.exit(1)
print("All RDAP domain-age client checks PASSED.")
