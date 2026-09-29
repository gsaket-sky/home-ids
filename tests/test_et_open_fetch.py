"""Standalone test (run directly): src/intelligence/et_open_fetch.py -- ET Open device-side updater.

Everything is offline: a fake clock and a fake HTTP layer drive every path (change detection,
back-off, garbage/truncated downloads, shrink guard, fallback URL, ETag)."""
import hashlib
import io
import random
import sys
import tarfile
import tempfile
from pathlib import Path as _P
sys.path.insert(0, str(_P(__file__).resolve().parent.parent / "src"))
from intelligence.et_open_fetch import ETOpenUpdater, DAY

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


def make_rules(n_ips=60, n_domains=30):
    lines = []
    lines.append('alert ip [%s] any -> $HOME_NET any (msg:"ET CINS Poor Reputation IP group 1"; sid:2403300; rev:1;)'
                 % ",".join(f"45.{i % 200 + 1}.{i // 200 + 1}.9" for i in range(n_ips)))
    for i in range(n_domains):
        lines.append(f'alert dns $HOME_NET any -> any any (msg:"ET MALWARE Evil {i}"; dns.query; content:"evil{i}.example-bad.net"; '
                     f'endswith; classtype:trojan-activity; sid:{2100000 + i}; rev:1;)')
    return "\n".join(lines) + "\n"


def make_archive(rules_text: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = rules_text.encode()
        info = tarfile.TarInfo("rules/emerging-test.rules")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class FakeNet:
    def __init__(self):
        self.version = "100"
        self._archive = b""
        self.etag = ""
        self.archive = make_archive(make_rules())
        self.calls = []            # (url, headers)
        self.version_code = 200
        self.rules_code = 200
        self.raise_on_version = None
        self.first_rules_url_code = None  # if set, the FIRST rules URL returns this code

    @property
    def archive(self):
        return self._archive

    @archive.setter
    def archive(self, value):
        # a real server's ETag changes when the content changes
        self._archive = value
        self.etag = '"%s"' % hashlib.md5(value).hexdigest()

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        if url.endswith("version.txt"):
            if self.raise_on_version:
                raise self.raise_on_version
            return self.version_code, {}, self.version.encode() if self.version_code == 200 else b""
        if self.first_rules_url_code is not None and "7.0.3" in url:
            return self.first_rules_url_code, {}, b""
        if headers.get("If-None-Match") == self.etag and self.rules_code == 200:
            return 304, {}, b""
        return self.rules_code, {"etag": self.etag}, self.archive if self.rules_code == 200 else b""

    def downloads(self):
        return [c for c in self.calls if "emerging.rules" in c[0]]


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


def new_updater(d, net, clock, **kw):
    kw.setdefault("min_ips", 20)
    kw.setdefault("min_domains", 10)
    return ETOpenUpdater(d, http_get=net, now=clock, rng=random.Random(1), **kw)


with tempfile.TemporaryDirectory() as d:
    net, clock = FakeNet(), Clock()
    u = new_updater(d, net, clock)

    r = u.update()
    check("first run downloads and installs an index", r.status == "updated" and u.index_path.exists(), r.detail)
    check("parsed IOCs are returned to the caller", r.parsed is not None and len(r.parsed.domains) == 30)
    st = u._state()
    check("next_due is one interval + jitter away (spreads a fleet)",
          clock.t + DAY <= st["next_due"] <= clock.t + DAY + 3600, str(st.get("next_due")))
    check("age_seconds() is 0 right after success", u.age_seconds() == 0)

    n_before = len(net.calls)
    r = u.update()
    check("a second call before it's due does no network I/O", r.status == "skipped" and len(net.calls) == n_before)

    clock.t += DAY + 4000
    n_dl = len(net.downloads())
    r = u.update()
    check("same version.txt -> 'unchanged' and NO tarball download",
          r.status == "unchanged" and len(net.downloads()) == n_dl, r.detail)
    check("an 'unchanged' check still counts as fresh (age resets)", u.age_seconds() == 0)

    # version changed but the new archive is truncated -> rejected, old index kept
    clock.t += DAY + 4000
    net.version = "101"
    net.archive = make_archive(make_rules(n_ips=25, n_domains=11))   # < 60% of 90 indicators
    old_counts = u.load_current()[0].counts()
    r = u.update()
    check("a sharply shrunken ruleset is rejected", r.status == "rejected" and "shrank" in r.detail, r.detail)
    check("the last good index is untouched after a rejection", u.load_current()[0].counts() == old_counts)

    # garbage archive -> rejected, old index kept
    clock.t += 7200
    net.archive = b"this is not a tarball"
    r = u.update()
    check("a garbage archive is rejected (never raises)", r.status == "rejected", r.detail)
    check("index still the last good one", u.load_current()[0].counts() == old_counts)

    # good new version installs
    clock.t += 7200
    net.version = "102"
    net.archive = make_archive(make_rules(n_ips=70, n_domains=35))
    r = u.update()
    check("a healthy new version replaces the index", r.status == "updated" and len(u.load_current()[0].domains) == 35, r.detail)

    # ETag / 304
    clock.t += DAY + 4000
    net.version = "103"   # version bump but body identical -> server answers 304 to If-None-Match
    r = u.update()
    check("If-None-Match is sent and a 304 is treated as unchanged", r.status == "unchanged" and
          any(c[1].get("If-None-Match") == net.etag for c in net.downloads()), r.detail)

with tempfile.TemporaryDirectory() as d:
    # rate limiting
    net, clock = FakeNet(), Clock()
    u = new_updater(d, net, clock)
    net.version_code = 429
    r = u.update()
    check("HTTP 429 -> 'rate_limited' with the publisher's 30-minute cool-down",
          r.status == "rate_limited" and u._state()["next_allowed"] == clock.t + 1800)
    check("nothing is attempted during the cool-down", u.update().status == "skipped")
    clock.t += 1801
    r = u.update()
    check("a second 429 doubles the back-off", u._state()["next_allowed"] == clock.t + 3600, str(u._state()))
    clock.t += 3601
    net.version_code = 200
    r = u.update()
    check("recovers after the cool-down and resets the back-off",
          r.status == "updated" and u._state()["rate_limited"] == 0, r.detail)

with tempfile.TemporaryDirectory() as d:
    # errors
    net, clock = FakeNet(), Clock()
    u = new_updater(d, net, clock)
    net.raise_on_version = OSError("network unreachable")
    r = u.update()
    check("a network error is reported, not raised, and backs off", r.status == "error" and u._state()["failures"] == 1)
    check("no index is created by a failed first run", not u.index_path.exists())
    clock.t += 901
    net.raise_on_version = None
    net.first_rules_url_code = 500
    r = u.update()
    check("falls back to the second ruleset URL when the first fails", r.status == "updated", r.detail)

with tempfile.TemporaryDirectory() as d:
    # first-ever install with a too-small result
    net, clock = FakeNet(), Clock()
    net.archive = make_archive(make_rules(n_ips=3, n_domains=2))
    u = new_updater(d, net, clock, min_ips=20, min_domains=10)
    r = u.update()
    check("a too-small first download is rejected and creates no index",
          r.status == "rejected" and not u.index_path.exists(), r.detail)

with tempfile.TemporaryDirectory() as d:
    # shrink guard force-accepts after a week of rejects (hands-off: the source really changed)
    net, clock = FakeNet(), Clock()
    u = new_updater(d, net, clock)
    u.update()
    net.archive = make_archive(make_rules(n_ips=25, n_domains=11))
    statuses = []
    for i in range(8):
        clock.t += (DAY + 4000) if i == 0 else 3700   # first check must be past the daily due time
        net.version = str(200 + i)
        statuses.append(u.update().status)
    check("after 7 consecutive shrink-rejections the new smaller data is accepted",
          statuses[:6] == ["rejected"] * 6 and "updated" in statuses[6:], str(statuses))

with tempfile.TemporaryDirectory() as d:
    # force
    net, clock = FakeNet(), Clock()
    u = new_updater(d, net, clock)
    u.update()
    n = len(net.downloads())
    r = u.update(force=True)
    check("force=True re-downloads even when nothing changed", len(net.downloads()) == n + 1, r.status)

if FAILURES:
    print(f"FAILED: {FAILURES}")
    sys.exit(1)
print("All checks PASSED.")
