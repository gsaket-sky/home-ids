"""
Atomic writers (W-12; runtime trace run 2 finding 4.5) and `clean_confirmed_intel.py --remove` (MASTER_TODO M3).

The feed snapshot combined.json.gz, feed_health.json and autotune_stats.json were written straight to their final
path by the engine, the retro-hunter and the scheduler's jobs: a crash or an overlapping write left a torn file.
Covers: atomic_write_text / atomic_write_gzip_json replace in one step and leave the old file intact (and no temp
file) when the write fails; LocalConfirmedIntel.remove deletes one entry only; the --remove CLI path is a dry run
until --apply, treats an address as an IP and anything else as a domain, and tells you about a missing entry.

Run directly: `venv/Scripts/python.exe tests/test_atomic_writes_and_intel_remove.py`
"""
import gzip
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

FAILURES = []


def check(name, cond, detail=""):
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        FAILURES.append(name)


from core.file_lock import atomic_write_gzip_json, atomic_write_text  # noqa: E402
from intelligence.local_intel import LocalConfirmedIntel  # noqa: E402
import clean_confirmed_intel as cci  # noqa: E402

tmp = Path(tempfile.mkdtemp(prefix="atomic_"))

p = tmp / "feed_health.json"
atomic_write_text(p, '{"a": 1}')
check("atomic_write_text writes the file", json.loads(p.read_text()) == {"a": 1})
class Boom:
    def __str__(self):
        raise RuntimeError("boom")
try:
    atomic_write_text(p, Boom())   # type: ignore[arg-type]  -- fails inside write_text
except Exception:
    pass
check("a failed write leaves the previous content", json.loads(p.read_text()) == {"a": 1})
check("...and no temp file", [f.name for f in tmp.iterdir() if f.name.endswith(".tmp")] == [])

g = tmp / "combined.json.gz"
atomic_write_gzip_json(g, {"ips": {"1.2.3.4": {}}})
with gzip.open(g, "rt", encoding="utf-8") as fh:
    check("atomic_write_gzip_json writes a readable gzip document", json.load(fh) == {"ips": {"1.2.3.4": {}}})
try:
    atomic_write_gzip_json(g, {"x": object()})   # not JSON-serialisable: fails mid-write
except TypeError:
    pass
with gzip.open(g, "rt", encoding="utf-8") as fh:
    check("a failed gzip write leaves the previous snapshot readable", json.load(fh) == {"ips": {"1.2.3.4": {}}})
check("...and no temp file", [f.name for f in tmp.iterdir() if f.name.endswith(".tmp")] == [])

# --- LocalConfirmedIntel.remove / the CLI -------------------------------------------------------------------------
state = tmp / "state"
store = LocalConfirmedIntel(state)
store.record("ip", "198.51.100.7", "dev_a", reason="TEST")
store.record("ip", "198.51.100.8", "dev_a", reason="TEST")
store.record("domain", "bad.example", "dev_a", reason="TEST")
intel_path = state / "local_confirmed_intel.json"

rc = cci._remove_chosen(intel_path, ["198.51.100.7", "bad.example"], apply_changes=False)
other = LocalConfirmedIntel(state)
check("dry run changes nothing", rc == 0 and other.check("ip", "198.51.100.7") and other.check("domain", "bad.example"))
rc = cci._remove_chosen(intel_path, ["198.51.100.7", "Bad.Example."], apply_changes=True)
other = LocalConfirmedIntel(state)
check("--apply removes the address as an IP entry and the name as a domain entry",
      rc == 0 and other.check("ip", "198.51.100.7") is None and other.check("domain", "bad.example") is None)
check("the other entry stays", other.check("ip", "198.51.100.8") is not None)
check("a running store sees the removal (mtime reload) and can still write",
      store.check("ip", "198.51.100.7") is None)
store.record("ip", "198.51.100.9", "dev_b", reason="T")
check("...and its next write keeps the removal (does not resurrect the entry) and the other entries",
      LocalConfirmedIntel(state).check("ip", "198.51.100.7") is None
      and LocalConfirmedIntel(state).check("ip", "198.51.100.8") is not None
      and LocalConfirmedIntel(state).check("ip", "198.51.100.9") is not None)
check("removing a missing entry reports it and fails only when nothing matched",
      cci._remove_chosen(intel_path, ["203.0.113.250"], apply_changes=True) == 1
      and cci._remove_chosen(intel_path, ["203.0.113.250", "198.51.100.8"], apply_changes=False) == 0)
check("remove() on an unknown kind or empty value is a no-op",
      store.remove("url", "x") is False and store.remove("ip", "") is False)

if FAILURES:
    print(f"\n{len(FAILURES)} check(s) FAILED")
    sys.exit(1)
print("\nAll atomic-write and intel --remove checks PASSED.")
