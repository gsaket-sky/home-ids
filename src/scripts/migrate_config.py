#!/usr/bin/env python3
"""migrate_config.py -- bring a deployment's config.yaml up to date with config.yaml.example
without overwriting it.

    python src/scripts/migrate_config.py                          # dry run: list what would change
    python src/scripts/migrate_config.py --apply                  # write it (backup first)
    python src/scripts/migrate_config.py --overrides host.yaml    # also pin this host's values

Rules:
  * ADD: keys present in the example but missing from config.yaml are inserted together with the
    comment block above them, into the same section. "Present" follows config.py's flattening
    (every top-level mapping is a category, its keys share one flat namespace), so a key the
    deployment keeps under a different section is never added a second time. Nested keys (e.g.
    scheduled_jobs.scheduler.live_prune.essential) are added inside their existing parent.
  * REMOVE: only keys listed in RETIRED_KEYS below -- never "anything not in the example", so a
    deployment's own extra keys survive.
  * OVERRIDES (optional file of flat key: scalar value): pins this host's value for a key, e.g.
    `scheduler_mode: external`. The only way this script ever changes an existing value.
  * VERIFY: the edited text must parse to exactly (old config + additions - retirements +
    overrides), or nothing is written. Comments and layout elsewhere are untouched (line-based
    edits: PyYAML's round trip would drop every comment).

Only block-style mappings are handled, which is how config.yaml.example is written.
"""
import argparse
import copy
import os
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import yaml

# Retired config keys (flat names, as config.py sees them) with the date and reason. Removed from
# a deployment's config.yaml by this script. Add a line whenever a key is dropped from
# config.yaml.example; keep old lines so a deployment that skipped releases still gets cleaned.
RETIRED_KEYS = {
    "ollama_cache_ttl_seconds": "2026-09-30: reader scripts/ollama_soc.py removed",
    "ollama_max_queries_per_run": "2026-09-30: reader scripts/ollama_soc.py removed",
    "health_manager_swap_pressure_pct": "2026-09-30: never read by health_manager.py",
    "health_manager_swap_critical_pct": "2026-09-30: never read by health_manager.py",
    "health_manager_recovery_confirm_seconds": "2026-09-30: never read by health_manager.py",
    "engine": "2026-10-03: the argus decision engine is the only engine (the old one is its in-process fallback)",
    "cl_afpe_engine": "2026-10-03: the argus CL-AFPE is the only engine (the old one is its in-process fallback)",
}

_KEY_RE = re.compile(r"^(?P<indent> *)(?P<key>[A-Za-z0-9_.\-]+|\"[^\"]+\"|'[^']+')\s*:(?P<rest>\s.*|)$")


# ----------------------------------------------------------------------------- text index

def _is_blank_or_comment(line: str) -> bool:
    s = line.strip()
    return not s or s.startswith("#")


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _index(lines: list) -> dict:
    """YAML key path (tuple) -> (start, end, indent). `start` is the key's line, `end` one past its
    last child/continuation line, trailing blank and comment lines excluded."""
    found = []
    stack = []  # (indent, key)
    for i, line in enumerate(lines):
        if _is_blank_or_comment(line) or line.lstrip().startswith("- "):
            continue
        m = _KEY_RE.match(line.rstrip("\r\n"))
        if not m:
            continue
        ind = _indent(line)
        while stack and stack[-1][0] >= ind:
            stack.pop()
        path = tuple(k for _, k in stack) + (m.group("key").strip("\"'"),)
        found.append((path, i, ind))
        stack.append((ind, path[-1]))

    out = {}
    for path, start, ind in found:
        end = len(lines)
        for j in range(start + 1, len(lines)):
            line = lines[j]
            if _is_blank_or_comment(line):
                continue
            if _indent(line) < ind or (_indent(line) == ind and not line.lstrip().startswith("- ")):
                end = j
                break
        while end > start + 1 and _is_blank_or_comment(lines[end - 1]):
            end -= 1
        out.setdefault(path, (start, end, ind))
    return out


def _comment_start(lines: list, start: int, indent: int) -> int:
    """First line of the comment block directly above `start` (same indent, no blank line in
    between) -- the key's own documentation, which moves or goes with it."""
    i = start
    while i > 0 and lines[i - 1].strip().startswith("#") and _indent(lines[i - 1]) == indent:
        i -= 1
    return i


# ----------------------------------------------------------------------------- data helpers

def _flat_locations(data: dict) -> dict:
    """flat key -> its path in the file (config.py flattening: top-level mappings are categories)."""
    loc = {}
    for top, val in (data or {}).items():
        if str(top).startswith(("_", "#")):
            continue
        if isinstance(val, dict):
            for k in val:
                loc.setdefault(k, (top, k))
        else:
            loc.setdefault(top, (top,))
    return loc


def _leaf_paths(value, prefix=()):
    if isinstance(value, dict) and value:
        for k, v in value.items():
            yield from _leaf_paths(v, prefix + (k,))
    else:
        yield prefix


def _get(d, path):
    for k in path:
        if not isinstance(d, dict) or k not in d:
            return None, False
        d = d[k]
    return d, True


def _set(d, path, value):
    for k in path[:-1]:
        d = d.setdefault(k, {})
    d[path[-1]] = value


def _delete(d, path):
    for k in path[:-1]:
        d = d[k]
    del d[path[-1]]


def _describe(path) -> str:
    return ".".join(str(p) for p in path)


# ----------------------------------------------------------------------------- planning

def plan(cfg: dict, ex: dict):
    """Returns (removals, additions, warnings). removals: config paths. additions: (example path,
    config parent path or None for a top-level block)."""
    cfg_loc, ex_loc = _flat_locations(cfg), _flat_locations(ex)
    cfg_categories = {t for t, v in cfg.items() if isinstance(v, dict)}
    removals = [cfg_loc[k] for k in RETIRED_KEYS if k in cfg_loc]
    additions, warnings = [], []

    def add(item):
        if item not in additions:
            additions.append(item)

    for key, ex_path in ex_loc.items():
        if key in RETIRED_KEYS:
            continue
        if key not in cfg_loc:
            if len(ex_path) == 1:
                add((ex_path, None))                       # top-level scalar key
            elif ex_path[0] in cfg_categories:
                add((ex_path, (ex_path[0],)))              # into the existing category
            else:
                siblings = [k for k in ex[ex_path[0]] if k in cfg_loc]
                if siblings:
                    warnings.append(f"category '{ex_path[0]}' missing but some of its keys live elsewhere "
                                    f"({', '.join(siblings)}); add '{key}' by hand")
                else:
                    add(((ex_path[0],), None))             # whole category block
            continue
        cfg_path = cfg_loc[key]
        ex_val, _ = _get(ex, ex_path)
        cfg_val, _ = _get(cfg, cfg_path)
        if not (isinstance(ex_val, dict) and isinstance(cfg_val, dict)):
            continue
        for sub in _leaf_paths(ex_val):                     # missing nested options
            for depth in range(1, len(sub) + 1):
                val, found = _get(cfg_val, sub[:depth])
                if not found:
                    add((ex_path + sub[:depth], cfg_path + sub[:depth - 1]))
                    break
                if not isinstance(val, dict):
                    break                                   # deployment has a scalar here: leave it
    return removals, additions, warnings


def _target(ex_path, parent):
    return (tuple(parent) + (ex_path[-1],)) if parent else tuple(ex_path)


# ----------------------------------------------------------------------------- editing

def _normalise(text: str) -> list:
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    return lines


def edit_structure(config_text: str, example_text: str, removals, additions) -> str:
    lines, ex_lines = _normalise(config_text), _normalise(example_text)
    idx, ex_idx = _index(lines), _index(ex_lines)
    edits = []  # (pos, until, seq, new_lines), applied bottom-up

    for path in removals:
        start, end, ind = idx[path]
        first = _comment_start(lines, start, ind)
        # don't leave a double blank line where the block was
        if first > 0 and not lines[first - 1].strip() and end < len(lines) and not lines[end].strip():
            end += 1
        edits.append((first, end, len(edits), []))

    for ex_path, parent in additions:
        start, end, ex_ind = ex_idx[ex_path]
        block = ex_lines[_comment_start(ex_lines, start, ex_ind):end]
        if parent is None:
            pos, new_ind, block = len(lines), 0, ["\n"] + block
        else:
            p_start, p_end, p_ind = idx[parent]
            kids = [v[2] for p, v in idx.items() if len(p) == len(parent) + 1 and p[:-1] == tuple(parent)]
            new_ind, pos = (kids[0] if kids else p_ind + 2), p_end
        shift = new_ind - ex_ind
        fixed = []
        for b in block:
            if b.strip():
                b = (" " * shift + b) if shift >= 0 else b[min(-shift, _indent(b)):]
            fixed.append(b)
        edits.append((pos, pos, len(edits), fixed))

    # Bottom-up so earlier positions stay valid; for inserts at the same position the LATER
    # addition goes in first, so the final order matches the example's order.
    for pos, until, _seq, new in sorted(edits, key=lambda e: (e[0], e[1], e[2]), reverse=True):
        lines[pos:until] = new
    return "".join(lines)


def edit_overrides(text: str, data: dict, overrides: dict) -> str:
    """Rewrites the value on the line of each overridden flat key (scalar values only)."""
    lines = _normalise(text)
    idx = _index(lines)
    loc = _flat_locations(data)
    for key, value in overrides.items():
        path = loc[key]
        start, end, _ = idx[path]
        if end != start + 1:
            raise ValueError(f"override for '{key}': its current value spans several lines; edit it by hand")
        m = _KEY_RE.match(lines[start].rstrip("\r\n"))
        comment = re.search(r"\s+#\s.*$", m.group("rest") or "")
        rendered = yaml.safe_dump(value, default_flow_style=True).strip()
        rendered = rendered[:-4].rstrip() if rendered.endswith("\n...") else rendered.replace("\n...", "")
        lines[start] = f"{m.group('indent')}{m.group('key')}: {rendered}{comment.group(0) if comment else ''}\n"
    return "".join(lines)


# ----------------------------------------------------------------------------- entry points

def migrate(config_text: str, example_text: str, overrides: dict = None):
    """Returns (new_text, report_lines, changed). Raises ValueError when the result can't be
    verified -- callers must then leave the file alone."""
    cfg = yaml.safe_load(config_text) or {}
    ex = yaml.safe_load(example_text) or {}
    removals, additions, warnings = plan(cfg, ex)

    want = copy.deepcopy(cfg)
    for path in removals:
        _delete(want, path)
    for ex_path, parent in additions:
        _set(want, _target(ex_path, parent), copy.deepcopy(_get(ex, ex_path)[0]))

    report = [f"  - {_describe(p)}   ({RETIRED_KEYS[p[-1]]})" for p in removals]
    report += [f"  + {_describe(_target(e, p))}" for e, p in additions]
    new_text = edit_structure(config_text, example_text, removals, additions) if (removals or additions) else config_text

    override_changes = {}
    if overrides:
        mid = yaml.safe_load(new_text) or {}
        loc = _flat_locations(mid)
        for key, value in overrides.items():
            if isinstance(value, (dict, list)):
                raise ValueError(f"override for '{key}' must be a scalar")
            if key not in loc:
                raise ValueError(f"override for '{key}': key not in config.yaml or the example")
            if _get(mid, loc[key])[0] != value:
                override_changes[key] = value
                _set(want, loc[key], value)
                report.append(f"  = {_describe(loc[key])}  (host override)")
        if override_changes:
            new_text = edit_overrides(new_text, mid, override_changes)

    report += [f"  ! {w}" for w in warnings]
    changed = bool(removals or additions or override_changes)
    if changed and (yaml.safe_load(new_text) or {}) != want:
        raise ValueError("the edited file would not parse to exactly (old + additions - retired + overrides)")
    return new_text, report, changed


def _atomic_write(path: Path, text: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        shutil.copymode(path, tmp)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv=None) -> int:
    root = Path(__file__).resolve().parent.parent.parent
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", default=str(root / "config.yaml"))
    example = root / "docker" / "config" / "ids" / "config.yaml.example"   # the product template; home_ids keeps it at the root
    ap.add_argument("--example", default=str(example if example.exists() else root / "config.yaml.example"))
    ap.add_argument("--overrides", help="YAML file of flat key: scalar value pinned for this host")
    ap.add_argument("--apply", action="store_true", help="write the result (default: dry run)")
    a = ap.parse_args(argv)

    config_path = Path(a.config)
    overrides = {}
    if a.overrides:
        overrides = yaml.safe_load(Path(a.overrides).read_text(encoding="utf-8")) or {}
    try:
        new_text, report, changed = migrate(config_path.read_text(encoding="utf-8"),
                                             Path(a.example).read_text(encoding="utf-8"), overrides)
    except ValueError as exc:
        print(f"REFUSING, nothing written: {exc}", file=sys.stderr)
        return 3

    print(f"{config_path}: {'changes' if changed else 'up to date'}")
    if report:
        print("\n".join(report))
    if not changed:
        return 0
    if not a.apply:
        print("Dry run only (result verified). Re-run with --apply to write.")
        return 0
    backup = config_path.with_name(f"{config_path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}-migrate")
    shutil.copy2(config_path, backup)
    _atomic_write(config_path, new_text)
    print(f"Written. Backup: {backup}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
