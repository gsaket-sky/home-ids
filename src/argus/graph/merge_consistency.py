"""
merge_consistency.py -- does the graph agree with the engine about which device ids were merged, and if not, fix it.

Two stores record a device merge: the engine (StateManager's merge redirects, persisted in state/ids_state.db) and the
graph (devices.merged_into_device_id). Every merge path merges in the engine first and then mirrors the merge into the
graph, best-effort; a failed mirror leaves the graph behind for good, because nothing replays it. Before the 2026-10-02
fix the identity-reconcile worker's mirror failed on every call (cross-thread SQLite error, logged at DEBUG). On .94
the graph then disagreed with the engine on 33 of 113 merges: 17 ids the engine had merged away still looked like live
devices in the graph, and one phone showed up as three ids.

The engine is the reference. It makes every merge decision (each graph merge is a mirror of one), it routes traffic by
its own redirects, and its redirect map is flat: orphan -> the live canonical id, one hop, latest decision wins. So the
graph is brought in line with the engine, never the reverse.

Each engine redirect orphan -> canonical falls into one kind:
  ok          the graph resolves both ids to the same device.
  absent      the graph has no row for the orphan. It never saw that id, so there is nothing to fix.
  missing     the graph stops short: the orphan resolves to a device the engine also merged into canonical (often the
              orphan itself, still live in the graph). Fix: merge that device into canonical.
  diverged    the graph has the orphan under a different device than the engine. The engine's redirect is the later
              decision (the graph mirror of it failed). Fix: point the orphan at canonical.
  unresolved  no merge replay can fix it: the graph has merged the engine's canonical itself into another device, or a
              merge chain cycles. Counted and logged; left alone.

Nothing here knows about any particular network or Prometheus; callers publish the counts.
"""
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Tuple

LOGGER = logging.getLogger("home_ids.argus.merge_consistency")

KINDS = ("ok", "absent", "missing", "diverged", "unresolved")
REPAIRABLE_KINDS = ("missing", "diverged")


@dataclass
class MergeItem:
    orphan_id: str
    canonical_id: str                  # the engine's canonical
    kind: str
    graph_root: Optional[str] = None   # where the graph resolves the orphan (None: absent or a cycle)
    repair_from: Optional[str] = None  # the device to merge into canonical_id, for a repairable kind
    reason: str = ""


@dataclass
class MergeReport:
    items: List[MergeItem] = field(default_factory=list)
    repaired: int = 0                  # merges written to the graph by repair_merges()
    repair_failures: int = 0

    def counts(self) -> Dict[str, int]:
        out = {k: 0 for k in KINDS}
        for item in self.items:
            out[item.kind] += 1
        return out

    def disagreements(self) -> List[MergeItem]:
        return [i for i in self.items if i.kind not in ("ok", "absent")]


def _root(pointers: Mapping[str, Optional[str]], device_id: str) -> Optional[str]:
    """Follow merged_into_device_id to the end; None on a cycle."""
    seen = set()
    cur = device_id
    while True:
        if cur in seen:
            return None
        seen.add(cur)
        nxt = pointers.get(cur)
        if not nxt:
            return cur
        cur = nxt


def classify(orphan_id: str, canonical_id: str, redirects: Mapping[str, str],
             pointers: Mapping[str, Optional[str]]) -> MergeItem:
    if orphan_id not in pointers:
        return MergeItem(orphan_id, canonical_id, "absent")
    g_orphan = _root(pointers, orphan_id)
    g_canon = _root(pointers, canonical_id)
    if g_orphan is None or g_canon is None:
        return MergeItem(orphan_id, canonical_id, "unresolved", g_orphan, reason="merge chain cycles in the graph")
    if g_orphan == g_canon:
        return MergeItem(orphan_id, canonical_id, "ok", g_orphan)
    if g_canon != canonical_id:
        return MergeItem(orphan_id, canonical_id, "unresolved", g_orphan,
                         reason=f"the graph merged the engine's canonical into {g_canon}")
    if g_orphan == orphan_id or redirects.get(g_orphan) == canonical_id:
        return MergeItem(orphan_id, canonical_id, "missing", g_orphan, repair_from=g_orphan)
    return MergeItem(orphan_id, canonical_id, "diverged", g_orphan, repair_from=orphan_id,
                     reason=f"the graph has it under {g_orphan}")


def check_merges(redirects: Mapping[str, str], pointers: Mapping[str, Optional[str]]) -> MergeReport:
    """Read-only comparison. `redirects`: the engine's {orphan: canonical}; `pointers`: GraphStore.get_merge_pointers()."""
    report = MergeReport()
    for orphan_id, canonical_id in redirects.items():
        if not orphan_id or not canonical_id or orphan_id == canonical_id:
            continue
        report.items.append(classify(orphan_id, canonical_id, redirects, pointers))
    return report


def repair_merges(store, redirects: Mapping[str, str]) -> MergeReport:
    """Replays the merges the graph is missing (kinds `missing` and `diverged`) through GraphStore.merge_device(), the
    same audit-preserving call the failed mirror would have made, then returns a fresh comparison with `repaired` and
    `repair_failures` set. Each repair is one transaction; a refused or failed one is logged and skipped."""
    pointers = dict(store.get_merge_pointers())
    planned: List[Tuple[str, str]] = []
    for item in check_merges(redirects, pointers).items:
        if item.kind in REPAIRABLE_KINDS and (item.repair_from, item.canonical_id) not in planned:
            planned.append((item.repair_from, item.canonical_id))
    repaired = failures = 0
    for repair_from, canonical_id in planned:
        if _root(pointers, repair_from) == _root(pointers, canonical_id):
            continue   # an earlier repair in this pass already joined them
        try:
            store.merge_device(repair_from, canonical_id)
        except Exception as exc:
            failures += 1
            LOGGER.warning("Graph merge repair %s -> %s failed: %s", repair_from, canonical_id, exc)
            continue
        pointers[repair_from] = canonical_id
        pointers.setdefault(canonical_id, None)
        repaired += 1
    report = check_merges(redirects, store.get_merge_pointers())
    report.repaired = repaired
    report.repair_failures = failures
    return report


def describe(item: MergeItem) -> str:
    text = f"{item.orphan_id} -> {item.canonical_id} [{item.kind}]"
    if item.graph_root and item.graph_root != item.orphan_id:
        text += f" graph root {item.graph_root}"
    if item.repair_from:
        text += f"; repair: merge {item.repair_from} into {item.canonical_id}"
    if item.reason:
        text += f"; {item.reason}"
    return text
