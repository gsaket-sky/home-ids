"""
identity_journal.py -- the exact record of every device-identity change (Documentation/internal/IDENTITY_MODEL.md, P1).

Keeps the time-bounded bindings "identifier X is device D since t" (identifier = MAC, address, or a legacy device id)
and an event for every change: a MAC first observed on a device, an address attributed to or released by a device, a
merge, a split, an address that changed hands, a new device on a reused address, an anchor recognised, a name change.
The identity resolver, the state manager and the reconcile worker report to it; the engine's main loop writes the
pending batch to the graph (identity_bindings / identity_events) with flush().

P1 is SHADOW: the journal records what the current identity logic decides and how strong the evidence was. Nothing
reads it to decide identity (that is P4), so a failure here never changes a device -- every entry point swallows its own
errors, and a batch the graph refused is kept (bounded) for the next flush.
"""
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

LOGGER = logging.getLogger("home_ids.identity_journal")

ID_KINDS = ("mac", "address", "legacy_id")


class IdentityJournal:
    MAX_PENDING_EVENTS = 50000

    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._lock = threading.Lock()
        # (id_kind, id_value) -> {"device_id", "valid_from", "last_seen", "binding_id" (None until written), "tmp"}
        self._open: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self._events: List[Dict[str, Any]] = []
        self._new: Dict[int, Dict[str, Any]] = {}            # tmp -> binding row to insert
        self._closes: Dict[Any, Dict[str, Any]] = {}         # binding_id or ("tmp", n) -> fields to set
        self._touched: set = set()                           # open keys whose last_seen moved since the last flush
        self._tmp = 0
        self.dropped_events = 0

    # --- loading -----------------------------------------------------------------------------------------------
    def load_open(self, rows: List[Dict[str, Any]]) -> None:
        """The bindings still open in the graph (after a restart)."""
        with self._lock:
            for r in rows:
                self._open[(r["id_kind"], r["id_value"])] = {
                    "device_id": r["device_id"], "valid_from": r["valid_from"], "last_seen": r["last_seen"],
                    "binding_id": r["binding_id"], "tmp": None}

    # --- recording ---------------------------------------------------------------------------------------------
    def event(self, kind: str, ts: Optional[float] = None, **fields: Any) -> None:
        try:
            with self._lock:
                self._event_locked(kind, ts, fields)
        except Exception as exc:                            # never let the record break identity
            LOGGER.debug("identity journal event %s failed: %s", kind, exc)

    def _event_locked(self, kind: str, ts: Optional[float], fields: Dict[str, Any]) -> None:
        if len(self._events) >= self.MAX_PENDING_EVENTS:
            self._events.pop(0)
            self.dropped_events += 1
        e = {"ts": float(ts if ts is not None else self._clock()), "kind": kind}
        detail = fields.pop("detail", None) or {}
        for k in ("device_id", "other_device_id", "id_kind", "id_value", "mac", "address", "reason"):
            if fields.get(k) not in (None, "", "unknown"):
                e[k] = fields.pop(k)
            else:
                fields.pop(k, None)
        detail.update({k: v for k, v in fields.items() if v is not None})
        if detail:
            e["detail"] = detail
        self._events.append(e)

    def bind(self, id_kind: str, id_value: str, device_id: str, ts: Optional[float] = None, evidence: str = "",
             reason: str = "") -> None:
        """`id_value` is `device_id`'s from `ts` on. Extends the open binding if it already is; otherwise closes the
        other device's binding at `ts` (that device's tenure ends -- recorded) and opens one for `device_id`."""
        if id_kind not in ID_KINDS or not id_value or id_value == "unknown" or not device_id:
            return
        try:
            with self._lock:
                self._bind_locked(id_kind, id_value, device_id, float(ts if ts is not None else self._clock()),
                                  evidence, reason)
        except Exception as exc:
            LOGGER.debug("identity journal bind failed: %s", exc)

    def _bind_locked(self, id_kind: str, id_value: str, device_id: str, ts: float, evidence: str, reason: str) -> None:
        key = (id_kind, id_value)
        cur = self._open.get(key)
        if cur is not None and cur["device_id"] == device_id:
            if ts > cur["last_seen"]:
                cur["last_seen"] = ts
                self._touched.add(key)
            return
        if cur is not None:
            self._close_locked(key, ts)
            self._event_locked("handed_over", ts, {"device_id": cur["device_id"], "other_device_id": device_id,
                                                   "id_kind": id_kind, "id_value": id_value,
                                                   "reason": reason or evidence})
        self._tmp += 1
        row = {"tmp": self._tmp, "device_id": device_id, "id_kind": id_kind, "id_value": id_value, "valid_from": ts,
               "last_seen": ts, "evidence": evidence, "reason": reason, "created_at": self._clock()}
        self._new[self._tmp] = row
        self._open[key] = {"device_id": device_id, "valid_from": ts, "last_seen": ts, "binding_id": None,
                           "tmp": self._tmp}
        kind = {"mac": "mac_observed", "address": "address_attributed", "legacy_id": "id_bound"}[id_kind]
        self._event_locked(kind, ts, {"device_id": device_id, "id_kind": id_kind, "id_value": id_value,
                                      "reason": reason or evidence})

    def unbind(self, id_kind: str, id_value: str, device_id: Optional[str] = None, ts: Optional[float] = None,
               reason: str = "", retract: bool = False) -> None:
        """Ends `id_value`'s binding (only if it is `device_id`'s, when given). `retract`: the binding was wrong, not
        merely over (a split) -- recorded as a retraction, the row is kept."""
        try:
            with self._lock:
                key = (id_kind, id_value)
                cur = self._open.get(key)
                if cur is None or (device_id and cur["device_id"] != device_id):
                    return
                t = float(ts if ts is not None else self._clock())
                self._close_locked(key, t, retract=retract, by=reason)
                self._event_locked("retracted" if retract else "released", t,
                                   {"device_id": cur["device_id"], "id_kind": id_kind, "id_value": id_value,
                                    "reason": reason})
        except Exception as exc:
            LOGGER.debug("identity journal unbind failed: %s", exc)

    def _close_locked(self, key: Tuple[str, str], ts: float, retract: bool = False, by: str = "") -> None:
        cur = self._open.pop(key)
        self._touched.discard(key)
        fields = {"valid_to": ts, "last_seen": cur["last_seen"]}
        if retract:
            fields.update({"retracted_at": ts, "retracted_by": by or "retracted"})
        if cur["binding_id"] is not None:
            self._closes.setdefault(cur["binding_id"], {}).update(fields)
        elif cur["tmp"] in self._new:
            self._new[cur["tmp"]].update(fields)              # opened and closed before a flush: one complete row
        else:
            # Its insert is being written by a flush on another thread right now: the close waits under the local key
            # until that flush maps it to the binding id.
            self._closes.setdefault(("tmp", cur["tmp"]), {}).update(fields)

    def observe(self, device_id: str, address: Optional[str], mac: Optional[str], mac_observed: bool,
                ts: Optional[float] = None) -> None:
        """The identity resolver attributed traffic from `address` (MAC `mac`) to `device_id`. The address binding's
        evidence says whether a MAC was observed for it -- without one, the attribution is the current logic's guess."""
        t = ts if ts is not None else self._clock()
        if mac_observed and mac and mac != "unknown":
            self.bind("mac", mac, device_id, t, evidence="observed")
        if address and address != "unknown":
            self.bind("address", address, device_id, t, evidence="mac_observed" if mac_observed else "no_mac")

    # --- reading -----------------------------------------------------------------------------------------------
    def current(self) -> Dict[Tuple[str, str], str]:
        """{(id_kind, id_value): device_id} of the open bindings."""
        with self._lock:
            return {k: v["device_id"] for k, v in self._open.items()}

    def pending(self) -> int:
        with self._lock:
            return len(self._events) + len(self._new) + len(self._closes) + len(self._touched)

    # --- writing -----------------------------------------------------------------------------------------------
    def flush(self, writer: Any) -> int:
        """Writes the pending batch with writer.write_identity_journal(events, opened, updates) (GraphStore). Call from
        the thread that owns the writer's connection. Returns how many records were written; on failure the batch is
        put back (the next flush retries) and 0 is returned."""
        if writer is None:
            return 0
        with self._lock:
            events, self._events = self._events, []
            new, self._new = self._new, {}
            closes = {k: v for k, v in self._closes.items() if not isinstance(k, tuple)}
            self._closes = {k: v for k, v in self._closes.items() if isinstance(k, tuple)}
            touched, self._touched = self._touched, set()
            updates = [{"binding_id": bid, **f} for bid, f in closes.items()]
            for key in touched:
                cur = self._open.get(key)
                if cur is not None and cur["binding_id"] is not None:
                    updates.append({"binding_id": cur["binding_id"], "last_seen": cur["last_seen"]})
                elif cur is not None and cur["tmp"] in new:
                    new[cur["tmp"]]["last_seen"] = cur["last_seen"]
        try:
            ids = writer.write_identity_journal(events, list(new.values()), updates)
        except Exception as exc:
            LOGGER.warning("Identity journal write failed (kept for the next flush): %s", exc)
            with self._lock:
                self._events = (events + self._events)[-self.MAX_PENDING_EVENTS:]
                for tmp, row in new.items():
                    self._new.setdefault(tmp, row)
                for bid, f in closes.items():
                    self._closes.setdefault(bid, {}).update(f)
                self._touched |= touched
            return 0
        with self._lock:
            for cur in self._open.values():
                if cur["binding_id"] is None and cur["tmp"] in ids:
                    cur["binding_id"] = ids[cur["tmp"]]
            for key in [k for k in self._closes if isinstance(k, tuple) and k[1] in ids]:
                self._closes.setdefault(ids[key[1]], {}).update(self._closes.pop(key))
        return len(events) + len(new) + len(updates)
