# Device Identity Lifecycle

**Scope of this document**: this covers the `device_id` lifecycle end-to-end and the
subsystems that key state off it — the exact blast radius of the device-identity
fragmentation fix landed alongside this document. It is **not** a whole-codebase map.

**A note on accuracy** (matching `ENGINEERING_MANUAL.md`'s own standard): every claim
below was checked directly against the running source — file and line references
included — not carried forward from a design intent that may have drifted. This is a
**living document**: when a future change touches the device-identity lifecycle or one
of the subsystems in the table below, extend the relevant section here rather than
starting a new, separate document for an adjacent change.

The retroactive-merge mechanism this document centers on is one of several autonomous
self-healing loops the system runs continuously — for how it fits alongside sigma-shift,
trust-cache immunization, per-device learned thresholds, and the rest, plus a real
Telegram alert example for a live merge, see
[`AUTONOMOUS_LEARNING.md`](AUTONOMOUS_LEARNING.md) §6.

---

## 1. Overview: the device_id lifecycle

```
packet/log line arrives (Pi-hole DNS row, or a Zeek conn/dns/http/notice/dhcp event)
        │
        ▼
DeviceIdentityManager.resolve_device_id(client_ip, mac_addr, hostname)   [identity.py]
        │  picks a device_id — see §2 for the exact priority order
        ▼
_merge_orphan_if_fragmented(client_ip, dev_id, ...)                     [identity.py]
        │  if client_ip was ALREADY tracked under a DIFFERENT device_id, fold that
        │  orphan into dev_id now — see §3's merge_into_canonical() row
        ▼
StateManager.bind_mac(mac_addr, dev_id)                                 [state_guard.py]
        │  records the MAC -> device_id binding for future lookups
        ▼
StateManager.get_or_create(dev_id, client_ip, hostname, ...)            [state_guard.py]
        │  materializes (or reuses) the DeviceState — may itself trigger a DIFFERENT
        │  kind of merge, see §3's migrate_device_id() row
        ▼
_refresh_identity_signals() + apply_device_type()                       [identity.py]
        │  updates mac/ip/hostname/known_ips/dhcp_fingerprint/ja4_seen, and
        │  (re-)classifies device_type — see §4's apply_device_type() entry, a second
        │  bug found and fixed alongside this document
        ▼
... device evaluated every pipeline cycle (baselines, evidence, decisions, alerts) ...
        │
        ▼
StateManager.prune_stale_devices()                                      [state_guard.py]
        eventually evicts it after 7 days idle — see §3's third row
```

---

## 2. `resolve_device_id()`'s priority order

`src/core/identity.py`, `DeviceIdentityManager.resolve_device_id()`. Checked in this
exact order, first match wins:

1. **Gateway special-case** (new): if `config.gateway_ip` is set and `client_ip` equals
   it exactly, always return `stable_device_id(gateway_ip)`. Exists because a router
   genuinely has multiple distinct physical MACs (one per LAN/WLAN/WAN interface) — MAC
   correlation (step 2 below) can never fully unify it on its own. Inert (falls through
   to the normal branches) when `gateway_ip` is unset — the default for any deployment
   that hasn't configured it.
2. **MAC-first anchor**: if `mac_addr` is known and `StateManager.get_device_id_for_mac()`
   already has a binding for it, reuse that `device_id`. This is what unifies a
   dual-stack device's IPv4 and IPv6 traffic into one identity — a MAC address is
   captured at L2, independent of which L3 protocol family carried the packet.
3. **IP-anchor**: if the IP is "trackable" (private IPv4, or IPv6 link-local `fe80::/10`,
   or IPv6 ULA `fc00::/7` — see `_is_trackable_local_ip()`), `device_id =
   stable_device_id(client_ip)` (sha256 of the IP, truncated to 12 hex chars).
4. **Hostname-anchor**: if a real (non-generic) hostname is known, anchor on
   `f"host:{hostname}"`.
5. **MAC-anchor fallback**, then **6. IP-anchor fallback** for anything else.

**Why step 3 alone caused systemic fragmentation** (the bug this fix closes): every
dual/triple-stack device produces up to 3 addresses that all independently satisfy step
3's "trackable" check (IPv4 + IPv6 link-local + IPv6 ULA). MAC resolution (from Zeek's
`conn.log` `orig_l2_addr`, tracked per-IP in `ZeekFeatureExtractor._mac_bindings[ip]`)
doesn't necessarily happen on the very first packet from a fresh address. Step 2 only
prevents a *new* `device_id` from being minted once a MAC binding exists for THAT
specific address going forward — it does nothing to retroactively fix a `device_id`
that was already minted via step 3 for an address seen before its MAC became known. A
live scan of one production deployment's `state/ids_state.json` found **24 fragmented
groups across 60 of 88 tracked device_ids** before this fix.

---

## 3. The three device-identity "moves"

| | `migrate_device_id()` | `merge_into_canonical()` (new) | `prune_stale_devices()` |
|---|---|---|---|
| **File** | `state_guard.py:309` | `state_guard.py` (next to `migrate_device_id`) | `state_guard.py:502` |
| **Trigger** | `get_or_create()`'s DHCP-fingerprint/JA4-similarity re-identify match on a cold start (`_find_reidentify_candidate()`) — "this looks like a device I already know under a different, now-abandoned identity" | `identity.py`'s `_merge_orphan_if_fragmented()`, called right after `resolve_device_id()` in both `process_dns_identities()`/`process_zeek_identities()` — "this client_ip is already tracked under a DIFFERENT device_id than the one just resolved" | Hourly, age-based (`pipeline.py`'s `_step()`); a device idle > 7 days (default) |
| **Destination state** | Assumed brand-new — **overwrites** `self._states[new_id]` | Assumed already-populated and richer — **untouched**, orphan's data discarded | N/A (device is gone entirely) |
| **Source state** | Moved wholesale to the new key, continuing its history under a new name | **Discarded** (per explicit product decision — the orphan is typically far sparser than the identity it's folded into; not blended/averaged) | Deleted |
| **DeviceState** | Relocated | Deleted (`del self._states[orphan_id]`) | Deleted |
| **`_ip_to_device_id`** | New id gets the old id's `client_ip` entry | Every orphan `known_ip` (+ `client_ip`) redirected to canonical | Every `known_ip` (+ `client_ip`) cleared — **fixed in this pass**, previously only cleared `client_ip` (see §6) |
| **`_mac_to_device_id`** | Every key mapped to old_id repointed (`_repoint_mac_index()`, shared helper) | Same shared helper | N/A |
| **ML model** (`ml_engine.py`) | `migrate_device()` — renames `models/<old_id>.pkl` → `models/<new_id>.pkl`, moves the in-memory engine | `discard_device()` (new) — deletes `models/<orphan_id>.pkl`, drops the in-memory engine. **Not** `migrate_device()` — its overwrite semantics would destroy the canonical's own live model. | Not touched — **pre-existing gap, closed in this pass** (see §6) |
| **FP learned thresholds** (`fp_engine.py`, `device_fp_profiles.json`) | Not touched (no existing hook) | `discard_device_profile()` (new) — pops the orphan's key, re-saves the file | `discard_device_profile()` (new) — **pre-existing gap, closed in this pass** (see §6) |
| **Evidence** (`evidence.py`) | Not touched | Caller's job via the consume-once cleanup channel (§5) → `clear_device(orphan_id)` | `evidence_store.clear_device(e_dev_id)` (existing) |
| **Prometheus metrics** | Not touched | Caller's job via the consume-once cleanup channel (§5) → `remove_device_metric_labels()` | `remove_device_metric_labels()` (existing) |
| **Containment** (tarpit/router-isolation) | `_last_migrated_isolation_target` side channel → `_release_stale_isolation_if_merged()` | **Reuses the same side channel** — zero new isolation-release code needed | Not applicable (eviction isn't a containment-relevant identity change) |
| **`blocked_domains` attribution** | Not touched | Reattributed (pure relabel — `device_id`/`hostname` metadata fields only, no functional block/release behavior change) | Not touched (a pruned device's historical blocks aren't retargeted at anything) |

---

## 4. What breaks if I change X

**`StateManager.merge_into_canonical(orphan_id, canonical_id, ml_registry=None, fp_engine=None)`**
(`state_guard.py`)
- **Called by**: `identity.py`'s `_merge_orphan_if_fragmented()` (live traffic path) and
  `src/merge_fragmented_devices.py` (offline one-time cleanup script, always with
  `ml_registry=None, fp_engine=None` since it has no running pipeline instance of
  either).
- **Mutates**: `self._states` (deletes `orphan_id`), `self._ip_to_device_id`,
  `self._mac_to_device_id`, the canonical state's `known_ips`, `self._ips_state`'s
  `blocked_domains` entries.
- **Side effects via consume-once channels**: sets `_last_migrated_isolation_target`
  (reused — no `identity.py` changes needed to release stale containment) and
  `_last_orphan_merge_cleanup` (new).
- **If you change what it deletes vs. keeps**: anyone holding an orphan `device_id`
  string across a call boundary gets a `KeyError` from `lock_device()` afterward — the
  same failure mode `migrate_device_id()`'s `old_id` already has today, not a new risk
  class.
- **What it does NOT clean up itself** (caller's job): evidence/metrics (needs the
  consume-once channel + a caller that actually threads `evidence_store`/
  `metrics_exporter` through — see the trigger-point entry below).

**`DeviceIdentityManager._merge_orphan_if_fragmented()`** (`identity.py`)
- **Called by**: both `process_dns_identities()`/`process_zeek_identities()`, once per
  row, **before** `bind_mac()`/`get_or_create()` run for that row.
- **Depends on**: `StateManager.get_device_id_for_ip()` (new, read-only, self-healing
  the same way `get_device_id_for_mac()` already is).
- **If you reorder this relative to `bind_mac()`/`get_or_create()`**: must stay
  *before* both. `get_or_create()` assumes `dev_id` is already final for this row;
  running the merge after would let a freshly-cold-started `dev_id` and an about-to-be-
  discovered orphan collide in an order this function doesn't currently handle.
- **If you add a new per-device collaborator that needs cleanup on merge** (a fourth
  subsystem beyond ML/FP/evidence/metrics): follow the same pattern —
  `merge_into_canonical()` gets a new optional param that calls a `discard_*()`-style
  method on it directly (like `ml_registry`/`fp_engine`), *or* it goes through the
  `_last_orphan_merge_cleanup` consume-once channel and `_cleanup_merged_orphan()`
  (like `evidence_store`/`metrics_exporter`) — pick the former if the collaborator is
  always available synchronously wherever `merge_into_canonical()` is called (the
  cleanup script included), the latter if it's only available deep in `pipeline.py`.

**`DeviceIdentityManager.apply_device_type()`** (`identity.py`) — bug found and fixed
alongside this document, not part of the original fragmentation-fix scope but
discovered via the cleanup script's real output (a merged router's canonical identity
still showed `device_type="laptop"`).
- **The bug**: at the time, `infer_device_type()` (`utils.py:499`) never returned
  `"unknown"` — its own final fallback was `"laptop"`. The old code only re-ran
  inference when `state.device_type == "unknown"`, which after the very first call
  could never be true again — a device whose real hostname resolves on a *later* cycle
  than its first sighting (the common case for anything that cold-starts via an
  address with no hostname yet, e.g. a router's IPv6 side) was permanently stuck with
  whatever `infer_device_type("unknown")` produced at cold-start.
- **The fix**: re-infer whenever the current value is *not* an explicit operator
  override (`device_type_is_override` — a field that already existed for exactly this
  distinction, see `pipeline.py`'s infra-sensitivity filter). Idempotent/self-
  correcting: the same hostname always re-infers to the same classification, so this
  doesn't flap once a device's real hostname is known.
- **Called by**: both `process_dns_identities()`/`process_zeek_identities()`, once per
  row, after `_refresh_identity_signals()`.
- **Follow-up fix (2026-08-29)**: the re-infer-every-cycle fix above only helps once a
  real hostname eventually resolves — 12 of 13 devices typed `"laptop"` on production
  turned out to have `hostname="unknown"` permanently (no DHCP/mDNS/Pi-hole name ever
  seen for them), so re-running `infer_device_type("unknown")` every cycle just kept
  landing on the same wrong `"laptop"` guess. Two changes: (1)
  `infer_device_type()`'s final fallback is now `"unknown"`, not `"laptop"` — this
  activates `fp_engine.py`'s own pre-existing `dev_type_weights["unknown"] = 0.3`
  entry, which was defined but unreachable before this fix. (2) `apply_device_type()`
  now resolves `mac_vendor` via the new `utils.get_mac_vendor()` (offline MAC-OUI
  lookup, the `manuf` package) and passes it into `infer_device_type()`, wiring up a
  parameter that had existed but was never fed by any caller — a device with no
  resolvable hostname but a real, non-randomized vendor MAC (e.g. an Espressif-made
  IoT sensor) now classifies correctly even with `hostname="unknown"`. Devices with a
  randomized/locally-administered MAC (the common iOS/Android privacy-MAC behavior)
  get no vendor signal either way and correctly land on the honest `"unknown"`.
- **If you change the override-precedence branches above it**: `device_type_is_override`
  must stay the single source of truth `pipeline.py`'s infra-sensitivity evidence
  filter trusts — a device must never be able to self-report its way into "verified
  infrastructure" status just by choosing a router-like hostname (`test_phase5_
  structural.py`'s Test 3 guards this specific distinction).

**`MetricsExporter.remove_device_metric_labels(dev_id, hostname, device_type,
keep_safe_flag=False)`** (`core/metrics_sync.py:115`)
- **Called by**: `pipeline.py`'s hourly `prune_stale_devices()` cleanup and
  `identity.py`'s `_cleanup_merged_orphan()` (new) — both always with the *orphan's*
  own pre-merge `(dev_id, hostname, device_type)`, never the canonical's.
- **If you change its signature**: both call sites need updating; there is no shared
  wrapper, this is a direct 2-site fan-in.

---

## 5. Consume-once side channels

`StateManager` uses this pattern for "something just happened during a call whose
caller needs to know, but adding it to the return value would mean changing that
function's signature/return type for every existing caller." Each one: set inside a
`with self._global_lock:` block, popped exactly once by a matching `pop_*()` method
(which clears it either way — a caller that doesn't check every cycle can't act on a
stale result from an earlier, unrelated call).

| Channel | Set by | Popped by | Carries |
|---|---|---|---|
| `_last_reidentify_ambiguous` | `get_or_create()`'s reidentify path, when a candidate is strong enough to log about but not strong enough to auto-merge | `pop_last_reidentify_ambiguous()` (external caller, e.g. reactive-capture trigger) | `{new_device_id, candidate_id, confidence, ts}` |
| `_last_migrated_isolation_target` | `migrate_device_id()` **and** `merge_into_canonical()` (shared) | `pop_last_migrated_isolation_target()` → `identity.py`'s `_release_stale_isolation_if_merged()` | `{mac_addr, ip_addr}` of the pre-merge identity |
| `_last_orphan_merge_cleanup` (new) | `merge_into_canonical()` only | `pop_last_orphan_merge_cleanup()` → `identity.py`'s `_cleanup_merged_orphan()` | `{orphan_id, orphan_hostname, orphan_device_type, canonical_id}` |

---

## 6. Gaps closed in this pass

Two pre-existing gaps, unrelated to the fragmentation bug itself but discovered and
fixed alongside it (same function family already being touched):

- **`prune_stale_devices()`'s `_ip_to_device_id` leak**: previously only cleared the
  single `client_ip` entry on eviction, leaving every *other* address in that device's
  `known_ips` dangling in `_ip_to_device_id` (self-healing on next lookup via the
  existing stale-mapping guards in `get_device_id_for_mac()`/`get_device_id_for_ip()`,
  but a real, needless leak in the meantime). Now clears every known address.
- **`fp_engine.py` profile orphaning on ordinary eviction**: `device_fp_profiles.json`
  had no cleanup mechanism of any kind before this — not on merge, not on ordinary
  age-out eviction either. `discard_device_profile()` is now called from both
  `merge_into_canonical()` and `pipeline.py`'s `prune_stale_devices()` cleanup loop.

One gap noted but **not** closed by this pass (out of scope — a display-only remnant of
whichever original release pipeline classified it, not part of the identity lifecycle):
Pi-hole `blocked_domains` entries created before this fix landed, for a device_id that
had *already* been pruned (not merged) before this pass ran, still show that now-gone
device_id — `merge_into_canonical()` reattributes on merge, but there is no equivalent
hook for ordinary prune-based eviction, since a pruned device's historical blocks
genuinely have nothing to be "reattributed" to.
