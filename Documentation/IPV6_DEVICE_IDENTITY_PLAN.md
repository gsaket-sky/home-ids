# IPv6 on Fritz!Box: Device-Identity Handling Plan

Status: **plan only, nothing implemented yet.** Written in response to: "i want to
enable ipv6 on fritzbox. make a plan how to handle device identity with ipv6
enabled in fritz. right now it is disabled."

## Bottom line up front

Most of what's needed is **already built, already live on `.94`, and confirmed
working on real traffic tonight** — this was a deliberate, prior engineering
effort (see `INSTALL.md` §3.3.1/3.3.2), not something being discovered now. There
is **one genuine, unaddressed gap**: router-side mitigation (WAN isolation) only
blocks a device's IPv4 address, so once a device is dual-stack, "isolating" it
over IPv4 leaves its IPv6 path open. Everything else below is either confirmed
working or a verification/observation step to run after the switch is flipped,
not new code.

**Router-agnostic revision**: the fix below deliberately does NOT chase a
Fritz!Box/AVM-specific TR-064 IPv6 action as the primary answer. Per
[[feedback_network_agnostic_design]], hand-coding against one vendor's firmware
quirks is exactly the kind of thing that breaks the moment someone runs this on
a different router. This also isn't a new problem for this codebase — it's the
same coupling already flagged in `SHIPPABILITY_AND_SCALE_PLAN.md` §1 as "the
single biggest blocker to shipping to another network," which already recommends
a `RouterAdapter` abstraction that hasn't been built yet. IPv6 mitigation is the
forcing function to finally build it, not a reason to add a second, parallel
Fritz!Box-specific code path on top of the existing one.

## What's already built and confirmed live (no action needed) — and already router-agnostic

Everything in this section depends only on Zeek/Suricata packet capture running
on the IDS host's own NIC — none of it talks to the router at all. This is the
part of the system that was already designed correctly: it will work identically
on a Fritz!Box, an OpenWrt box, a UniFi setup, or anything else, because it never
asks the router anything.

1. **`_is_trackable_local_ip()` (`src/core/identity.py:45`)** already treats IPv6
   ULA (`fc00::/7`) and link-local (`fe80::/10`) as trackable, and deliberately
   excludes global (public, non-private) IPv6 addresses from anchoring identity —
   written specifically for this day, per its own "PHASE 5 FIX (IPv6 visibility)"
   comment. This is correct: a rotating public IPv6 address must never become the
   identity anchor.

2. **MAC-first resolution is the real anchor, and it works across address
   families.** `resolve_device_id()` (`src/core/identity.py:239`) checks
   `state_manager.get_device_id_for_mac(mac_addr)` before ever falling back to an
   IP-based identity. As long as the MAC is known for a flow, it doesn't matter
   whether the flow's `client_ip` is the device's IPv4 address, its IPv6 SLAAC
   address, a rotating IPv6 privacy address, or its link-local address — they all
   resolve to the same `dev_id`.

3. **Zeek supplies the MAC on every connection.** `mac-logging.zeek` is loaded in
   the real, live `local.zeek` on `.94` (confirmed: `@load
   policy/protocols/conn/mac-logging.zeek` active, line 122) and real `conn.log`
   rows already contain populated `orig_l2_addr` (confirmed on live traffic
   tonight, e.g. `84:47:09:5c:a0:c3`). `core/extractors/zeek_features.py` reads
   this field and is what feeds `mac_addr` into `resolve_device_id()` above. This
   is the mechanism that will correlate a device's IPv4 identity to its IPv6
   identity(ies) the moment they start appearing in traffic.

4. **New-address-family bootstrap is handled, not just steady-state.** In
   `identity.py`'s device-resolution loop (`~line 326-347`): the moment a MAC
   becomes known for a `client_ip` that was previously tracked under a
   IP-anchored `dev_id` (exactly what happens the first time a device's IPv6
   traffic is seen and its MAC gets learned), `_merge_orphan_if_fragmented()` folds
   the old fragmented identity into the richer, MAC-anchored one, and
   `state_manager.bind_mac()` immediately publishes the MAC→dev_id binding so the
   *next* packet (same or different address family) finds it via the MAC-first
   check. This was tested as a general fix on 2026-09-05 (see
   `project_device_identity_fragmentation` memory) and isn't specific to IPv6, but
   IPv6 rollout is exactly the scenario it exists for.

5. **MAC-rotation re-identification (separate problem, also handled).**
   `mac-logging.zeek` only solves cross-address-family correlation for a device
   that *keeps the same MAC*. iOS Private Wi-Fi Address and Android per-network
   randomized MAC are a different problem, already solved by
   `core/device_matching.py`: DHCP Option 60/55 fingerprint + JA4 TLS fingerprint
   Jaccard comparison against recently-active devices, merging only above
   `AUTO_MERGE_CONFIDENCE = 0.75`. Confirmed genuinely wired into the live
   resolution path tonight (not just unit-tested): `_reidentify_kwargs()`
   (`identity.py:353`) is called on every `get_or_create()`, and even a
   below-threshold, genuinely-ambiguous candidate isn't silently dropped — it
   triggers a reactive Suricata capture (`pipeline.py:1039`, `trigger_reason=
   "ambiguous_reidentify"`) to gather fresher fingerprint evidence for a future
   resolution attempt. JA3 and JA4 are both installed and confirmed producing
   real, populated fingerprints on live `ssl.log` traffic on `.94` right now.

6. **`_reidentify_kwargs()` also correctly no-ops when there's no Zeek context**
   (`if not zeek_fx: return {"reidentify": False, ...}`) — defensive, not a gap.

## The one real gap: mitigation only blocks IPv4 — and only on one router vendor

`src/middleware/routers/fritzbox_api.py`'s `execute_fritzbox_isolation()` — the
function that actually performs router-side WAN isolation when the IDS decides to
contain a device — calls exactly one TR-064 action:

```python
fc.call_action(
    "X_AVM-DE_HostFilter:1",
    "DisallowWANAccessByIP",
    NewIPv4Address=ip_address,
    NewDisallow=disallow_value,
)
```

This has two separate limitations worth naming separately, because they call for
different fixes:

- **IPv4-only** (the parameter is literally `NewIPv4Address`). Once IPv6 is
  enabled and a device is dual-stack, an "isolated" device's IPv4 WAN access is
  blocked but its IPv6 WAN access is not — a real bypass/leak channel for
  exactly the devices this system is trying to contain.
- **AVM-only**. This whole call only exists at all if the router is a Fritz!Box.
  This isn't new — `SHIPPABILITY_AND_SCALE_PLAN.md` §1 already identified this
  exact function as the "single biggest blocker" to running this system on any
  other router, months before IPv6 came up.

Also worth noting: the read-only `get_dhcp_hosts()` (`fritzbox_api.py:124`, used
by `identity.py`'s `_poll_fritzbox_hosts()` for MAC↔hostname↔IP enrichment) is
IPv4-only by the underlying TR-064 `Hosts:1` service — it will never return IPv6
addresses, on any router that exposes it this way. This is **not a gap for IPv6
specifically**: enrichment only needs MAC+hostname from this call, and IPv6
address visibility comes entirely from Zeek's packet capture, which needs no
router cooperation at all (see previous section). It's the same underlying
Fritz!Box-naming/coupling issue, though — see the adapter fix below.

### The router-agnostic fix: don't add more Fritz!Box code, finally add the adapter boundary

Rather than hand-coding a Fritz!Box IPv6 TR-064 action (which would fix the gap
for this one household while making the vendor-lock-in problem worse, and would
still be guessing at undocumented AVM firmware behavior — exactly what
[[feedback_network_agnostic_design]] warns against), the right fix is the
`RouterAdapter` interface `SHIPPABILITY_AND_SCALE_PLAN.md` §1 already scoped
(`isolate`/`unisolate`/`get_hosts`/`capture_if_supported`), built with IPv6 as a
first-class part of the interface from the start rather than bolted on later:

- **`FritzBoxAdapter`** — wraps the existing `fritzbox_api.py` calls exactly as
  they are today (IPv4 WAN-block via TR-064) as one *capability* among several,
  not the only mechanism. If/when a Fritz!Box firmware turns out to expose an
  IPv6 or MAC-based `X_AVM-DE_HostFilter:1` action, it plugs in here as an
  additional capability of this same adapter — worth a live TR-064 check once
  IPv6 is actually on, but as an enhancement to one adapter, not the plan's
  foundation.
- **Universal, router-agnostic baseline** — `mitigation/ips.py` already has a
  Scapy-based ARP/NDP tarpit (`_ndp_tarpit_loop`) that operates directly on the
  IDS host's own NIC via raw sockets. It needs zero router cooperation, so it
  works identically regardless of vendor, and it already covers the IPv6
  neighbor-discovery side that the Fritz!Box TR-064 call can't touch. This
  becomes the mitigation layer every isolation action gets, on any network,
  including a `NoRouterAdapter` setup (no supported router at all — the
  §1-recommended safe default) and including this household as soon as IPv6 is
  live: an isolate action always arms the local NDP tarpit for the device's IPv6
  traffic, with the Fritz!Box IPv4 WAN-block layered on top where a Fritz!Box is
  present, rather than router-vendor-specific behavior being the only thing
  standing between "isolated" and "actually isolated."
- **Net result**: containment stops being "does this feature exist on my
  specific router's firmware" and becomes "the local-segment block always
  works, router-level WAN block is a bonus when the adapter supports it" —
  correct dual-stack behavior on this household's Fritz!Box AND correct
  behavior (with no router-level component at all) on someone else's OpenWrt or
  UniFi network.

This is real implementation work — introducing the adapter interface, moving
the two existing capabilities (Fritz!Box TR-064, hosts polling) behind it, and
making NDP-tarpit arming unconditional on `isolate()` rather than router-vendor
conditional. Appropriately scoped as its own piece of work, not squeezed into
this planning pass, and worth sequencing before or alongside the pre-flight
checklist below rather than after IPv6 is already live, since the safe default
(local tarpit always arms) doesn't need the router to be inspected first.

## Phased checklist for when IPv6 actually gets enabled

**Before flipping the switch:**
1. Confirm this plan's mitigation gap (above) is either accepted as a known,
   temporary limitation, or fixed first — this is the one item with real
   security consequences, not just an observability nice-to-have. The
   router-agnostic fix (unconditional NDP-tarpit arming on isolate) doesn't
   require inspecting the Fritz!Box at all, so it can land before IPv6 is even
   turned on.
2. No code changes are required for identity resolution/correlation itself — it
   is already IPv6-ready, live-verified tonight, and already router-agnostic
   (depends only on Zeek, not on the Fritz!Box).

**Immediately after enabling IPv6 on the Fritz!Box:**
3. Watch `.94`'s logs for `_merge_orphan_if_fragmented` activity and the
   Autonomy/device-count views in the console — expect a burst of merges as
   already-known IPv4-anchored devices get their first IPv6 flows correlated in.
   This is expected, healthy behavior, not a bug.
4. Spot-check a handful of real devices' entries in the graph/device view to
   confirm they show both IPv4 and IPv6 addresses folded under one `dev_id`,
   not split.
5. Watch for `ambiguous_reidentify`-triggered reactive captures spiking
   temporarily — also expected while fresh fingerprints accumulate for any
   device whose MAC randomizes per network (phones, mainly).
6. Verify Zeek is actually seeing IPv6 traffic at all: check `conn.log` for rows
   with IPv6 `id.orig_h`/`id.resp_h` and confirm `orig_l2_addr` is still
   populated on them (this depends on Zeek's capture interface/BPF filter not
   silently excluding IPv6 — worth an explicit check, not an assumption, since
   nothing in this codebase's config has been verified against real IPv6 traffic
   yet).
7. Re-test isolation end-to-end against a real dual-stack test device to confirm
   the local NDP-tarpit layer actually blocks the IPv6 path, and (separately)
   whether Fritz!Box's IPv4 WAN-block is still working as it does today — the
   two are now independent layers, so verify each rather than assuming one
   implies the other.

**Ongoing:**
8. No new config keys are required beyond what already exists
   (`identity_reidentify_*` keys already operator-tunable). If reactive-capture
   volume from ambiguous re-identification climbs meaningfully post-IPv6 (more
   address-family churn to correlate), `identity_reidentify_min_confidence` and
   `identity_reidentify_window_seconds` are the existing knobs to revisit — no
   new tuning mechanism needed.

## Non-goals

- This plan does not cover actually flipping the IPv6 toggle in the Fritz!Box
  admin UI — that's a router-admin action outside this codebase, for the user to
  do directly.
- This plan does not hand-encode any Fritz!Box-specific IPv6 provisioning
  behavior (SLAAC prefix delegation details, NDP proxying, firewall defaults) as
  assumed fact, since none of it has been observed on live traffic yet — per
  [[feedback_network_agnostic_design]], those get verified against real behavior
  once IPv6 is actually live (checklist items 3-7 above), not guessed at now.
- This plan does not attempt the full `RouterAdapter` refactor scoped in
  `SHIPPABILITY_AND_SCALE_PLAN.md` §1 (a second router-specific adapter for
  OpenWrt/UniFi/etc. is explicitly called out there as "its own scoped project,
  not a prerequisite"). It only pulls forward the minimum slice of that
  abstraction — separating "local NDP-tarpit enforcement" from "Fritz!Box
  TR-064 WAN block" as independent layers — that's actually load-bearing for
  correct IPv6 mitigation. The rest of that plan stays deferred.
