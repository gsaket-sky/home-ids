"""
mitigation/router_adapter.py -- RouterAdapter abstraction (Phase 12, zero-site
network bootstrap D, autonomy-completion effort). Implements the shape
Documentation/SHIPPABILITY_AND_SCALE_PLAN.md's own SS1 already proposes:
isolate/unisolate/get_hosts/capture_supported, with FritzBoxAdapter as the
existing real implementation and NoRouterAdapter (Pi-hole + L2 tarpit only) as
the safe default for any network without a supported router.

Selected via config.yaml's `router_type` key ("fritzbox" -- the default, matching
every existing real deployment's hardware -- or "none"). This is purely an
adapter-SELECTION mechanism: it does not change what isolation does for a
Fritz!Box-equipped network at all. FritzBoxAdapter is a thin wrapper calling the
EXACT SAME TR-064/FritzHosts functions middleware/routers/fritzbox_api.py always
had -- moved behind this interface, not reimplemented.

mitigation/ips.py itself needs ZERO changes for this phase: confirmed via direct
read that it already talks to router isolation over a generic local HTTP webhook
(`router_webhook_url`, default http://127.0.0.1:8010/isolate), never importing
fritzbox_api.py or FritzConnection directly -- the abstraction boundary this
phase formalizes already existed at that HTTP layer. This phase moves the
FRITZ!BOX-SPECIFIC LOGIC BEHIND THAT WEBHOOK (fritzbox_api.py's own route
handlers) onto a swappable adapter, not ips.py's own call site.

ips.py's OWN Layer-2 IPv6 NDP-tarpit mitigation (mitigate()/
get_containment_status()/operator_isolate_router()) is untouched -- already
vendor-agnostic (raw sockets on this host's own NIC, no router cooperation
needed at all), exactly the "already vendor-agnostic, doesn't need fixing" case
SHIPPABILITY_AND_SCALE_PLAN.md's own SS1 calls out. Its `_router_isolated_devices`/
`_tarpit_active_targets` dict shapes are untouched by this module.
"""
import logging
from typing import Any, Dict, List, Tuple

LOGGER = logging.getLogger("mitigation.router_adapter")

VALID_ROUTER_TYPES = frozenset({"fritzbox", "none"})
DEFAULT_ROUTER_TYPE = "fritzbox"


class RouterAdapter:
    """Interface every router integration implements. A subclass that can't
    support a given capability returns the documented safe default (False/[]/a
    clear message) rather than raising -- the same fail-safe-degrade convention
    this codebase already uses everywhere else (e.g. GeoIPEngine,
    LocalConfirmedIntel). `isolate()`/`unisolate()` match the existing
    fire-and-forget webhook contract: they return True once the action was
    successfully QUEUED, not necessarily completed -- the real outcome is
    logged asynchronously, same as before this abstraction existed."""

    capture_supported: bool = False

    def isolate(self, mac: str, ip: str, reason: str) -> bool:
        raise NotImplementedError

    def unisolate(self, mac: str, ip: str, reason: str) -> bool:
        raise NotImplementedError

    def get_hosts(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

    def get_isolation_status(self, ip: str) -> bool:
        """True if `ip` is CURRENTLY isolated at the router level, per the
        router's own real state (not this process's own bookkeeping) -- used by
        ips.py's reconcile_router_isolation_state() to notice an operator
        toggling isolation directly in the router's own admin UI."""
        raise NotImplementedError

    def health_check(self) -> Tuple[bool, str]:
        """(ok, human-readable detail) -- used by main.py's startup diagnostic
        summary."""
        raise NotImplementedError


class FritzBoxAdapter(RouterAdapter):
    """Thin wrapper around the existing, unchanged Fritz!Box TR-064/FritzHosts
    logic in middleware/routers/fritzbox_api.py -- local imports (not top-level)
    to avoid a real import cycle: fritzbox_api.py imports mitigation.ips at
    module scope, and this module lives in mitigation/ alongside it."""

    capture_supported = True

    def __init__(self, config: Dict[str, Any]):
        self.config = config

    def isolate(self, mac: str, ip: str, reason: str) -> bool:
        from middleware.routers.fritzbox_api import execute_fritzbox_isolation
        execute_fritzbox_isolation(action="isolate", mac_address=mac, ip_address=ip, reason=reason)
        return True

    def unisolate(self, mac: str, ip: str, reason: str) -> bool:
        from middleware.routers.fritzbox_api import execute_fritzbox_isolation
        execute_fritzbox_isolation(action="unisolate", mac_address=mac, ip_address=ip, reason=reason)
        return True

    def get_hosts(self) -> List[Dict[str, Any]]:
        from middleware.routers.fritzbox_api import _get_fritz_hosts, _invalidate_fritz_hosts_cache
        fritz_ip = self.config.get("fritz_ip", "192.168.1.1")
        fritz_user = self.config.get("fritz_user", "admin")
        fritz_pass = self.config.get("fritz_password", "")
        if not fritz_pass:
            raise RuntimeError("FritzBox credentials not configured.")
        timeout_seconds = float(self.config.get("router_hosts_timeout_seconds", 5.0))
        if timeout_seconds <= 0:
            timeout_seconds = 5.0
        try:
            fh = _get_fritz_hosts(fritz_ip, fritz_user, fritz_pass, timeout_seconds)
            hosts_info = fh.get_hosts_info()
        except Exception:
            _invalidate_fritz_hosts_cache()
            raise
        parsed_hosts = []
        for host in hosts_info:
            if host.get("ip"):
                parsed_hosts.append({
                    "ip": host.get("ip"),
                    "mac": host.get("mac", "unknown").lower(),
                    "name": host.get("name", "unknown"),
                })
        return parsed_hosts

    def get_isolation_status(self, ip: str) -> bool:
        from fritzconnection import FritzConnection
        fritz_ip = self.config.get("fritz_ip", "192.168.1.1")
        fritz_user = self.config.get("fritz_user", "admin")
        fritz_pass = self.config.get("fritz_password", "")
        if not fritz_pass:
            raise RuntimeError("FritzBox credentials not configured.")
        timeout_seconds = float(self.config.get("router_status_query_timeout_seconds", 20.0))
        if timeout_seconds <= 0:
            timeout_seconds = 20.0
        fc = FritzConnection(address=fritz_ip, user=fritz_user, password=fritz_pass, timeout=timeout_seconds)
        result = fc.call_action("X_AVM-DE_HostFilter:1", "GetWANAccessByIP", NewIPv4Address=ip)
        return bool(result.get("NewDisallow", 0))

    def health_check(self) -> Tuple[bool, str]:
        from fritzconnection import FritzConnection
        fritz_ip = self.config.get("fritz_ip", "")
        fritz_pass = self.config.get("fritz_password", "")
        if not fritz_pass:
            return False, "fritz_password not configured"
        FritzConnection(address=fritz_ip, user=self.config.get("fritz_user", "admin"),
                          password=fritz_pass, timeout=3.0)
        return True, f"authenticated to {fritz_ip}"


class NoRouterAdapter(RouterAdapter):
    """The safe default for any network without a supported router -- Pi-hole
    DNS sinkholing and the Layer-2 ARP/NDP tarpit (both already vendor-agnostic,
    untouched by this module) remain fully active; only hardware-level WAN
    isolation and reactive AVM-format packet capture are unavailable. Never
    raises: every method degrades to its documented safe default, with a clear,
    loud log message explaining WHY nothing happened -- an operator debugging a
    "why didn't this device get isolated" report must see this reason
    immediately, not a silent no-op."""

    capture_supported = False

    def isolate(self, mac: str, ip: str, reason: str) -> bool:
        LOGGER.warning(
            "[ROUTER ADAPTER] No router configured (router_type=none) -- cannot "
            "isolate %s (%s) at the hardware level. Pi-hole DNS sinkholing and "
            "the Layer-2 tarpit are unaffected and still active for this device.",
            ip, mac,
        )
        return False

    def unisolate(self, mac: str, ip: str, reason: str) -> bool:
        LOGGER.info(
            "[ROUTER ADAPTER] No router configured (router_type=none) -- nothing "
            "to release at the hardware level for %s (%s).", ip, mac,
        )
        return False

    def get_hosts(self) -> List[Dict[str, Any]]:
        return []

    def get_isolation_status(self, ip: str) -> bool:
        return False

    def health_check(self) -> Tuple[bool, str]:
        return True, "No router adapter configured -- router-level isolation unavailable, Pi-hole + tarpit still active."


def get_router_adapter(config: Dict[str, Any]) -> RouterAdapter:
    """Factory, selected by config.yaml's `router_type` key. An unrecognized
    value fails safe to NoRouterAdapter (never silently to FritzBoxAdapter,
    which would attempt real TR-064 calls against hardware that may not even
    be a Fritz!Box) -- loud warning, not a silent wrong guess."""
    router_type = config.get("router_type", DEFAULT_ROUTER_TYPE)
    if router_type == "fritzbox":
        return FritzBoxAdapter(config)
    if router_type == "none":
        return NoRouterAdapter()
    LOGGER.warning(
        "[ROUTER ADAPTER] Unrecognized router_type %r (valid: %s) -- falling "
        "back to NoRouterAdapter (the safe default) rather than guessing.",
        router_type, sorted(VALID_ROUTER_TYPES),
    )
    return NoRouterAdapter()
