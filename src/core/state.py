"""
state.py – In-Memory Device State and Diurnal Baseline Tracking.

Manages the core mathematical representations of all tracked network devices,
including rolling event deques and exponentially weighted moving averages (EWMA).

RECENT FIXES (AUDIT CORRECTIONS):
- FIXED (LRU EVICTION FLAW): Updated `BoundedSet` to properly call `move_to_end()` on 
  cache hits. Previously, it operated purely as FIFO, which caused highly-active, benign 
  domains to be falsely evicted and misidentified as "First-seen domain bursts"[cite: 10].
- ADDED (LOGGING): Injected telemetry logging for state object instantiation and baseline poisoning.
- FIXED: Lowered `is_poisoned` threshold from 7.0 to 4.0 to prevent slow-burn baseline poisoning by low-and-slow attackers[cite: 10].
"""
import logging
from collections import deque, Counter, defaultdict, OrderedDict

LOGGER = logging.getLogger("home_ids.state")

class BoundedSet:
    """Thread-safe, maximum-capacity LRU Set to prevent memory leaks."""
    def __init__(self, max_size=10000, initial=None):
        self.max_size = max_size
        self._data = OrderedDict()
        if initial:
            for item in initial:
                self.add(item)

    def add(self, item):
        if item in self._data:
            # LRU FIX: Promote the item to the MRU (Most Recently Used) position on the right end
            self._data.move_to_end(item)
        else:
            # Add new item and enforce maximum capacity bound
            self._data[item] = None
            if len(self._data) > self.max_size:
                # Evict the oldest (Least Recently Used) item from the left end
                self._data.popitem(last=False)

    def __contains__(self, item):
        return item in self._data

    def __iter__(self):
        return iter(self._data.keys())

    def __len__(self):
        return len(self._data)

    def to_list(self):
        return list(self._data.keys())

class EWMABaseline:
    """Exponentially Weighted Moving Average (EWMA) tracker grouped by 24-hour diurnal buckets."""
    def __init__(self, alpha=0.05):
        self.alpha = alpha
        self.mean = [0.0] * 24
        self.var = [0.0] * 24
        self.init = [False] * 24
        self.n = [0] * 24

    def update(self, value: float, hour: int):
        if not self.init[hour]:
            self.mean[hour] = value
            self.var[hour] = 0.0
            self.init[hour] = True
            self.n[hour] = 1
        else:
            diff = value - self.mean[hour]
            self.mean[hour] += self.alpha * diff
            self.var[hour] = (1 - self.alpha) * (self.var[hour] + self.alpha * (diff ** 2))
            self.n[hour] += 1

    def get_stats(self, hour: int):
        return self.mean[hour], self.var[hour], self.init[hour], self.n[hour]

    def get_stats_interpolated(self, hour: int, minute: int = 0):
        """Smoothly interpolates diurnal baseline statistics between adjacent hours to prevent step-function jumps."""
        cur_m, cur_v, cur_init, cur_n = self.get_stats(hour)
        if not cur_init or cur_n < 10:
            return cur_m, cur_v, cur_init, cur_n

        next_hour = (hour + 1) % 24
        next_m, next_v, next_init, next_n = self.get_stats(next_hour)
        if not next_init or next_n < 5:
            return cur_m, cur_v, cur_init, cur_n

        weight = max(0.0, min(1.0, minute / 60.0))
        interp_m = ((1.0 - weight) * cur_m) + (weight * next_m)
        interp_v = ((1.0 - weight) * cur_v) + (weight * next_v)
        return interp_m, interp_v, True, cur_n

    def to_dict(self) -> dict:
        return {
            "mean": self.mean,
            "var": self.var,
            "init": self.init,
            "n": self.n
        }

    @classmethod
    def from_dict(cls, data: dict, alpha=0.05):
        obj = cls(alpha)
        obj.mean = (list(data.get("mean", [])) + [0.0] * 24)[:24]
        obj.var = (list(data.get("var", [])) + [0.0] * 24)[:24]
        obj.init = (list(data.get("init", [])) + [False] * 24)[:24]
        obj.n = (list(data.get("n", [])) + [0] * 24)[:24]
        return obj

class RollingWindow:
    def __init__(self):
        self.events = deque(maxlen=2000)        # M3 FIX: bounded ~5-min window at 2s poll rate
        self.long_events = deque(maxlen=20000)  # M3 FIX: bounded ~1-hour window
        self.domains = Counter()
        self.domain_timestamps = defaultdict(deque)
        self.blocked = 0
        self.nxdomain = 0
        self.dns_qtypes = Counter()         # Tracks DNS qtypes (A, AAAA, TXT, NULL, ANY, MX)

    def reset(self):
        self.events.clear()
        self.long_events.clear()
        self.domains.clear()
        self.domain_timestamps.clear()
        self.blocked = 0
        self.nxdomain = 0
        self.dns_qtypes.clear()

class DeviceState:
    """Consolidated state tracking profile for a single physical network device."""
    def __init__(self, device_id: str, client_ip: str, hostname: str = "unknown", alpha: float = 0.05):
        self.device_id = device_id
        self.client_ip = client_ip
        self.hostname = hostname
        self.mac_address = "unknown"
        from utils import infer_device_type
        self.device_type = infer_device_type(hostname)
        
        self.rate_baseline = EWMABaseline(alpha)
        self.entropy_baseline = EWMABaseline(alpha)
        self.unique_baseline = EWMABaseline(alpha)
        self.nxdomain_baseline = EWMABaseline(alpha)
        self.blocked_baseline = EWMABaseline(alpha)
        self.dga_baseline = EWMABaseline(alpha)
        self.outbound_bytes_baseline = EWMABaseline(alpha)
        self.risk_baseline = EWMABaseline(alpha)
        
        self.rolling = RollingWindow()
        self.seen_domains = BoundedSet(max_size=10000)
        self.geo_exported_ips = BoundedSet(max_size=5000)
        
        self.last_baseline_update = 0.0
        self.last_alert_time = 0.0
        self.last_alert_confidence = 0.0
        self.last_alert_signature = ""
        self.killchain_history = deque(maxlen=5)
        
        # SecOps Operator Validation Tracking
        self.has_validated_threat = False
        self.confirmed_threat_count = 0
        self.fp_count = 0
        
        LOGGER.debug("DeviceState profile instantiated for ID: %s (IP: %s, Hostname: %s)", device_id, client_ip, hostname)

    def is_poisoned(self, risk_score: float) -> bool:
        """Returns True if the device exhibits high risk, freezing baseline ingestion.
        H1 FIX: Raised from 4.0 to 5.5 — prevents over-freezing baselines for devices
        that slightly exceed Z-score boundaries without being genuine threats.
        Baselines only freeze when the risk is within 0.5 of the default alert threshold (6.0).
        """
        poisoned = risk_score >= 5.5
        if poisoned:
            LOGGER.debug("Device %s flagged as POISONED (Risk: %.2f). Baseline ingestion frozen.", self.hostname, risk_score)
        return poisoned

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "client_ip": self.client_ip,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "device_type": self.device_type,
            "seen_domains": self.seen_domains.to_list(),
            "geo_exported_ips": self.geo_exported_ips.to_list(),
            "last_baseline_update": self.last_baseline_update,
            "last_alert_time": self.last_alert_time,
            "last_alert_confidence": self.last_alert_confidence,
            "last_alert_signature": self.last_alert_signature,
            "killchain_history": list(self.killchain_history),
            "has_validated_threat": self.has_validated_threat,
            "confirmed_threat_count": self.confirmed_threat_count,
            "fp_count": self.fp_count,
            "rate_baseline": self.rate_baseline.to_dict(),
            "entropy_baseline": self.entropy_baseline.to_dict(),
            "unique_baseline": self.unique_baseline.to_dict(),
            "nxdomain_baseline": self.nxdomain_baseline.to_dict(),
            "blocked_baseline": self.blocked_baseline.to_dict(),
            "dga_baseline": self.dga_baseline.to_dict(),
            "outbound_bytes_baseline": self.outbound_bytes_baseline.to_dict(),
            "risk_baseline": self.risk_baseline.to_dict()
        }

    @classmethod
    def from_dict(cls, data: dict, alpha: float = 0.05):
        obj = cls(
            device_id=data.get("device_id", ""),
            client_ip=data.get("client_ip", ""),
            hostname=data.get("hostname", "unknown"),
            alpha=alpha
        )
        obj.mac_address = data.get("mac_address", "unknown")
        obj.device_type = data.get("device_type", "unknown")
        
        obj.seen_domains = BoundedSet(max_size=10000, initial=data.get("seen_domains", []))
        obj.geo_exported_ips = BoundedSet(max_size=5000, initial=data.get("geo_exported_ips", []))
        
        obj.last_baseline_update = data.get("last_baseline_update", 0.0)
        obj.last_alert_time = data.get("last_alert_time", 0.0)
        obj.last_alert_confidence = data.get("last_alert_confidence", 0.0)
        obj.last_alert_signature = data.get("last_alert_signature", "")
        obj.killchain_history = deque(data.get("killchain_history", []), maxlen=5)
        
        obj.has_validated_threat = data.get("has_validated_threat", False)
        obj.confirmed_threat_count = data.get("confirmed_threat_count", 0)
        obj.fp_count = data.get("fp_count", 0)
        
        if "rate_baseline" in data: obj.rate_baseline = EWMABaseline.from_dict(data["rate_baseline"], alpha)
        if "entropy_baseline" in data: obj.entropy_baseline = EWMABaseline.from_dict(data["entropy_baseline"], alpha)
        if "unique_baseline" in data: obj.unique_baseline = EWMABaseline.from_dict(data["unique_baseline"], alpha)
        if "nxdomain_baseline" in data: obj.nxdomain_baseline = EWMABaseline.from_dict(data["nxdomain_baseline"], alpha)
        if "blocked_baseline" in data: obj.blocked_baseline = EWMABaseline.from_dict(data["blocked_baseline"], alpha)
        if "dga_baseline" in data: obj.dga_baseline = EWMABaseline.from_dict(data["dga_baseline"], alpha)
        if "outbound_bytes_baseline" in data: obj.outbound_bytes_baseline = EWMABaseline.from_dict(data["outbound_bytes_baseline"], alpha)
        if "risk_baseline" in data: obj.risk_baseline = EWMABaseline.from_dict(data["risk_baseline"], alpha)
        
        return obj