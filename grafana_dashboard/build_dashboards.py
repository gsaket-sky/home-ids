"""
build_dashboards.py -- generates the five Home-IDS Grafana dashboards (Grafana v2 schema)
from the declarations below. The JSON files in this folder are OUTPUT: edit this script,
run it, commit both.

    python grafana_dashboard/build_dashboards.py

Design rules (Documentation/ARGUS_OBSERVABILITY_PLAN.md):
  - organised around the Argus architecture: sensors -> evidence -> decision -> false-positive
    filter -> alert/containment, with autotuning and learning alongside;
  - numbers come from Prometheus. Loki (alerts.json) is used only for the raw alert-log
    tables, which a time-series store cannot hold -- listed for later retirement;
  - every panel says in plain words what it shows, what "good" looks like, and what to do;
  - network-agnostic: no addresses, hostnames or household specifics in any query or text.

Dashboard UIDs never change (bookmarks and cross-links keep working).
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROM = "${PROMETHEUS_DS}"
LOKI = "${LOKI_DS}"
VIZ_VERSION = "13.1.1"
TAG = "home-ids-v2"

# Live device name for series keyed only by device id (the evidence graph stores no
# names). Multiplies by exactly 1, so values are unchanged.
def with_host(expr: str, device_filter: bool = True) -> str:
    sel = '{hostname=~"$device"}' if device_filter else ""
    return f'({expr}) * on(device) group_left(hostname) (max by (device, hostname) (home_ids_decision_state{sel}) * 0 + 1)'


def per_device_or_zero(expr: str) -> str:
    """Every device the engine knows, 0 where `expr` has no series (counts that simply
    haven't happened yet), restricted to the device picker."""
    return (f'(max by (device) ({expr}) or max by (device) (home_ids_decision_state) * 0) '
            f'and on(device) max by (device) (home_ids_decision_state{{hostname=~"$device"}})')


def by(expr: str, *labels: str) -> str:
    """Aggregate to exactly these labels, so joined table frames carry nothing else
    (Grafana would otherwise emit suffixed duplicate columns for every shared label)."""
    return f"max by ({', '.join(labels)}) ({expr})"


def keyed(expr: str, first: str, second: str) -> str:
    """Single join key 'first · second' for rows identified by two labels."""
    return f'max by (key) (label_join({expr}, "key", " · ", "{first}", "{second}"))'


def per_device(expr: str) -> str:
    return f'max by (device) ({expr}) and on(device) max by (device) (home_ids_decision_state{{hostname=~"$device"}})'


# ---------------------------------------------------------------------------- panel builders
class Board:
    def __init__(self, name, title, description, device_var=False):
        self.name, self.title, self.description, self.device_var = name, title, description, device_var
        self.elements, self.items, self.y, self.next_id = {}, [], 0, 1

    def _add(self, spec, width, height, x):
        pid = self.next_id
        self.next_id += 1
        spec["id"] = pid
        name = f"panel-{pid}"
        self.elements[name] = {"kind": "Panel", "spec": spec}
        self.items.append({"kind": "GridLayoutItem", "spec": {"x": x, "y": self.y, "width": width,
                                                              "height": height,
                                                              "element": {"kind": "ElementReference", "name": name}}})

    def row(self, panels, height=7, widths=None):
        widths = widths or [24 // len(panels)] * len(panels)
        x = 0
        for p, w in zip(panels, widths):
            self._add(p, w, height, x)
            x += w
        self.y += height

    def section(self, title, text):
        self.row([text_panel(title, text)], height=3)


def q(expr, ref="A", legend=None, instant=False, fmt=None, ds="prometheus"):
    spec = {"expr": expr}
    if ds == "prometheus":
        spec["instant"] = bool(instant)
        spec["range"] = not instant
        if fmt:
            spec["format"] = fmt
        if legend:
            spec["legendFormat"] = legend
        source = PROM
    else:
        spec["queryType"] = "range"
        if fmt:
            spec["format"] = fmt
        source = LOKI
    return {"kind": "PanelQuery", "spec": {"query": {"kind": "DataQuery", "group": ds, "version": "v0",
                                                     "datasource": {"name": source}, "spec": spec},
                                           "refId": ref, "hidden": False}}


def panel(title, description, group, queries, options=None, defaults=None, overrides=None, transformations=None):
    return {"title": title, "description": description, "links": [],
            "data": {"kind": "QueryGroup", "spec": {"queries": queries, "transformations": transformations or [],
                                                    "queryOptions": {}}},
            "vizConfig": {"kind": "VizConfig", "group": group, "version": VIZ_VERSION,
                          "spec": {"options": options or {},
                                   "fieldConfig": {"defaults": defaults or {}, "overrides": overrides or []}}}}


def thresholds(*steps):
    return {"mode": "absolute", "steps": [{"value": v, "color": c} for v, c in steps]}


def value_map(mapping):
    return [{"type": "value", "options": {str(k): {"text": t, "color": c, "index": i}
                                          for i, (k, (t, c)) in enumerate(mapping.items())}}]


def range_map(ranges):
    return [{"type": "range", "options": {"from": lo, "to": hi, "result": {"text": t, "color": c, "index": i}}}
            for i, (lo, hi, t, c) in enumerate(ranges)]


def text_panel(title, content):
    return panel(title, "", "text", [], options={"mode": "markdown", "content": content})


def stat(title, description, expr, unit="none", steps=None, mappings=None, no_value="0", decimals=None,
         color_mode="value", instant=True, graph=False):
    d = {"unit": unit, "noValue": no_value, "thresholds": thresholds(*(steps or [(None, "green")]))}
    if mappings:
        d["mappings"] = mappings
    if decimals is not None:
        d["decimals"] = decimals
    return panel(title, description, "stat", [q(expr, instant=instant)],
                 options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                          "colorMode": color_mode, "graphMode": "area" if graph else "none",
                          "textMode": "value", "justifyMode": "auto", "orientation": "auto", "wideLayout": True},
                 defaults=d)


def timeseries(title, description, targets, unit="none", steps=None, stack=False, min_zero=True, decimals=None):
    custom = {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 12, "showPoints": "never",
              "spanNulls": True, "stacking": {"mode": "normal" if stack else "none", "group": "A"}}
    d = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if min_zero:
        d["min"] = 0
    if steps:
        d["thresholds"] = thresholds(*steps)
        custom["thresholdsStyle"] = {"mode": "dashed"}
    if decimals is not None:
        d["decimals"] = decimals
    qs = [q(e, ref=chr(65 + i), legend=lg) for i, (e, lg) in enumerate(targets)]
    return panel(title, description, "timeseries", qs,
                 options={"legend": {"displayMode": "table", "placement": "right", "showLegend": True,
                                     "calcs": ["lastNotNull", "max"]},
                          "tooltip": {"mode": "multi", "sort": "desc"}},
                 defaults=d)


def bars(title, description, expr, legend, unit="none", steps=None, no_value="0"):
    return panel(title, description, "bargauge", [q(expr, legend=legend, instant=True)],
                 options={"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                          "orientation": "horizontal", "displayMode": "basic", "showUnfilled": True,
                          "valueMode": "color", "namePlacement": "left", "sizing": "auto"},
                 defaults={"unit": unit, "noValue": no_value, "min": 0,
                           "thresholds": thresholds(*(steps or [(None, "blue")]))})


def column(name, description, unit="none", mappings=None, steps=None, cell="color-text", width=None, decimals=None,
           no_value=None):
    props = [{"id": "displayName", "value": name}, {"id": "description", "value": description},
             {"id": "unit", "value": unit}, {"id": "custom.cellOptions", "value": {"type": cell}}]
    if mappings:
        props.append({"id": "mappings", "value": mappings})
    if steps:
        props.append({"id": "color", "value": {"mode": "thresholds"}})
        props.append({"id": "thresholds", "value": thresholds(*steps)})
    if width:
        props.append({"id": "custom.width", "value": width})
    if decimals is not None:
        props.append({"id": "decimals", "value": decimals})
    if no_value is not None:
        props.append({"id": "noValue", "value": no_value})
    return props


def table(title, description, columns, key_field, key_label=None, extra_label_fields=(), hide_fields=(),
          sort_by=None, links=None, key_description=""):
    """columns: list of (ref, expr, column-properties). Queries are instant, table-formatted,
    joined on `key_field`; Value #<ref> gets that column's properties."""
    qs = [q(expr, ref=ref, instant=True, fmt="table") for ref, expr, _ in columns]
    exclude = {"Time": True, "__name__": True, "instance": True, "job": True}
    for i in range(1, len(columns) + 2):
        exclude[f"Time {i}"] = True
    for f in hide_fields:
        exclude[f] = True
    order = {key_field: 0}
    for i, f in enumerate(extra_label_fields):
        order[f] = i + 1
    for i, (ref, _, _) in enumerate(columns):
        order[f"Value #{ref}"] = len(extra_label_fields) + 1 + i
    overrides = [{"matcher": {"id": "byName", "options": f"Value #{ref}"}, "properties": props}
                 for ref, _, props in columns]
    key_props = [{"id": "custom.align", "value": "left"}]
    if key_label:
        key_props.append({"id": "displayName", "value": key_label})
    if key_description:
        key_props.append({"id": "description", "value": key_description})
    if links:
        key_props.append({"id": "links", "value": links})
    overrides.insert(0, {"matcher": {"id": "byName", "options": key_field}, "properties": key_props})
    xf = []
    if len(columns) > 1:
        xf.append({"kind": "Transformation", "group": "joinByField",
                   "spec": {"options": {"byField": key_field, "mode": "outer"}}})
    xf.append({"kind": "Transformation", "group": "organize",
               "spec": {"options": {"excludeByName": exclude, "indexByName": order, "renameByName": {}}}})
    return panel(title, description, "table", qs,
                 options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False},
                          "sortBy": [{"displayName": sort_by, "desc": True}] if sort_by else []},
                 defaults={"custom": {"align": "auto", "filterable": True, "cellOptions": {"type": "auto"}}},
                 overrides=overrides, transformations=xf)


def log_table(title, description, expr):
    return panel(title, description, "table", [q(expr, ds="loki", fmt="table")],
                 options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
                 defaults={"custom": {"align": "auto", "filterable": True, "cellOptions": {"type": "auto"}}})


# ---------------------------------------------------------------------------- shared vocab
VERDICT_MAP = value_map({0: ("🟢 Benign", "green"), 1: ("🟡 Anomalous", "yellow"), 2: ("🟠 Suspicious", "orange"),
                         3: ("🔴 High", "red"), 4: ("⚫ Critical", "dark-red")})
VERDICT_STEPS = [(None, "green"), (1, "yellow"), (2, "orange"), (3, "red"), (4, "dark-red")]
# Codes: core/metrics_sync.py DECISION_PATH_CODES (append-only).
PATH_MAP = value_map({
    -1: ("❔ Unrecognised path", "text"),
    0: ("Nothing suspicious", "green"),
    1: ("ML anomaly only (logged)", "yellow"),
    2: ("Unconfirmed bad reputation (watching)", "yellow"),
    3: ("Suspicious pattern, one source (watching)", "orange"),
    4: ("Known-bad destination, uncorroborated (watching)", "orange"),
    5: ("Attack pattern, ≥2 independent sources", "red"),
    6: ("Blocked-country contact (uncorroborated)", "red"),
    7: ("Suricata signature (uncorroborated)", "red"),
    8: ("Known-bad destination + corroboration", "dark-red"),
    9: ("Verified threat indicator", "dark-red"),
    10: ("Hard-stop rule (certain threat)", "dark-red"),
})
# intelligence/reputation/classifier.py
TIER_MAP = value_map({0: ("Own network", "green"), 1: ("Trusted", "green"), 2: ("Known infrastructure", "green"),
                      3: ("Unknown", "text"), 4: ("Weak bad signal", "orange"), 5: ("Confirmed bad", "red")})
# core/metrics_sync.py phase_map -- the detector itself says "suspected"
KILLCHAIN_MAP = value_map({0: ("Normal", "green"), 1: ("Suspected recon", "yellow"), 2: ("Suspected C2", "red"),
                           3: ("Suspected lateral movement", "orange"), 4: ("Suspected exfiltration", "purple")})
HEALTH_MAP = value_map({-1: ("Retired", "text"), 0: ("🟢 Healthy", "green"), 1: ("🟡 Degraded", "yellow"),
                        2: ("🔴 Unhealthy", "red"), 3: ("🟣 Safe mode", "purple"), 4: ("⛔ Recovery failed", "dark-red")})
PRESSURE_MAP = value_map({0: ("🟢 Normal", "green"), 1: ("🟡 Resource pressure", "yellow"),
                          2: ("🟠 Conserving", "orange"), 3: ("🔴 Critical", "red")})
TASK_STATE_MAP = value_map({0: ("Idle", "text"), 1: ("▶ Running", "green"), 2: ("⏸ Paused", "yellow"),
                            3: ("⏳ Waiting", "orange")})
UPDOWN = value_map({0: ("🔴 Down", "red"), 1: ("🟢 Up", "green")})
DEVICE_LINK = [{"title": "🔍 Open this device", "url": "/d/home_ids_v3_device?var-device=${__value.raw}",
                "targetBlank": False}]


# ============================================================================ 1. Overview
def overview():
    b = Board("home_ids_v3_main", "1. 🏠 Overview", "Is Home-IDS working, what reached you, and how every device looks right now.",
              device_var=True)
    b.row([text_panel("", "**Start here.** Top row: is everything running. Second row: what the system did in the last 24 hours. "
                      "Then the **Master Threat Ledger**, with one row per device. Hover any tile or column header for an "
                      "explanation. The other dashboards go deeper: **2** Threat Landscape, **3** Device Deep Dive, "
                      "**4** Autonomy & Learning, **5** System Health & Operations.")], height=3)
    b.section("🩺 Is it working?", "Green means running. A red tile means that part is down; the other layers keep working on their own.")
    b.row([
        stat("Detection engine", "Is Prometheus reaching the Home-IDS engine? If this is down, every other number here is stale.",
             'max(up{job="home_ids"})', mappings=UPDOWN, steps=[(None, "red"), (1, "green")], no_value="🔴 Down"),
        stat("Job scheduler", "Is the scheduler daemon (which runs the LLM review, retro-hunt, pruning, autotune...) reachable?",
             'max(up{job="home_ids_scheduler"})', mappings=UPDOWN, steps=[(None, "red"), (1, "green")], no_value="🔴 Down"),
        stat("Host load", "The health manager's view of the machine: Normal, Resource pressure, Conserving (non-essential work paused) or Critical.",
             "home_ids_health_pressure_level", mappings=PRESSURE_MAP, steps=[(None, "green"), (1, "yellow"), (2, "orange"), (3, "red")],
             no_value="?"),
        stat("Parts needing attention", "How many internal components the health manager does not rate Healthy (retired ones excluded). 0 is normal; see dashboard 5 for which.",
             "count(home_ids_health_component_state > 0) or vector(0)", steps=[(None, "green"), (1, "orange")]),
        stat("Network sensor (Zeek)", "Is Zeek's traffic log being read? Without it, scans, TLS fingerprints and lateral movement go unseen.",
             "home_ids_zeek_status", mappings=UPDOWN, steps=[(None, "red"), (1, "green")], no_value="?"),
        stat("DNS blocking (Pi-hole)", "Can Home-IDS reach Pi-hole to block domains?", "home_ids_ips_pihole_status",
             mappings=UPDOWN, steps=[(None, "red"), (1, "green")], no_value="?"),
        stat("Router isolation", "Can Home-IDS cut a device off at the router?", "home_ids_ips_router_status",
             mappings=UPDOWN, steps=[(None, "red"), (1, "green")], no_value="?"),
        stat("LAN tarpit", "Is the local ARP/NDP tarpit (traps a device on the LAN) armed?", "home_ids_ips_tarpit_status",
             mappings=UPDOWN, steps=[(None, "red"), (1, "green")], no_value="?"),
    ], height=4, widths=[3, 3, 3, 3, 3, 3, 3, 3])
    b.section("🛡️ The last 24 hours", "Counted from the evidence graph, so these survive restarts.")
    b.row([
        stat("Alerts sent to you", "Alerts that passed every gate (HIGH or CRITICAL, not hidden as a false positive) in the last 24h. Low is normal.",
             'sum(home_ids_argus_alert_events_24h{status="FIRED"}) or vector(0)', steps=[(None, "green"), (1, "orange"), (10, "red")]),
        stat("Hidden as false positives", "Alerts the false-positive filter suppressed in the last 24h (typically trusted destinations). Nothing is deleted; they stay in the log.",
             'sum(home_ids_argus_alert_events_24h{status="SUPPRESSED_AUTONOMOUS"}) or vector(0)', steps=[(None, "blue")]),
        stat("Logged below the alert bar", "Candidates recorded for context but not strong enough to alert on.",
             'sum(home_ids_argus_alert_events_24h{status="LOGGED_ONLY"}) or vector(0)', steps=[(None, "text")]),
        stat("High / critical decisions", "Decisions the engine rated High or Critical in the last 24h (before incident grouping and false-positive filtering).",
             'sum(home_ids_argus_decisions_24h{state=~"HIGH|CRITICAL"}) or vector(0)', steps=[(None, "green"), (1, "orange")]),
        stat("Active incidents", "Distinct incidents (a device + what it is doing, grouped) with activity in the last 24h.",
             "home_ids_argus_incidents_active_24h", steps=[(None, "green"), (1, "orange")]),
        stat("Devices isolated now", "Devices cut off right now by the router and/or the LAN tarpit. 0 is normal.",
             "count(max by (device) (home_ids_ips_tarpit_active == 1 or home_ids_ips_router_isolated_active == 1)) or vector(0)",
             steps=[(None, "green"), (1, "red")]),
        stat("Domains blocked now", "Domains currently blocked in Pi-hole on Home-IDS's instruction.",
             "count(home_ids_ips_active_blocks == 1) or vector(0)", steps=[(None, "blue")]),
    ], height=4)
    b.section("🚨 Master Threat Ledger", "One row per device, one column per signal. **Read left to right:** the verdict, "
              "why it was reached, how well it is backed up, then the individual signals. Hover a column header for what it "
              "means. Click a device name to open its deep dive. Filter with the **device** box at the top.")
    ledger = table(
        "🚨 Master Threat Ledger (all devices, all signals)",
        "Every device the engine is tracking, with its current Argus verdict and every signal behind it. Counts cover "
        "the last 24 hours; everything else is the current value. An empty cell means that signal has no data for "
        "this device yet.",
        [
            ("A", 'max by (device, hostname, device_type) (home_ids_decision_state{hostname=~"$device"})',
             column("Verdict", "The engine's current decision for this device. High and Critical can trigger automatic containment.",
                    mappings=VERDICT_MAP, steps=VERDICT_STEPS, cell="color-background", width=120)),
            ("B", per_device("home_ids_decision_path_code"),
             column("Why", "Which rule or hypothesis path produced the verdict.", mappings=PATH_MAP, width=280,
                    steps=[(None, "text")])),
            ("C", per_device("home_ids_threat_confidence"),
             column("Confidence", "How sure the engine is of its verdict (not how dangerous the device is).",
                    unit="percentunit", decimals=0, steps=[(None, "text")])),
            ("D", per_device("home_ids_decision_independent_sources"),
             column("Independent sources", "How many independent kinds of evidence back the verdict. HIGH needs at least 2.",
                    steps=[(None, "text"), (2, "orange")])),
            ("E", per_device("home_ids_decision_evidence_families"),
             column("Evidence families", "How many different evidence families were seen (DNS, network behaviour, reputation...).",
                    steps=[(None, "text")])),
            ("F", per_device("home_ids_reputation_tier"),
             column("Destination reputation", "Reputation of the destination behind the current evidence: own network, trusted, known infrastructure, unknown, weak bad signal, confirmed bad.",
                    mappings=TIER_MAP)),
            ("G", per_device_or_zero("home_ids_device_alerts_fired_24h"),
             column("Alerts sent (24h)", "Alerts about this device that reached you in the last 24h.",
                    steps=[(None, "green"), (1, "red")])),
            ("H", per_device_or_zero("home_ids_device_alerts_suppressed_24h"),
             column("Hidden as FP (24h)", "Alerts about this device the false-positive filter hid in the last 24h.",
                    steps=[(None, "text"), (1, "blue")])),
            ("I", per_device("home_ids_killchain_phase"),
             column("Kill-chain stage", "Which attack stage this device's traffic most resembles (suspected, not confirmed).",
                    mappings=KILLCHAIN_MAP)),
            ("J", per_device("home_ids_anomaly_confidence"),
             column("ML outlier score", "How unusual the device looks to its own anomaly model (0 = normal for it).",
                    mappings=range_map([(0, 0.0199, "Normal", "green"), (0.02, 0.0499, "Warning", "yellow"),
                                        (0.05, 1, "Outlier", "red")]), decimals=3)),
            ("K", per_device_or_zero("home_ids_device_baseline_regime_shifts"),
             column("Behaviour changes learned", "How many times the baseline detected a lasting change in this device's behaviour and re-learned it.",
                    steps=[(None, "text")])),
            ("L", per_device("home_ids_device_learned_trust"),
             column("Learned trust", "How much the false-positive filter has learned to trust this device's usual behaviour (0-100%).",
                    unit="percentunit", decimals=0, steps=[(None, "text")], no_value="not learned yet")),
            ("M", per_device("home_ids_device_sigma_shift"),
             column("Sensitivity", "Automatic sensitivity shift. Below 0: stricter after confirmed threats (floor -1.5). Above 0: more lenient after corrected false positives.",
                    mappings=range_map([(-100, -0.01, "Stricter", "orange"), (-0.0099, 0.0099, "Default", "text"),
                                        (0.01, 100, "More lenient", "blue")]), no_value="Default")),
            ("N", per_device_or_zero('count by (device) (label_replace(home_ids_autotune_value{scope="device"}, "device", "$1", "target", "(.*)"))'),
             column("Own tuned thresholds", "How many thresholds autotune has calibrated specifically for this device (others use its device-type or global value).",
                    steps=[(None, "text")])),
            ("O", per_device("home_ids_ti_risk"),
             column("Threat-intel feeds", "Match against curated threat-intel feeds.",
                    mappings=[{"type": "value", "options": {"0": {"text": "Clean", "color": "green", "index": 0}}}]
                    + range_map([(0.01, 1.99, "Weak signal", "yellow"), (2, 100, "Known bad", "red")]))),
            ("P", per_device("home_ids_abuseipdb_risk"),
             column("AbuseIPDB", "AbuseIPDB community reports for this device's destinations.",
                    mappings=[{"type": "value", "options": {"0": {"text": "Clean", "color": "green", "index": 0}}}]
                    + range_map([(0.01, 3.99, "Weak signal", "yellow"), (4, 100, "Known bad", "red")]))),
            ("Q", per_device("home_ids_virustotal_risk"),
             column("VirusTotal", "VirusTotal detections for this device's destinations.",
                    mappings=[{"type": "value", "options": {"0": {"text": "Clean", "color": "green", "index": 0}}}]
                    + range_map([(0.01, 1.99, "Weak signal", "yellow"), (2, 100, "Known bad", "red")]))),
            ("R", per_device("home_ids_zeek_ja4_malicious"),
             column("Malicious TLS", "Connections whose TLS fingerprint (JA4) matches known malware.",
                    steps=[(None, "text"), (1, "red")])),
            ("S", per_device("home_ids_zeek_honeypot_hits"),
             column("Honeypot hits", "Contacts to a configured decoy address. Any hit is a strong sign of scanning.",
                    steps=[(None, "text"), (1, "red")])),
            ("T", per_device("home_ids_zeek_s0_rej_count"),
             column("Failed connections", "Unanswered or rejected connection attempts, typical of port scanning.",
                    steps=[(None, "text"), (20, "orange"), (50, "red")])),
            ("U", per_device("home_ids_zeek_doh_bypass"),
             column("Encrypted-DNS bypass", "Connections to DNS-over-HTTPS resolvers that skip your Pi-hole.",
                    steps=[(None, "text"), (1, "yellow"), (5, "red")])),
            ("V", per_device("home_ids_outbound_bytes_window"),
             column("Data sent out", "Bytes this device sent out in the current window.", unit="bytes",
                    steps=[(None, "text"), (104857600, "orange")])),
            ("W", per_device_or_zero("home_ids_ips_tarpit_active == 1 or home_ids_ips_router_isolated_active == 1"),
             column("Isolated", "Is this device cut off right now (router and/or LAN tarpit)?",
                    mappings=value_map({0: ("No", "green"), 1: ("🛑 Isolated", "red")}), cell="color-background")),
            ("X", per_device("home_ids_probation_status"),
             column("Baseline", "Still learning what is normal for this device (new or recently reset), or monitored normally.",
                    mappings=value_map({0: ("Monitored", "green"), 1: ("⏳ Learning", "yellow")}))),
            ("Y", per_device("home_ids_baseline_poisoned"),
             column("Learning paused", "Learning is paused while the device looks risky, so an attacker can't teach the baseline that bad is normal.",
                    mappings=value_map({0: ("Learning", "green"), 1: ("❄️ Paused", "orange")}))),
            ("Z", per_device("home_ids_safe_device"),
             column("Allow-listed", "Exempted from containment by your configuration.",
                    mappings=value_map({0: ("No", "text"), 1: ("🛡️ Yes", "blue")}))),
        ],
        key_field="hostname", key_label="Device", extra_label_fields=("device_type",),
        hide_fields=("device", "device 1"), sort_by="Verdict", links=DEVICE_LINK,
        key_description="The device's name as the engine knows it. Click to open its deep dive.",
    )
    # the identity query carries hostname/device_type; every other query joins on device id
    ledger["data"]["spec"]["transformations"][0]["spec"]["options"]["byField"] = "device"
    ledger["vizConfig"]["spec"]["fieldConfig"]["overrides"].append(
        {"matcher": {"id": "byName", "options": "device_type"},
         "properties": [{"id": "displayName", "value": "Type"},
                        {"id": "description", "value": "Device type as inferred or configured."}]})
    b.row([ledger], height=16)
    b.section("📈 Trends", "")
    b.row([
        timeseries("Alert outcomes (rolling 24 h)", "For each moment, how many alerts in the preceding 24 hours were sent to you, hidden as false positives, or only logged.",
                   [('sum by (status) (home_ids_argus_alert_events_24h)', "{{status}}")]),
        timeseries("Decision paths (per minute)", "How the engine reached its decisions over time. A mix shifting towards corroborated paths means sharper detection.",
                   [("sum by (path) (rate(home_ids_decision_path_total[5m])) * 60", "{{path}}")], stack=True),
    ], height=8)
    b.section("📜 Alert log", "Raw alert records from the log stream (Loki). Every number above comes from Prometheus; this table exists because a metrics store can't hold log lines.")
    b.row([log_table("Alerts that reached you",
                     "HIGH or CRITICAL alerts that the false-positive filter did not hide, newest first. Expand a row for the full evidence.",
                     '{job="home_ids_alerts"} | json | type="ids_alert" | suppressed!="true" | '
                     'hee_decision_path=~"hard_stop|hypothesis_high|tier5_confirmed|tier5_corroborated|geofence_uncorroborated|suricata_uncorroborated"'
                     ' | json device="device.hostname", signature="signature", risk="risk", why="hee_decision_path"')], height=9)
    return b


# ============================================================================ 2. Threat Landscape
def landscape():
    b = Board("home_ids_v3_landscape", "2. 🌐 Threat Landscape", "Where your network talks to, and which outside threats it meets.")
    b.row([text_panel("", "Where traffic goes (countries, networks) and which outside threats show up: threat-intel hits, "
                      "beaconing, malicious TLS, DNS tricks. Country data needs the GeoIP database to be installed.")], height=2)
    b.section("🌍 Geography", "")
    geo = panel("Countries your network talks to", "Each marker is a country contacted recently, coloured by risk (0-10).",
                "geomap", [q("home_ids_geo_country_marker", instant=True, fmt="table")],
                options={"view": {"id": "zero", "zoom": 1}, "controls": {"showZoom": True},
                         "layers": [{"type": "markers", "name": "Countries", "location": {"mode": "coords", "latitude": "latitude", "longitude": "longitude"},
                                     "config": {"showLegend": True, "style": {"color": {"field": "Value"}, "size": {"fixed": 6}}}}]},
                defaults={"unit": "none", "thresholds": thresholds((None, "green"), (5, "orange"), (9, "red"))})
    b.row([geo, table("Riskiest countries", "The 10 highest-risk countries by the engine's GeoIP risk score.",
                      [("A", "topk(10, max by (country, org, asn) (home_ids_geo_risk))",
                        column("Risk (0-10)", "GeoIP-based risk for traffic to this country/network.",
                               steps=[(None, "green"), (5, "orange"), (9, "red")]))],
                      key_field="country", key_label="Country", extra_label_fields=("org", "asn"), sort_by="Risk (0-10)")],
          height=10, widths=[14, 10])
    b.row([table("All countries (traffic context)", "Every country your network talks to, risky or not: traffic, devices, DNS activity.",
                 [("A", "sum by (country) (home_ids_geo_traffic_total)", column("Connections", "Connections seen to this country.")),
                  ("B", "sum by (country) (home_ids_geo_device_count)", column("Devices", "How many of your devices talked to it.")),
                  ("C", "sum by (country) (home_ids_geo_queries_per_minute)", column("DNS queries / min", "DNS lookups per minute resolving there.", decimals=1)),
                  ("D", "sum by (country) (home_ids_geo_unique_domains)", column("Unique domains", "Distinct domains resolving there.")),
                  ("E", "avg by (country) (home_ids_geo_entropy)", column("Name randomness", "Average randomness of the domain names (above ~4.5 looks machine-generated).", decimals=2,
                                                                          steps=[(None, "text"), (4.5, "red")]))],
                 key_field="country", key_label="Country", sort_by="Connections")], height=9)
    b.section("🦠 Outside threats", "")
    b.row([
        timeseries("Threat-intel matches (per hour, by feed)", "Connections to destinations listed on a threat-intel feed, per rolling hour.",
                   [("sum by (source) (increase(home_ids_ti_ioc_hits_total[1h]))", "{{source}}")]),
        timeseries("Beaconing (per device)", "Regular, clock-like outbound connections, a classic sign of malware checking in.",
                   [("home_ids_beaconing_c2_count", "{{hostname}}")]),
    ], height=8)
    b.row([
        timeseries("Malicious TLS fingerprints (JA4)", "Connections whose TLS handshake matches known malware tooling. Any non-zero value is serious.",
                   [("home_ids_zeek_ja4_malicious", "{{hostname}}")], steps=[(None, "green"), (1, "red")]),
        timeseries("Malicious TLS fingerprints (JA3, older format)", "Same idea as JA4, for families only catalogued under the older format.",
                   [("home_ids_zeek_ja3_malicious", "{{hostname}}")], steps=[(None, "green"), (1, "red")]),
        timeseries("Domain-name randomness (per device)", "Average randomness of looked-up names. Machine-generated domains (DGA) sit above ~4.5.",
                   [("home_ids_entropy_avg", "{{hostname}}")], steps=[(None, "green"), (4.5, "red")]),
    ], height=8)
    b.section("📡 Inside your network", "")
    b.row([
        timeseries("Lateral movement events (per hour)", "A device probing several of your other devices. Almost always worth investigating.",
                   [("sum(increase(home_ids_zeek_lateral_events_total[1h])) or vector(0)", "events / hour")]),
        timeseries("Honeypot probes (per hour)", "Contacts to a decoy address you configured. Only meaningful if you set one up.",
                   [("sum(increase(home_ids_honeypot_probes_total[1h])) or vector(0)", "probes / hour")]),
        timeseries("Encrypted-DNS bypass (per device)", "Connections to DNS-over-HTTPS resolvers that go around your Pi-hole.",
                   [("home_ids_zeek_doh_bypass", "{{hostname}}")]),
    ], height=8)
    return b


# ============================================================================ 3. Device Deep Dive
def device():
    b = Board("home_ids_v3_device", "3. 🔍 Device Deep Dive", "Everything about one device: its verdict history, signals, baseline and its own tuning.",
              device_var=True)
    b.row([text_panel("", "Pick a device in the **device** box at the top. Every panel follows it.")], height=2)
    b.section("🎯 Verdict", "")
    b.row([
        timeseries("Verdict over time", "0 Benign · 1 Anomalous · 2 Suspicious · 3 High · 4 Critical.",
                   [('home_ids_decision_state{hostname=~"$device"}', "{{hostname}}")], steps=[(None, "green"), (2, "orange"), (3, "red")]),
        timeseries("Confidence and backing", "Verdict confidence (0-1), with the independent sources and evidence families behind it.",
                   [('home_ids_threat_confidence{hostname=~"$device"}', "confidence · {{hostname}}"),
                    ('home_ids_decision_independent_sources{hostname=~"$device"}', "independent sources · {{hostname}}"),
                    ('home_ids_decision_evidence_families{hostname=~"$device"}', "evidence families · {{hostname}}")]),
    ], height=8)
    b.row([
        stat("Alerts sent (24h)", "Alerts about this device that reached you.", with_host("home_ids_device_alerts_fired_24h") + " or vector(0)",
             steps=[(None, "green"), (1, "red")]),
        stat("Hidden as false positive (24h)", "Alerts about this device the filter hid.", with_host("home_ids_device_alerts_suppressed_24h") + " or vector(0)",
             steps=[(None, "blue")]),
        stat("Learned trust", "How much the false-positive filter trusts this device's usual behaviour.", with_host("home_ids_device_learned_trust"),
             unit="percentunit", no_value="not learned yet", steps=[(None, "text")]),
        stat("Sensitivity shift", "Below 0: stricter after confirmed threats. Above 0: more lenient after corrected false positives.",
             with_host("home_ids_device_sigma_shift"), no_value="0 (default)", decimals=2, steps=[(None, "orange"), (0, "text"), (0.01, "blue")]),
        stat("Behaviour changes learned", "Lasting behaviour changes its baseline detected and re-learned.",
             with_host("home_ids_device_baseline_regime_shifts") + " or vector(0)", steps=[(None, "text")]),
        stat("Kill-chain stage", "Which attack stage its traffic most resembles (suspected).", 'max(home_ids_killchain_phase{hostname=~"$device"})',
             mappings=KILLCHAIN_MAP, steps=[(None, "text")], no_value="?"),
    ], height=4)
    b.section("⚙️ How autotune has tuned this device", "Autotune picks a value per device when it has enough evidence, otherwise per device type, otherwise the global value.")
    dev_scope = 'label_replace(home_ids_autotune_{kind}{{scope="device"}}, "device", "$1", "target", "(.*)")'
    b.row([table("This device's own tuned thresholds", "Thresholds autotune calibrated specifically for the selected device(s), and proposals still in their trial (canary) period.",
                 [("A", keyed(with_host(dev_scope.format(kind="value")), "hostname", "parameter"),
                   column("Active value", "The value in force for this device.", decimals=3)),
                  ("B", keyed(with_host(dev_scope.format(kind="canary_value")), "hostname", "parameter"),
                   column("On trial", "A proposed new value still being tested before promotion.", decimals=3, no_value="—"))],
                 key_field="key", key_label="Device · Threshold"),
           table("Its device type's values", "What the selected device(s) fall back to where they have no value of their own.",
                 [("A", keyed('home_ids_autotune_value{scope="category"} and on(target) label_replace(max by (device_type) '
                              '(home_ids_decision_state{hostname=~"$device"}), "target", "$1", "device_type", "(.*)")', "target", "parameter"),
                   column("Device-type value", "Calibrated for all devices of this type.", decimals=3))],
                 key_field="key", key_label="Device type · Threshold"),
           table("Global values", "Used by every device without a more specific value.",
                 [("A", by('home_ids_autotune_value{scope="global"}', "parameter"), column("Global value", "Network-wide calibrated value.", decimals=3)),
                  ("B", by("home_ids_autotune_config_value", "parameter"), column("Configured default", "The hand-set config.yaml value it started from.", decimals=3))],
                 key_field="parameter", key_label="Threshold")],
          height=8, widths=[10, 7, 7])
    b.section("📊 Behaviour signals", "The raw inputs behind the anomaly score. Several moving together matters more than one spike.")
    b.row([
        timeseries("DNS queries per minute", "Raw lookup rate. Read together with randomness and z-score.",
                   [('home_ids_query_rate{hostname=~"$device"}', "{{hostname}}")]),
        timeseries("Query rate vs its learned limit", "The learned normal rate and the live alert threshold derived from it.",
                   [('home_ids_query_rate_baseline_mean{hostname=~"$device"}', "normal · {{hostname}}"),
                    ('home_ids_query_rate_threshold_limit{hostname=~"$device"}', "alert threshold · {{hostname}}")]),
        timeseries("Unusualness vs its own history (z-score)", "Above ~3 is a statistical outlier for this device.",
                   [('home_ids_zscore_query_rate{hostname=~"$device"}', "query rate · {{hostname}}"),
                    ('home_ids_zscore_nxdomain_ratio{hostname=~"$device"}', "failed lookups · {{hostname}}"),
                    ('home_ids_zscore_unique_domains{hostname=~"$device"}', "unique domains · {{hostname}}")],
                   steps=[(None, "green"), (3, "red")], min_zero=False),
    ], height=8)
    b.row([
        timeseries("Blocked and failed lookups", "Share of lookups Pi-hole blocked, and share that returned 'no such domain'. Rising failures without blocks can mean a DGA probing for its C2.",
                   [('home_ids_blocked_ratio{hostname=~"$device"}', "blocked · {{hostname}}"),
                    ('home_ids_nxdomain_ratio{hostname=~"$device"}', "no such domain · {{hostname}}")], unit="percentunit"),
        timeseries("Domain-name randomness", "Above ~4.5 suggests machine-generated names.",
                   [('home_ids_entropy_avg{hostname=~"$device"}', "{{hostname}}")], steps=[(None, "green"), (4.5, "red")]),
        timeseries("Beaconing: volume and regularity", "Regular timing (low jitter) plus steady volume is the C2 check-in pattern.",
                   [('home_ids_beaconing_volume_score{hostname=~"$device"}', "volume · {{hostname}}"),
                    ('home_ids_jitter_cv_score{hostname=~"$device"}', "timing regularity · {{hostname}}")]),
    ], height=8)
    b.row([
        timeseries("ML outlier score", "How unusual the device looks to its own anomaly model.",
                   [('home_ids_anomaly_confidence{hostname=~"$device"}', "{{hostname}}")], decimals=3),
        timeseries("Unusual behaviour sequence (Markov)", "How unlikely its current behaviour sequence is, given its history.",
                   [('home_ids_markov_anomaly_score{hostname=~"$device"}', "{{hostname}}")]),
        timeseries("External reputation", "Threat-intel, AbuseIPDB and VirusTotal scores for its destinations.",
                   [('home_ids_ti_risk{hostname=~"$device"}', "threat intel · {{hostname}}"),
                    ('home_ids_abuseipdb_risk{hostname=~"$device"}', "AbuseIPDB · {{hostname}}"),
                    ('home_ids_virustotal_risk{hostname=~"$device"}', "VirusTotal · {{hostname}}")]),
    ], height=8)
    b.section("📜 Alert log", "Raw alert records for this device from the log stream (Loki).")
    b.row([log_table("This device's alerts", "Every candidate alert for the selected device, published or not.",
                     '{job="home_ids_alerts"} | json | type="ids_alert" | device_hostname=~"$device"'
                     ' | json signature="signature", risk="risk", why="hee_decision_path", fp_verdict="fp_verdict.verdict", suppressed="suppressed"')],
          height=9)
    return b


# ============================================================================ 4. Autonomy & Learning
def autonomy():
    b = Board("home_ids_v3_autonomous", "4. 🤖 Autonomy & Learning",
              "What Home-IDS decides and learns on its own: the false-positive filter, autotuning (global, per type, per device), learned trust, baselines, LLM review, retro-hunting.",
              device_var=True)
    b.row([text_panel("", "Can you trust what it does while you're not watching? Top to bottom: the **false-positive filter**, "
                      "**autotuning** (global, per device type, per device), **what it has learned**, and its **background jobs**.")], height=2)
    b.section("🧪 False-positive filter (CL-AFPE)", "Every alert candidate passes through this filter before it can reach you.")
    b.row([
        timeseries("Filter funnel (per hour)", "Candidates checked, how many were hard-stopped (strong evidence, never suppressible), and how many were hidden as false positives.",
                   [("sum(increase(home_ids_fp_evaluations_total[1h]))", "checked"),
                    ("sum(increase(home_ids_fp_confirmed_threats_total[1h]))", "hard-stopped"),
                    ("sum(increase(home_ids_fp_suppressed_total[1h]))", "hidden as false positive")]),
        timeseries("Which stage decided (per hour)", "TRUST_CACHE = already-trusted destination. STAGE_1_HARD_STOP = strong evidence. STAGE_1B_LOCAL_ORIGIN = your own device. STAGE_3_COMBINED = the ML + similarity score.",
                   [("sum by (stage, verdict) (increase(home_ids_cl_afpe_verdicts_total[1h]))", "{{stage}} → {{verdict}}")], stack=True),
    ], height=8)
    b.row([
        bars("Learned trust by destination kind", "Trust entries the filter has learned (mean trust in the next panel).",
             "home_ids_cl_afpe_trust_entries", "{{destination_class}}"),
        bars("Mean learned trust by destination kind", "0-100%: how strongly each kind of destination is trusted.",
             "home_ids_cl_afpe_trust_mean", "{{destination_class}}", unit="percentunit"),
        stat("Filter models", "Are the filter's classifier (LightGBM) and similarity (embedding) models loaded? Without them it falls back to simpler rules: more alerts, not fewer.",
             "min(home_ids_fp_lgbm_model_status) + min(home_ids_fp_embed_model_status)",
             mappings=value_map({0: ("🔴 Both missing", "red"), 1: ("🟡 One missing", "yellow"), 2: ("🟢 Both loaded", "green")}),
             steps=[(None, "red"), (1, "yellow"), (2, "green")], no_value="?"),
    ], height=7, widths=[9, 9, 6])
    b.section("⚙️ Autotuning", "Autotune proposes a value, tests it in a canary period, backtests it, then promotes or rolls back. "
              "A device uses its own value if it has one, else its device type's, else the global value.")
    b.row([
        table("Global values", "Network-wide calibrated values against their configured defaults.",
              [("A", by('home_ids_autotune_value{scope="global"}', "parameter"), column("Active value", "In force now.", decimals=3)),
               ("B", by("home_ids_autotune_config_value", "parameter"), column("Configured default", "Hand-set value in config.yaml.", decimals=3)),
               ("C", by('home_ids_autotune_canary_value{scope="global"}', "parameter"), column("On trial", "Proposed, still in its canary period.", decimals=3, no_value="—"))],
              key_field="parameter", key_label="Threshold"),
        table("Per device type", "Values calibrated for a whole device type.",
              [("A", keyed('home_ids_autotune_value{scope="category"}', "target", "parameter"), column("Active value", "In force for this device type.", decimals=3)),
               ("B", keyed('home_ids_autotune_canary_value{scope="category"}', "target", "parameter"), column("On trial", "Proposed, still in its canary period.", decimals=3, no_value="—"))],
              key_field="key", key_label="Device type · Threshold"),
    ], height=8)
    dev_scope = 'label_replace(home_ids_autotune_{kind}{{scope="device"}}, "device", "$1", "target", "(.*)")'
    per_dev = table("Per device", "Values calibrated for one specific device (filter with the device box).",
                    [("A", keyed(with_host(dev_scope.format(kind="value")), "hostname", "parameter"),
                      column("Active value", "In force for this device.", decimals=3)),
                     ("B", keyed(with_host(dev_scope.format(kind="canary_value")), "hostname", "parameter"),
                      column("On trial", "Proposed, still in its canary period.", decimals=3, no_value="—"))],
                    key_field="key", key_label="Device · Threshold")
    b.row([
        per_dev,
        panel("Autotune history", "Every change autotune has made, by threshold, scope and outcome. Promoted = active; superseded = replaced later; rolled back = undone (for example by the circuit breaker after a missed threat); not promoted = its trial ended without promotion.",
              "table", [q("home_ids_autotune_changes", instant=True, fmt="table")],
              options={"showHeader": True, "cellHeight": "sm", "footer": {"show": False}},
              defaults={"custom": {"align": "auto", "filterable": True, "cellOptions": {"type": "auto"}}},
              overrides=[{"matcher": {"id": "byName", "options": "Value"}, "properties": [{"id": "displayName", "value": "Changes"}]},
                         {"matcher": {"id": "byName", "options": "parameter"}, "properties": [{"id": "displayName", "value": "Threshold"}]},
                         {"matcher": {"id": "byName", "options": "scope"}, "properties": [{"id": "displayName", "value": "Scope"}]},
                         {"matcher": {"id": "byName", "options": "status"}, "properties": [{"id": "displayName", "value": "Outcome"}]}],
              transformations=[{"kind": "Transformation", "group": "organize", "spec": {"options": {
                  "excludeByName": {"Time": True, "__name__": True, "instance": True, "job": True}}}}]),
    ], height=9, widths=[12, 12])
    b.row([
        stat("Last promotion", "When autotune last promoted a new value.", 'time() - home_ids_autotune_last_change_timestamp{status="promoted"}',
             unit="s", no_value="never", steps=[(None, "text")]),
        stat("Last rollback", "When a value was last rolled back (for example by the circuit breaker after a missed threat).",
             'time() - home_ids_autotune_last_change_timestamp{status="rolled_back"}', unit="s", no_value="never", steps=[(None, "text")]),
        stat("Last backtest", "Did the most recent backtest (which gates every promotion) pass?", "home_ids_backtest_last_pass",
             mappings=value_map({0: ("🔴 Failed", "red"), 1: ("🟢 Passed", "green")}), steps=[(None, "red"), (1, "green")], no_value="?"),
        stat("Backtest age", "Time since the last backtest finished.", "time() - home_ids_backtest_last_run_timestamp", unit="s",
             steps=[(None, "green"), (129600, "orange"), (259200, "red")], no_value="never"),
    ], height=4)
    b.section("🧠 What it has learned", "")
    b.row([
        bars("Behaviour models by kind", "Per-device statistical baseline models (Gaussian, Beta, Poisson, Markov).", "home_ids_baseline_models", "{{model_kind}}"),
        bars("Starter baselines by device type", "Population priors: new devices start from what similar devices look like, instead of from zero.",
             "home_ids_population_priors", "{{device_type}}"),
        timeseries("Identity self-healing (per hour)", "A device's split identities merged back into one, or re-identified after a MAC address change.",
                   [("sum(increase(home_ids_identity_merges_total[1h])) or vector(0)", "merged"),
                    ("sum(increase(home_ids_identity_reidentify_migrations_total[1h])) or vector(0)", "re-identified after MAC change"),
                    ("sum(increase(home_ids_identity_reidentify_ambiguous_total[1h])) or vector(0)", "ambiguous (capture requested)")]),
    ], height=7)
    b.section("🕵️ Background reviewers", "Scheduled jobs that review the engine's own decisions. Their results come straight from the scheduler.")
    b.row([
        stat("LLM review: last success", "The LLM re-reviews suspicious decisions every few hours; under ~5h is normal.",
             'time() - home_ids_scheduler_task_last_success_timestamp{task="live_llm_review"}', unit="s",
             steps=[(None, "green"), (18000, "orange"), (43200, "red")], no_value="not since restart"),
        stat("Reviewed last run", "Decisions reviewed (fresh LLM calls plus reuses of an earlier answer for the same pattern).",
             'home_ids_scheduler_task_result{task="live_llm_review", field="reviewed"}', no_value="—"),
        stat("Fresh LLM calls", "Real calls to the LLM in the last run (each can take minutes).",
             'home_ids_scheduler_task_result{task="live_llm_review", field="queries_made"}', no_value="—"),
        stat("Waiting for review", "Decisions left for the next run. They are reviewed oldest first.",
             'home_ids_scheduler_task_result{task="live_llm_review", field="deferred"}', no_value="—", steps=[(None, "text")]),
        stat("Stopped for time", "Did the last run stop early to stay inside its time budget? That's normal on a slow LLM host; the rest waits.",
             'home_ids_scheduler_task_result{task="live_llm_review", field="stopped_for_deadline"}',
             mappings=value_map({0: ("No", "green"), 1: ("Yes (deferred)", "yellow")}), no_value="—", steps=[(None, "text")]),
    ], height=4)
    b.row([
        stat("Retro-hunt: last success", "Re-checks past traffic against today's threat intel, daily.",
             'time() - home_ids_scheduler_task_last_success_timestamp{task="live_retro_hunter"}', unit="s",
             steps=[(None, "green"), (93600, "orange"), (172800, "red")], no_value="not since restart"),
        stat("Retro-hunt findings", "Past connections now known to be bad, found in the last run.",
             'home_ids_scheduler_task_result{task="live_retro_hunter", field="findings_count"}', no_value="—",
             steps=[(None, "green"), (1, "red")]),
        stat("Cross-device matches", "Past connections matching something another of your devices has since confirmed.",
             'home_ids_scheduler_task_result{task="live_retro_hunter", field="local_intel_matches_count"}', no_value="—",
             steps=[(None, "green"), (1, "orange")]),
        table("Retro-hunt findings by device", "Per device, from the last run.",
              [("A", by(with_host('home_ids_scheduler_task_result_by_device{task="live_retro_hunter", field="findings_by_device"}', device_filter=False), "hostname"),
                column("Findings", "Past connections now known bad.", no_value="0")),
               ("B", by(with_host('home_ids_scheduler_task_result_by_device{task="live_retro_hunter", field="local_intel_matches_by_device"}', device_filter=False), "hostname"),
                column("Cross-device matches", "Matches to threats another device confirmed.", no_value="0"))],
              key_field="hostname", key_label="Device"),
    ], height=6, widths=[4, 4, 4, 12])
    return b


# ============================================================================ 5. System Health & Operations
def health():
    b = Board("home_ids_v3_mitigation", "5. 🛡️ System Health & Operations",
              "Is the machinery healthy: internal components, scheduled jobs, disk budget, containment, sensors and the engine process.")
    b.row([text_panel("", "Everything that keeps detection running. If something on the Overview looks wrong, the cause is usually here.")], height=2)
    b.section("🩺 Components", "The health manager checks every part and repairs what it can on its own.")
    b.row([
        table("Component health", "Every internal component the health manager watches, with its state and self-repair attempts.",
              [("A", by("home_ids_health_component_state", "component"), column("State", "Healthy, Degraded, Unhealthy, Safe mode (running reduced), Recovery failed, or Retired.",
                                                             mappings=HEALTH_MAP, cell="color-background")),
               ("B", by("home_ids_health_recovery_attempts", "component"), column("Repair attempts", "Self-repair attempts in the current back-off window.",
                                                                steps=[(None, "text"), (1, "orange")]))],
              key_field="component", key_label="Component", sort_by="State"),
        panel("Host load over time", "0 Normal · 1 Resource pressure · 2 Conserving · 3 Critical.", "state-timeline",
              [q("home_ids_health_pressure_level", legend="host load")], options={"showValue": "never", "mergeValues": True},
              defaults={"mappings": PRESSURE_MAP, "color": {"mode": "thresholds"},
                        "thresholds": thresholds((None, "green"), (1, "yellow"), (2, "orange"), (3, "red"))}),
    ], height=9, widths=[12, 12])
    b.section("📅 Scheduled jobs", "Every enabled background job, as seen by the scheduler. Retired jobs drop out on their own.")
    b.row([table("Scheduled jobs", "State, last success, runtime, time budget and trouble counts per job. Kills mean the job overran its budget and was stopped.",
                 [("A", by("home_ids_scheduler_task_state", "task"), column("State", "Idle, Running, Paused (a more urgent job is running), or Waiting (due but held back).",
                                                              mappings=TASK_STATE_MAP)),
                  ("B", by("time() - home_ids_scheduler_task_last_success_timestamp", "task"), column("Since last success", "Time since its last successful run (since the scheduler last started).",
                                                                                         unit="s", no_value="not since restart", steps=[(None, "text")])),
                  ("C", by("home_ids_scheduler_task_last_duration_seconds", "task"), column("Last runtime", "How long the last run took.", unit="s", no_value="—")),
                  ("D", by("home_ids_scheduler_task_budget_minutes", "task"), column("Time budget", "Longest it may actively run before being stopped.", unit="m")),
                  ("E", 'sum by (task) (home_ids_scheduler_task_runs_total{outcome="success"})', column("Successful runs", "Since the scheduler started.", no_value="0")),
                  ("F", 'sum by (task) (home_ids_scheduler_task_runs_total{outcome=~"error|failed"})', column("Failed runs", "Reported an error or exited abnormally.",
                                                                                                       no_value="0", steps=[(None, "text"), (1, "red")])),
                  ("G", "sum by (task) (home_ids_scheduler_task_kills_total)", column("Stopped for overrunning", "Times it hit its time budget and was stopped.",
                                                                                    no_value="0", steps=[(None, "text"), (1, "red")])),
                  ("H", "sum by (task) (home_ids_scheduler_task_preemptions_total)", column("Paused for others", "Times it was paused so a more urgent job could run.", no_value="0")),
                  ("I", 'sum by (task) (home_ids_scheduler_task_deferrals_total{reason="pressure"})', column("Held back (host load)", "Scheduler ticks it waited because the host was under pressure.", no_value="0")),
                  ("J", by("home_ids_scheduler_task_enabled", "task"), column("Enabled", "Currently enabled in config.", mappings=value_map({1: ("Yes", "green")})))],
                 key_field="task", key_label="Job", sort_by="Since last success")], height=10)
    b.section("💾 Disk budget", "The disk governor keeps the whole stack under a fixed size, trimming the oldest data first.")
    gov = 'home_ids_scheduler_task_result{task="disk_budget_governor"'
    b.row([
        bars("Used vs budget (GB)", "Size of each stored data set against its budget, from the governor's last run.",
             f'label_replace({gov}, field=~"graph_db.final_size_gb|zeek_logs.final_size_gb|state_files.state_files_gb"}}, "part", "$1", "field", "([a-z_]+)\\\\..*")',
             "{{part}} used", unit="decgbytes"),
        bars("Budgets (GB)", "The limits those data sets are held to.",
             f'label_replace({gov}, field=~"budget_gb.(graph_db|zeek_logs|state_files|total)"}}, "part", "$1", "field", "budget_gb.(.*)")',
             "{{part}} budget", unit="decgbytes"),
        stat("Governor last success", "The governor runs on a schedule; this is how long ago it last succeeded.",
             'time() - home_ids_scheduler_task_last_success_timestamp{task="disk_budget_governor"}', unit="s",
             no_value="not since restart", steps=[(None, "green"), (93600, "orange"), (172800, "red")]),
    ], height=7, widths=[10, 10, 4])
    b.section("🛡️ Containment", "What is being blocked or isolated right now, and whether blocking actions work.")
    b.row([
        stat("Devices tarpitted", "Devices trapped on the LAN by the ARP/NDP tarpit right now.", "count(home_ids_ips_tarpit_active == 1) or vector(0)",
             steps=[(None, "green"), (1, "red")]),
        stat("Devices router-isolated", "Devices cut off from the internet at the router right now.", "count(home_ids_ips_router_isolated_active == 1) or vector(0)",
             steps=[(None, "green"), (1, "red")]),
        stat("Domains blocked", "Domains currently blocked in Pi-hole.", "count(home_ids_ips_active_blocks == 1) or vector(0)", steps=[(None, "blue")]),
        stat("Blocks waiting to retry", "Blocking commands that failed and are being retried. Anything here is not actually blocked yet.",
             "count(home_ids_ips_queue_status) or vector(0)", steps=[(None, "green"), (1, "orange")]),
        stat("Blocks given up on", "Blocking commands that failed every retry. These domains are NOT blocked; check the Pi-hole connection.",
             "count(home_ids_ips_dead_letter) or vector(0)", steps=[(None, "green"), (1, "red")]),
        timeseries("Blocking errors (per minute)", "Failures while executing a block, isolation or release, by integration. Should stay at 0.",
                   [("sum by (target_type) (rate(home_ids_ips_errors_total[5m])) * 60 or vector(0)", "{{target_type}}")]),
    ], height=6, widths=[3, 3, 3, 3, 3, 9])
    b.section("📡 Sensors and data flow", "")
    b.row([
        stat("Processing delay", "Seconds between an event happening and the engine finishing it. A climbing value means it is falling behind.",
             "home_ids_collector_lag_seconds", unit="s", steps=[(None, "green"), (15, "orange"), (60, "red")], no_value="?", graph=True),
        timeseries("Events processed (per second)", "DNS and network events flowing through the engine. A drop to zero while devices are active means a sensor stalled.",
                   [("rate(home_ids_events_processed_total[5m])", "events / s")]),
        stat("Threat intel loaded", "Have the threat-intel feeds loaded at least once? Until then every lookup reads as clean.",
             "home_ids_ti_engine_ready", mappings=value_map({0: ("🔴 Not yet", "red"), 1: ("🟢 Ready", "green")}), steps=[(None, "red"), (1, "green")], no_value="?"),
        stat("Suricata scans OK (30 min)", "Share of Suricata scans that succeeded in the last 30 minutes (Suricata only runs during capture bursts).",
             'sum(increase(home_ids_suricata_scan_total{outcome="success"}[30m])) / sum(increase(home_ids_suricata_scan_total[30m]))',
             unit="percentunit", steps=[(None, "red"), (0.5, "orange"), (0.9, "green")], no_value="no scans"),
        stat("Evidence-graph export", "When the evidence graph was last published to Prometheus (every ~2 min). Stale means graph-based panels are stale.",
             "time() - home_ids_argus_exporter_last_success_timestamp", unit="s", steps=[(None, "green"), (600, "orange"), (1800, "red")], no_value="never"),
    ], height=6, widths=[4, 8, 4, 4, 4])
    b.section("⚙️ Engine process", "")
    b.row([
        timeseries("Engine CPU (100% = one full core)", "CPU used by the engine process.", [('rate(process_cpu_seconds_total{job="home_ids"}[5m]) * 100', "engine")], unit="percent"),
        timeseries("Engine memory", "Resident memory of the engine process. A steady climb with no plateau over days suggests a leak.",
                   [('process_resident_memory_bytes{job="home_ids"}', "engine")], unit="bytes"),
        stat("Engine uptime", "Time since the engine last (re)started. Unexpected drops mean it crashed and was restarted.",
             'time() - process_start_time_seconds{job="home_ids"}', unit="s", steps=[(None, "orange"), (3600, "green")]),
        stat("Unreadable model files removed", "Per-device ML model files found damaged at startup and removed (since the engine started). "
             "Each such device re-learns from scratch. Should stay 0; saves are atomic, so a non-zero value points at a disk problem.",
             'sum(home_ids_device_profile_discards_total{reason="corrupt"}) or vector(0)', steps=[(None, "green"), (1, "orange")]),
    ], height=7, widths=[9, 9, 3, 3])
    return b


# ============================================================================ assemble
def variables(device_var):
    v = [{"kind": "DatasourceVariable", "spec": {"name": "PROMETHEUS_DS", "pluginId": "prometheus", "refresh": "onDashboardLoad",
                                                 "regex": "", "current": {"text": "default", "value": "default"}, "options": [],
                                                 "multi": False, "includeAll": False, "hide": "dontHide", "skipUrlSync": False,
                                                 "allowCustomValue": True}},
         {"kind": "DatasourceVariable", "spec": {"name": "LOKI_DS", "pluginId": "loki", "refresh": "onDashboardLoad",
                                                 "regex": "", "current": {"text": "default", "value": "default"}, "options": [],
                                                 "multi": False, "includeAll": False, "hide": "dontHide", "skipUrlSync": False,
                                                 "allowCustomValue": True}}]
    # every dashboard gets the device box so ${device}-based links keep their selection
    v.append({"kind": "QueryVariable", "spec": {
        "name": "device", "label": "device", "current": {"text": "All", "value": "$__all"},
        "hide": "dontHide" if device_var else "hideVariable", "refresh": "onDashboardLoad", "skipUrlSync": False,
        "query": {"kind": "DataQuery", "group": "prometheus", "version": "v0", "datasource": {"name": PROM},
                  "spec": {"query": "label_values(home_ids_decision_state, hostname)", "refId": "StandardVariableQuery"}},
        "regex": "", "regexApplyTo": "value", "sort": "alphabeticalAsc",
        "definition": "label_values(home_ids_decision_state, hostname)", "options": [], "multi": True,
        "includeAll": True, "allValue": ".*", "allowCustomValue": True}})
    return v


LINKS = [("🏠 Overview", "home_ids_v3_main"), ("🌐 Threat Landscape", "home_ids_v3_landscape"),
         ("🔍 Device Deep Dive", "home_ids_v3_device"), ("🤖 Autonomy & Learning", "home_ids_v3_autonomous"),
         ("🛡️ System Health", "home_ids_v3_mitigation")]
FILES = {"home_ids_v3_main": "1_main_overview.json", "home_ids_v3_landscape": "2_threat_landscape.json",
         "home_ids_v3_device": "3_device_deep_dive.json", "home_ids_v3_autonomous": "4_autonomous_behavior.json",
         "home_ids_v3_mitigation": "5_system_health.json"}


def render(board: Board) -> dict:
    path = HERE / FILES[board.name]
    existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    metadata = existing.get("metadata") or {"name": board.name, "namespace": "default"}
    for k in ("resourceVersion", "generation", "creationTimestamp", "labels"):
        metadata.pop(k, None)
    metadata["name"] = board.name
    links = [{"title": t, "type": "link", "icon": "dashboard", "tooltip": t, "url": f"/d/{uid}", "tags": [],
              "asDropdown": False, "targetBlank": False, "includeVars": True, "keepTime": True}
             for t, uid in LINKS if uid != board.name]
    annotations = (existing.get("spec") or {}).get("annotations") or []  # Grafana's built-in annotation query
    return {"apiVersion": "dashboard.grafana.app/v2", "kind": "Dashboard", "metadata": metadata,
            "spec": {"annotations": annotations, "cursorSync": "Tooltip", "description": board.description, "editable": True,
                     "elements": board.elements, "layout": {"kind": "GridLayout", "spec": {"items": board.items}},
                     "links": links, "liveNow": False, "preload": False, "tags": [TAG],
                     "timeSettings": {"from": "now-24h", "to": "now", "autoRefresh": "1m",
                                      "autoRefreshIntervals": ["30s", "1m", "5m", "15m"], "hideTimepicker": False,
                                      "fiscalYearStartMonth": 0},
                     "title": board.title, "variables": variables(board.device_var)}}


def main():
    for build in (overview, landscape, device, autonomy, health):
        board = build()
        out = render(board)
        with open(HERE / FILES[board.name], "w", encoding="utf-8", newline="\n") as f:  # LF on every OS
            f.write(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
        print(f"{FILES[board.name]}: {len(board.elements)} panels")


if __name__ == "__main__":
    main()
