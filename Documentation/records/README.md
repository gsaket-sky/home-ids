# Engineering records

These are dated working documents from building Home-IDS: investigations, audits, capacity analyses and design
plans. Each one is a snapshot of its own date. They show how decisions were reached, so they mention earlier
designs, internal code names and test hosts.

**They are not the current reference.** For how the system works today, read
[ENGINEERING_MANUAL.md](../ENGINEERING_MANUAL.md). For the story they add up to, read
[EVOLUTION.md](../EVOLUTION.md).

| Record | Date | What it covers |
|---|---|---|
| [ARCHITECTURE_REVIEW_2026-09.txt](ARCHITECTURE_REVIEW_2026-09.txt) | 2026-09-10 | A full architecture, detection and mitigation review report, kept verbatim (a design review, not an independent security assessment) |
| [ARCHITECTURE_REVIEW_2026-09_RESPONSE.md](ARCHITECTURE_REVIEW_2026-09_RESPONSE.md) | 2026-09-10 | A finding-by-finding response to that review, and what was changed |
| [AUDIT_REVIEW_FOLLOWUP.md](AUDIT_REVIEW_FOLLOWUP.md) | 2026-09-09 | A design review of two real alerts, and the roadmap that followed |
| [ARGUS_ARCHITECTURE.md](ARGUS_ARCHITECTURE.md) | September 2026 | The detailed architecture reference while the evidence-graph engine replaced the original engine |
| [ARGUS_DECISIONS.md](ARGUS_DECISIONS.md) | September 2026 | The design decisions behind the evidence graph, autotuning and identity, with alternatives considered |
| [ARGUS_AUTONOMY_DEPENDENCY_MAP.md](ARGUS_AUTONOMY_DEPENDENCY_MAP.md) | September 2026 | The dependency map used to build full autonomy |
| [ALERT_TRACE_GRAPH_PLAN.md](ALERT_TRACE_GRAPH_PLAN.md) | 2026-09-22 | Tracing each alert through its evidence; plain-language alert text |
| [ARGUS_OBSERVABILITY_PLAN.md](ARGUS_OBSERVABILITY_PLAN.md) | 2026-09-23 | Metrics, job fixes and the dashboard redesign |
| [GRAFANA_DASHBOARD_AUDIT_2026-09-23.md](GRAFANA_DASHBOARD_AUDIT_2026-09-23.md) | 2026-09-23 | An audit of every dashboard panel against the data behind it |
| [DISK_CAPACITY_AND_RETENTION_AUDIT.md](DISK_CAPACITY_AND_RETENTION_AUDIT.md) | 2026-09-23 | Disk growth over a ten-year continuous run, and the retention design |
| [MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md](MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md) | 2026-09-28 | The root cause of memory-driven restarts, and capacity planning |
| [REACTIVE_CAPTURE_LOAD_ANALYSIS.md](REACTIVE_CAPTURE_LOAD_ANALYSIS.md) | August–September 2026 | Best-case and worst-case load of router capture bursts |
| [RESOURCE_AWARE_SCHEDULING.md](RESOURCE_AWARE_SCHEDULING.md) | 2026-09-22 | The single-slot, priority-based background job scheduler |
