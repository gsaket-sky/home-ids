# Home-IDS — an evidence-graph intrusion detection system for home networks

A self-built network security system: it watches a network with [Zeek](https://zeek.org) and DNS telemetry, models what
is *normal for each individual device*, reasons about what it sees as competing hypotheses backed by independent
evidence, and acts — blocking, isolating or asking a human — only when the evidence justifies it. It has been running
on a real home network, and this repository is the engineering behind it: **~55,000 lines of Python, 158 test
scripts, and the design documents and mathematics that explain every decision.**

> **This is a showcase, not a product.** The code is published to be read. It is licensed for viewing only
> (see [LICENSE](LICENSE)) and is deliberately not packaged for installation — see [Running it](#running-it).

## What makes it interesting

| Idea | Where to read about it |
|---|---|
| **Evidence graph.** Observations (a DNS burst, a suspicious TLS fingerprint, a periodic beacon…) are typed, timestamped *evidence* attached to a device and a destination in a SQLite graph. Decisions are made over the graph, so every alert has a traceable chain back to its evidence. | [ARGUS_ARCHITECTURE.md](Documentation/ARGUS_ARCHITECTURE.md), `src/argus/graph/` |
| **Hypothesis competition with independence.** Threat hypotheses (C2 beaconing, DNS tunnelling, DGA, scanning, exfiltration, …) compete with benign explanations; corroboration only counts across *independent* evidence families, so five readings of the same signal never add up to a false certainty. | [PIPELINE_MATH_REFERENCE.md](Documentation/PIPELINE_MATH_REFERENCE.md), `src/argus/hypotheses/` |
| **Per-device behavioural baselines.** Bayesian online change-point detection (BOCPD) and Markov models per device, metric and hour; peer cohorts so a device is also compared with devices like it. | `src/argus/baseline/`, [ARGUS_ARCHITECTURE.md](Documentation/ARGUS_ARCHITECTURE.md) |
| **A second system grades the first.** CL-AFPE (a continuously-learning false-positive engine) suppresses what it is confident is benign, remembers why, and keeps its own track record — suppression is revocable and never hides a hard indicator. | `src/argus/cl_afpe/`, [ARGUS_DECISIONS.md](Documentation/ARGUS_DECISIONS.md) |
| **Autonomy with accountability.** Self-tuning thresholds are evidence-gated, bounded, logged with their reasons, and reversible. | `src/argus/autotune/`, [ARGUS_AUTONOMY_DEPENDENCY_MAP.md](Documentation/ARGUS_AUTONOMY_DEPENDENCY_MAP.md) |
| **Built for small, fragile hardware.** A health manager with resource-pressure modes, resource-aware job scheduling, bounded I/O on every hot path, and flash-wear-aware persistence (changed-rows-only SQLite state). | `src/core/health_manager.py`, [RESOURCE_AWARE_SCHEDULING.md](Documentation/RESOURCE_AWARE_SCHEDULING.md), [DISK_CAPACITY_AND_RETENTION_AUDIT.md](Documentation/DISK_CAPACITY_AND_RETENTION_AUDIT.md) |
| **Containment that explains itself.** DNS sinkholing, router-level isolation and a Layer-2 ARP/NDP tarpit (own raw-socket implementation, no third-party packet library), each with a plain-language explanation and a one-tap undo. | `src/mitigation/` |
| **Honest engineering records.** Audits, root-cause write-ups and "what we got wrong" are kept next to the code. | [AUDIT_V14_REVIEW_RESPONSE.md](Documentation/AUDIT_V14_REVIEW_RESPONSE.md), [MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md](Documentation/MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md) |

## Where to start reading

| Document | What it covers |
|---|---|
| [ENGINEERING_MANUAL.md](Documentation/ENGINEERING_MANUAL.md) | The whole system, component by component |
| [ARGUS_ARCHITECTURE.md](Documentation/ARGUS_ARCHITECTURE.md) | Pipeline stages, scheduling, the two decision engines, autotuning, identity, the health manager, threat categorisation |
| [PIPELINE_MATH_REFERENCE.md](Documentation/PIPELINE_MATH_REFERENCE.md) | The mathematics: scoring, baselines, confidence, staleness |
| [ARGUS_DECISIONS.md](Documentation/ARGUS_DECISIONS.md) | Standing rules, closed decisions, and what is deliberately not built |
| [CONFIG_API.md](Documentation/CONFIG_API.md), [CONSOLE_DATA_API.md](Documentation/CONSOLE_DATA_API.md) | The engine API and the engineering console's data model |
| [USER_MANUAL.md](Documentation/USER_MANUAL.md) | Every setting and what it does |
| [CHANGELOG.md](Documentation/CHANGELOG.md) | Release by release |

## Repository layout

```
src/core/          pipeline, health manager, state, scheduling, identity
src/argus/         evidence graph, hypotheses, baselines, CL-AFPE, autotune, shadow evaluation
src/extractors/    Zeek and DNS feature extraction
src/intelligence/  threat-intelligence feeds, false-positive engine, detectors
src/mitigation/    containment (DNS, router, Layer-2 raw sockets)
src/middleware/    engine API
web/               the engineering console (single-page, no build step)
tests/             158 standalone and pytest scripts
```

## Running it

Home-IDS needs a Zeek sensor on a mirrored or in-path interface, a Pi-hole instance, a Python environment, a router
integration if you want hardware-level isolation, and a hand-written `config.yaml` (see `config.yaml.example` and
[USER_MANUAL.md](Documentation/USER_MANUAL.md)). It is **not packaged, not supported and not licensed for running**
([LICENSE](LICENSE)); there is no installer and no step-by-step guide on purpose. If you want to discuss it, or
the work behind it, get in touch through the profile of the account that owns this repository.

## Limits, stated plainly

It is a single-site system tuned on one network; it sees what its sensor sees (Wi-Fi traffic through an all-in-one
router is only partly visible, which the documents explain); and it is a detector that helps a person decide, not a
guarantee. The documents list what it still cannot do.
