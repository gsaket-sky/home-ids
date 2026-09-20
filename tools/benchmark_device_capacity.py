#!/usr/bin/env python3
"""
benchmark_device_capacity.py -- Phase 4 of the memory-restart investigation
(Documentation/MEMORY_RESTART_ROOT_CAUSE_AND_CAPACITY_PLAN.md): answers "how
many devices can a Raspberry Pi 8GB handle" with a real, measured curve
instead of a guess.

Drives the SAME real code path pipeline.py uses per device per cycle --
argus.ops.live_engine.evaluate() -- with synthetic-but-realistically-rated
traffic for N virtual devices, compressing simulated time (evaluate() is
called with an explicit, advancing `now`, not real wall-clock sleeps) so a
multi-day capacity curve doesn't require multi-day wall-clock runtime.
Everything downstream of evaluate() is 100% real: the same HypothesisEngine/
DecisionEngine/BaselineEngine/GraphStore code this project ships, writing to
an isolated state dir (never the real state/v13_graph.db).

Traffic model, not a guess: per-device event rates are taken directly from
.94's own real measured system-wide rates (2026-09-20 investigation) --
~530 evidence items/device/day, ~28 decision-state-changes/device/day, for a
household of ~13-55 tracked device identities. See _EVIDENCE_PER_DEVICE_PER_DAY/
_STATE_CHANGE_PROBABILITY_PER_TICK's own comments for the exact derivation.

Run under a Pi-approximating cgroup for a trustworthy result -- this machine's
CPU is NOT the target hardware:
    systemd-run --scope -p MemoryMax=8G -p CPUQuota=76% \\
        python3 tools/benchmark_device_capacity.py --devices 50 --simulated-days 7

CPUQuota=76% is calibrated (2026-09-20) from Geekbench 6 single-core scores:
Ryzen 5 3550H ~1012, Raspberry Pi 5 ~770 -- a 1.31x gap, not the 3-5x this
project's own docs previously assumed before actually looking it up. 1/1.31
~= 76%. This corrects single-thread throughput; it does NOT correct for the
Pi's different core count/topology (4 Cortex-A76 cores vs the Ryzen's 4C/8T) --
a real Pi run would still be the more trustworthy number (see the plan doc's
own open question on this).
"""
import argparse
import json
import random
import sys
import time
from pathlib import Path

import psutil

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from intelligence.hypotheses.evidence import Evidence as V1Evidence  # noqa: E402
from intelligence.reputation.classifier import ReputationVector  # noqa: E402
import argus.ops.live_engine as live_engine  # noqa: E402

# Calibrated against .94's real measured rates (2026-09-20 investigation):
# 29,157 evidence rows/day system-wide / ~55 tracked device identities at the
# time of measurement ~= 530/device/day. 1,543 decisions/day system-wide /
# ~55 ~= 28/device/day -- but insert_decision() only fires on a STATE CHANGE
# (_write_graph()'s own dedup), not every cycle, so this is modeled as a
# per-tick PROBABILITY of the device's state actually changing, not a fixed
# count. First-pass, not empirically re-validated against Phase 1/2's
# now-fixed write path -- rerun this benchmark's own numbers once .94 has
# accumulated a few weeks on the fixed code, per the plan doc's own honesty
# framing for every other not-yet-validated constant in this project.
_EVIDENCE_PER_DEVICE_PER_DAY = 530
_TICKS_PER_DAY = 288  # one tick per 5 simulated minutes -- fine enough
# granularity for realistic-looking traffic bursts without needing a tick
# per real evidence item (530/day ~= 1.8/tick already averaged into batches).
_STATE_CHANGE_PROBABILITY_PER_TICK = 28.0 / _TICKS_PER_DAY

_EVIDENCE_TYPES = [
    # (type, independence_group, weight) -- weighted toward everyday, mostly-
    # benign traffic shapes, matching what a real household's evidence table
    # is actually dominated by (dns_query_volume/connection-log-style types),
    # not attack-shaped evidence (which is comparatively rare, by design).
    ("dns_query_volume", "traffic_volume", 40),
    ("new_destination", "destination_novelty", 20),
    ("zeek_notice_weak", "zeek_network", 15),
    ("peer_deviation", "behavioral", 10),
    ("elevated_connection_rate", "traffic_volume", 10),
    ("zeek_notice_medium", "zeek_network", 5),
]
_DESTINATIONS = [f"dest{i}.example.com" for i in range(200)]


def _synthetic_evidence_batch(device_id: str, now: float, rng: random.Random, batch_size: int):
    out = []
    for _ in range(batch_size):
        ev_type, group, _ = rng.choices(_EVIDENCE_TYPES, weights=[w for *_, w in _EVIDENCE_TYPES])[0]
        out.append(V1Evidence(
            type=ev_type, source="synthetic_benchmark", timestamp=now, device=device_id,
            value=round(rng.uniform(0.1, 1.0), 2), confidence=round(rng.uniform(0.3, 0.9), 2),
            independence_group=group, domain=rng.choice(_DESTINATIONS),
        ))
    return out


def run_benchmark(devices: int, simulated_days: float, state_dir: Path, hardware_profile: str,
                    sample_every_ticks: int, seed: int) -> dict:
    state_dir.mkdir(parents=True, exist_ok=True)
    db_path = state_dir / "v13_graph.db"
    live_engine.configure(str(db_path), hardware_profile=hardware_profile)

    rng = random.Random(seed)
    process = psutil.Process()
    device_ids = [f"bench_device_{i:04d}" for i in range(devices)]
    total_ticks = int(simulated_days * _TICKS_PER_DAY)
    now = time.time()
    tick_seconds = 86400.0 / _TICKS_PER_DAY

    samples = []
    start_wall = time.time()
    for tick in range(total_ticks):
        now += tick_seconds
        for device_id in device_ids:
            # Most ticks: a handful of ordinary evidence items, no state change.
            # A minority of ticks (per _STATE_CHANGE_PROBABILITY_PER_TICK): a
            # sharper burst that's more likely to actually flip the device's
            # decision state, matching how a real state change usually
            # coincides with a real behavioral shift, not a single stray item.
            is_burst = rng.random() < _STATE_CHANGE_PROBABILITY_PER_TICK
            batch_size = rng.randint(3, 6) if is_burst else rng.randint(0, 2)
            if batch_size == 0:
                continue
            evidence = _synthetic_evidence_batch(device_id, now, rng, batch_size)
            rep = ReputationVector(domain=evidence[-1].domain if evidence else "", tier=rng.choice([0, 0, 0, 1, 3]))
            live_engine.evaluate(
                evidence, rep, device_type="iot", features={}, device_id=device_id, now=now,
            )

        if tick % sample_every_ticks == 0 or tick == total_ticks - 1:
            wal_path = db_path.with_name(db_path.name + "-wal")
            samples.append({
                "simulated_day": round(tick / _TICKS_PER_DAY, 2),
                "wall_clock_seconds_elapsed": round(time.time() - start_wall, 1),
                "rss_mb": round(process.memory_info().rss / (1024 * 1024), 1),
                "db_size_mb": round(db_path.stat().st_size / (1024 * 1024), 2) if db_path.exists() else 0.0,
                "wal_size_mb": round(wal_path.stat().st_size / (1024 * 1024), 2) if wal_path.exists() else 0.0,
            })
            print(f"  day {samples[-1]['simulated_day']:>6.2f} -- "
                  f"rss={samples[-1]['rss_mb']}MB db={samples[-1]['db_size_mb']}MB "
                  f"wal={samples[-1]['wal_size_mb']}MB "
                  f"({samples[-1]['wall_clock_seconds_elapsed']}s wall-clock elapsed)", flush=True)

    return {
        "devices": devices, "simulated_days": simulated_days, "hardware_profile": hardware_profile,
        "seed": seed, "samples": samples,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--devices", type=int, required=True, help="Number of synthetic virtual devices.")
    parser.add_argument("--simulated-days", type=float, default=7.0,
                         help="Simulated days of traffic to compress into this run (default: 7).")
    parser.add_argument("--state-dir", default=None,
                         help="Isolated scratch dir for this run's own v13_graph.db "
                              "(default: a fresh tmp dir under state/benchmark_runs/).")
    parser.add_argument("--hardware-profile", default="pi_8gb", choices=["pi_8gb", "x86_16gb", "custom"])
    parser.add_argument("--sample-every-ticks", type=int, default=_TICKS_PER_DAY // 4,
                         help="How often (in ticks) to sample RSS/db size (default: every 6 simulated hours).")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default=None, help="Write the full result JSON here (default: stdout only).")
    args = parser.parse_args()

    state_dir = Path(args.state_dir) if args.state_dir else Path("state/benchmark_runs") / f"n{args.devices}_{int(time.time())}"
    print(f"Benchmarking {args.devices} devices, {args.simulated_days} simulated days, "
          f"profile={args.hardware_profile}, state_dir={state_dir}")

    result = run_benchmark(
        devices=args.devices, simulated_days=args.simulated_days, state_dir=state_dir,
        hardware_profile=args.hardware_profile, sample_every_ticks=args.sample_every_ticks, seed=args.seed,
    )

    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nFull result written to {args.out}")
    final = result["samples"][-1]
    print(f"\nFinal (day {final['simulated_day']}): rss={final['rss_mb']}MB, "
          f"db={final['db_size_mb']}MB, wal={final['wal_size_mb']}MB")


if __name__ == "__main__":
    main()
