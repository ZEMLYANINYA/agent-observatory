from __future__ import annotations

import sys
from pathlib import Path

from agent_observatory.endpoint.baseline_compare import (
    DifferenceKind,
    compare_processes_to_baseline,
)
from agent_observatory.endpoint.baseline_store import (
    load_process_baseline,
    save_process_baseline,
)
from agent_observatory.endpoint.fingerprint import fingerprint_process
from agent_observatory.endpoint.windows_snapshot import collect_processes


BASELINE_PATH = Path(".local") / "exp001-process-baseline.json"


def current_fingerprints():
    processes = collect_processes()

    return processes, tuple(
        fingerprint_process(process)
        for process in processes
    )


def learn() -> int:
    processes, fingerprints = current_fingerprints()

    save_process_baseline(
        BASELINE_PATH,
        fingerprints,
    )

    print(f"Baseline saved: {BASELINE_PATH}")
    print(f"Processes observed: {len(processes)}")
    print(f"Unique fingerprints: {len(set(fingerprints))}")

    return 0


def check() -> int:
    if not BASELINE_PATH.exists():
        print("Baseline does not exist. Run with 'learn' first.")
        return 2

    baseline = load_process_baseline(BASELINE_PATH)
    processes = collect_processes()

    differences = compare_processes_to_baseline(
        processes,
        baseline,
    )

    first_seen = tuple(
        item
        for item in differences
        if item.kind is DifferenceKind.FIRST_SEEN
    )

    if not first_seen:
        print("FIRST_SEEN: 0")
        return 0

    print(f"FIRST_SEEN: {len(first_seen)}")

    for item in first_seen:
        print(
            f"  PID={item.pid:<6} "
            f"PPID={item.ppid:<6} "
            f"ROLE={item.fingerprint.role.value:<13} "
            f"{item.name}"
        )

    return 1


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: exp001_first_seen.py learn|check")
        return 2

    command = sys.argv[1].casefold()

    if command == "learn":
        return learn()

    if command == "check":
        return check()

    print(f"Unknown command: {sys.argv[1]}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())