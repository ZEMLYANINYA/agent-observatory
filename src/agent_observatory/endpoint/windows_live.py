from __future__ import annotations

from .correlation import (
    correlate_application_network,
    format_network_snapshot,
)
from .windows_capture import (
    attributable_tcp_connections,
    collect_windows_capture,
    rejected_tcp_connections,
    stable_processes,
)
from .windows_snapshot import collect_application_snapshots


def collect_live_snapshot() -> str:
    capture = collect_windows_capture()

    process_snapshots = collect_application_snapshots(
        stable_processes(capture)
    )
    tcp_connections = attributable_tcp_connections(capture)

    correlated = correlate_application_network(
        process_snapshots,
        tcp_connections,
    )

    output = format_network_snapshot(correlated)
    rejected_count = len(rejected_tcp_connections(capture))

    if rejected_count:
        guard = (
            "Attribution guard: skipped "
            f"{rejected_count} TCP connection(s) because the owning PID "
            "was not stable across the bracketing process snapshots."
        )

        if output:
            output = f"{output}\n\n{guard}"
        else:
            output = guard

    return output


def main() -> int:
    output = collect_live_snapshot()

    if not output:
        print("No configured AI desktop applications detected.")
        return 1

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
