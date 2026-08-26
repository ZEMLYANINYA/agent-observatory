from __future__ import annotations

from .correlation import (
    correlate_application_network,
    format_network_snapshot,
)
from .windows_network import collect_tcp_connections
from .windows_snapshot import collect_application_snapshots


def collect_live_snapshot() -> str:
    process_snapshots = collect_application_snapshots()
    tcp_connections = collect_tcp_connections()

    correlated = correlate_application_network(
        process_snapshots,
        tcp_connections,
    )

    return format_network_snapshot(correlated)


def main() -> int:
    output = collect_live_snapshot()

    if not output:
        print("No configured AI desktop applications detected.")
        return 1

    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())