from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from agent_observatory.analysis.firewall_rule_candidates import (
    FirewallCandidateStatus,
    correlate_firewall_rule_candidates,
)
from agent_observatory.storage import EventStore


DEFAULT_DB_PATH = Path(".local") / "agent-observatory.sqlite3"


def _resolve_stream_id(store: EventStore, explicit: str | None) -> str:
    if explicit:
        return explicit
    stream_ids = store.list_stream_ids()
    if not stream_ids:
        raise ValueError("EventStore contains no streams")
    return stream_ids[-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Correlate persisted TCP listener evidence with candidate inbound Windows "
            "Firewall rule facts without computing effective allow/block disposition."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"EventStore SQLite path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument("--stream-id", help="Explicit service-exposure stream id")
    parser.add_argument(
        "--port",
        type=int,
        help="Show only listeners with this local port",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Print candidate rule ids, actions, profiles, and unresolved dimensions",
    )
    args = parser.parse_args(argv)

    if not args.db.exists():
        print(f"EventStore does not exist: {args.db}", file=sys.stderr)
        return 1
    if args.port is not None and not (0 <= args.port <= 65535):
        print("--port must be between 0 and 65535", file=sys.stderr)
        return 1

    try:
        store = EventStore(args.db)
        stream_id = _resolve_stream_id(store, args.stream_id)
        correlation = correlate_firewall_rule_candidates(store, stream_id)
    except Exception as exc:
        print(f"Correlation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    listeners = correlation.listeners
    if args.port is not None:
        listeners = tuple(item for item in listeners if item.local_port == args.port)

    status_counts = Counter(item.status.value for item in listeners)
    print(f"EventStore: {args.db}")
    print(f"stream_id: {stream_id}")
    print(
        "active_network_categories: "
        + (", ".join(correlation.active_network_categories) or "unknown")
    )
    print(f"listeners_selected: {len(listeners)}")
    print()
    print("STATUS COUNTS:")
    for status in FirewallCandidateStatus:
        print(f"  {status.value:<18} {status_counts.get(status.value, 0)}")

    print()
    print("LISTENERS:")
    if not listeners:
        print("  none")
    for item in listeners:
        print(
            "  "
            f"event={item.listener_event_id} "
            f"{item.local_address}:{item.local_port} "
            f"owner_pid={item.owner_pid} "
            f"status={item.status.value} "
            f"candidates={len(item.candidates)}"
        )
        if args.details:
            for candidate in item.candidates:
                compatible = ",".join(candidate.compatible_dimensions) or "none"
                unknown = ",".join(candidate.unknown_dimensions) or "none"
                print(
                    "    "
                    f"rule_event={candidate.rule_event_id} "
                    f"action={candidate.action} "
                    f"profile={candidate.profile} "
                    f"name={candidate.rule_name!r} "
                    f"compatible={compatible} "
                    f"unknown={unknown}"
                )

    print()
    print("SEMANTICS:")
    print("  candidate rules are source-compatible possibilities, not effective firewall verdicts")
    print("  AMBIGUOUS may mean multiple candidate rules or unresolved rule dimensions")
    print("  NO_CANDIDATE does not prove remote unreachability")
    print("  no authentication or exploitability is inferred")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
