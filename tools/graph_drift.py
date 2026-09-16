from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from agent_observatory.analysis import GraphDrift, compare_graph_streams
from agent_observatory.storage import EventStore


DEFAULT_DB_PATH = Path(".local") / "agent-observatory.sqlite3"


def _resolve_stream_pair(
    store: EventStore,
    before: str | None,
    after: str | None,
) -> tuple[str, str]:
    if (before is None) != (after is None):
        raise ValueError("provide both --before and --after, or neither")

    if before is not None and after is not None:
        if not before.strip() or not after.strip():
            raise ValueError("stream ids must be non-empty strings")
        return before, after

    streams = store.list_stream_ids()
    if len(streams) < 2:
        raise ValueError("Graph Drift requires at least two persisted streams")
    return streams[-2], streams[-1]


def _print_show(drift: GraphDrift, *, details: bool) -> None:
    print(f"before: {drift.before_stream_id}")
    print(f"after:  {drift.after_stream_id}")
    print()
    print("GRAPH DRIFT:")
    print("  provenance ids/timestamps are excluded from structural comparison")

    print("NODE DRIFT:")
    for item in drift.nodes:
        print(
            f"  {item.node_type.value:<18} "
            f"unchanged={len(item.unchanged):<4} "
            f"added={len(item.added):<3} "
            f"removed={len(item.removed):<3} "
            f"changed={len(item.changed):<3}"
        )
        if details:
            for node_id in item.added:
                print(f"    + {node_id}")
            for node_id in item.removed:
                print(f"    - {node_id}")
            for change in item.changed:
                print(f"    ~ {change.node_id}")
                print(
                    "      before="
                    + json.dumps(
                        dict(change.before_attributes),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                )
                print(
                    "      after ="
                    + json.dumps(
                        dict(change.after_attributes),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                )

    print("EDGE DRIFT:")
    for item in drift.edges:
        print(
            f"  {item.edge_type.value:<18} "
            f"unchanged={item.unchanged_count:<4} "
            f"added={len(item.added):<3} "
            f"removed={len(item.removed):<3} "
            f"changed={len(item.changed):<3} "
            f"ambiguous={len(item.ambiguous_keys):<3}"
        )
        if details:
            for fact in item.added:
                print(
                    f"    + {fact.source_node_id} -> {fact.target_node_id} "
                    f"attrs={json.dumps(dict(fact.attributes), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)}"
                )
            for fact in item.removed:
                print(
                    f"    - {fact.source_node_id} -> {fact.target_node_id} "
                    f"attrs={json.dumps(dict(fact.attributes), ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)}"
                )
            for change in item.changed:
                print(f"    ~ {change.edge_key}")
                print(
                    "      before="
                    + json.dumps(
                        dict(change.before_attributes),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                )
                print(
                    "      after ="
                    + json.dumps(
                        dict(change.after_attributes),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    )
                )
            for key in item.ambiguous_keys:
                print(f"    ? {key}")

    continuity_counts = Counter(item.status for item in drift.process_continuity)
    print("PROCESS CONTINUITY:")
    print(f"  compared_pid_slots={len(drift.process_continuity)}")
    for status in sorted(continuity_counts, key=lambda item: item.value):
        print(f"  {status.value:<20} {continuity_counts[status]}")
    if details:
        for item in drift.process_continuity:
            before_instances = ",".join(item.before_instances)
            after_instances = ",".join(item.after_instances)
            print(
                f"    pid={item.pid} status={item.status.value} "
                f"before={before_instances} after={after_instances}"
            )

    notes = drift.projection_notes
    print("PROJECTION NOTE DRIFT:")
    print(
        f"  unchanged={notes.unchanged_count} "
        f"added={sum(item.count for item in notes.added)} "
        f"removed={sum(item.count for item in notes.removed)}"
    )
    if details:
        for item in notes.added:
            print(f"    + {item.event_type.value}:{item.reason} count={item.count}")
        for item in notes.removed:
            print(f"    - {item.event_type.value}:{item.reason} count={item.count}")

    print()
    print(
        "result: structural changes observed"
        if drift.has_changes
        else "result: no structural changes observed"
    )


def _drift_payload(drift: GraphDrift) -> dict[str, object]:
    return {
        "before_stream_id": drift.before_stream_id,
        "after_stream_id": drift.after_stream_id,
        "has_changes": drift.has_changes,
        "nodes": [
            {
                "node_type": item.node_type.value,
                "added": list(item.added),
                "removed": list(item.removed),
                "unchanged": list(item.unchanged),
                "changed": [
                    {
                        "node_id": change.node_id,
                        "before_attributes": dict(change.before_attributes),
                        "after_attributes": dict(change.after_attributes),
                    }
                    for change in item.changed
                ],
            }
            for item in drift.nodes
        ],
        "edges": [
            {
                "edge_type": item.edge_type.value,
                "unchanged_count": item.unchanged_count,
                "ambiguous_keys": list(item.ambiguous_keys),
                "added": [
                    {
                        "source_node_id": fact.source_node_id,
                        "target_node_id": fact.target_node_id,
                        "attributes": dict(fact.attributes),
                    }
                    for fact in item.added
                ],
                "removed": [
                    {
                        "source_node_id": fact.source_node_id,
                        "target_node_id": fact.target_node_id,
                        "attributes": dict(fact.attributes),
                    }
                    for fact in item.removed
                ],
                "changed": [
                    {
                        "edge_key": change.edge_key,
                        "source_node_id": change.source_node_id,
                        "target_node_id": change.target_node_id,
                        "before_attributes": dict(change.before_attributes),
                        "after_attributes": dict(change.after_attributes),
                    }
                    for change in item.changed
                ],
            }
            for item in drift.edges
        ],
        "process_continuity": [
            {
                "pid": item.pid,
                "status": item.status.value,
                "before_instances": list(item.before_instances),
                "after_instances": list(item.after_instances),
            }
            for item in drift.process_continuity
        ],
        "projection_notes": {
            "unchanged_count": drift.projection_notes.unchanged_count,
            "added": [
                {
                    "event_type": item.event_type.value,
                    "reason": item.reason,
                    "count": item.count,
                }
                for item in drift.projection_notes.added
            ],
            "removed": [
                {
                    "event_type": item.event_type.value,
                    "reason": item.reason,
                    "count": item.count,
                }
                for item in drift.projection_notes.removed
            ],
        },
    }


def _print_json(drift: GraphDrift) -> None:
    print(
        json.dumps(
            _drift_payload(drift),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two persisted EventStore streams through their read-only "
            "Evidence Graph projections."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Existing EventStore SQLite path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument("--before", help="Before stream id. Defaults to penultimate stream.")
    parser.add_argument("--after", help="After stream id. Defaults to latest stream.")
    parser.add_argument(
        "command",
        choices=("show", "json"),
        help="Drift report view to print.",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help="Print changed structural facts in the human-readable report.",
    )
    args = parser.parse_args(argv)

    if args.command == "json" and args.details:
        parser.error("--details is only valid with show")

    if not args.db.is_file():
        print(f"Graph drift failed: database does not exist: {args.db}", file=sys.stderr)
        return 1

    try:
        store = EventStore(args.db)
        before, after = _resolve_stream_pair(store, args.before, args.after)
        drift = compare_graph_streams(store, before, after)
    except (KeyError, OSError, ValueError, RuntimeError) as exc:
        print(f"Graph drift failed: {exc}", file=sys.stderr)
        return 1

    if args.command == "show":
        _print_show(drift, details=args.details)
    elif args.command == "json":
        _print_json(drift)
    else:
        raise RuntimeError(f"unsupported command: {args.command}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
