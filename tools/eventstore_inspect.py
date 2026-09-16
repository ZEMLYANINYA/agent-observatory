from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from agent_observatory.analysis import compare_streams, summarize_stream
from agent_observatory.storage import EventStore


DEFAULT_DB_PATH = Path(".local") / "agent-observatory.sqlite3"


def _iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _resolve_stream(
    store: EventStore,
    requested: str | None,
    *,
    offset_from_latest: int = 0,
) -> str:
    if requested is not None:
        return requested

    streams = store.list_stream_ids()
    index = len(streams) - 1 - offset_from_latest
    if index < 0:
        raise ValueError("not enough persisted streams")
    return streams[index]


def _print_stream_summary(store: EventStore, stream_id: str) -> int:
    summary = summarize_stream(store, stream_id)
    if summary is None:
        print(f"Stream not found: {stream_id}", file=sys.stderr)
        return 1

    print(f"stream_id: {summary.stream_id}")
    print(f"events: {summary.event_count}")
    print(f"event_id_range: {summary.first_event_id}..{summary.last_event_id}")
    print(f"observed_start: {_iso(summary.observed_start)}")
    print(f"observed_end:   {_iso(summary.observed_end)}")
    print(f"sources: {', '.join(summary.sources)}")
    print("event_counts:")
    for event_type, count in summary.event_counts:
        print(f"  {event_type.value:<34} {count}")
    return 0


def _print_stream_list(store: EventStore) -> int:
    stream_ids = store.list_stream_ids()
    print(f"EventStore: {store.path}")
    print(f"streams: {len(stream_ids)}")
    if not stream_ids:
        return 0

    for index, stream_id in enumerate(stream_ids, start=1):
        summary = summarize_stream(store, stream_id)
        if summary is None:
            continue
        print(
            f"  [{index:>3}] {summary.first_event_id:>6}..{summary.last_event_id:<6} "
            f"events={summary.event_count:<5} "
            f"observed={_iso(summary.observed_start)} "
            f"{stream_id}"
        )
    return 0


def _print_diff(
    store: EventStore,
    before_stream_id: str,
    after_stream_id: str,
    *,
    details: bool,
) -> int:
    try:
        diff = compare_streams(store, before_stream_id, after_stream_id)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(f"before: {before_stream_id}")
    print(f"after:  {after_stream_id}")
    print()
    print("SEMANTIC DIFF:")
    print("  timing/provenance metadata is excluded from semantic comparison")

    for item in diff.by_type:
        print(
            f"  {item.event_type.value:<34} "
            f"unchanged={item.unchanged_count:<4} "
            f"added={len(item.added):<3} "
            f"removed={len(item.removed):<3} "
            f"changed={len(item.changed):<3}"
        )

        if not details:
            continue

        for fact in item.added:
            print(f"    + {fact}")
        for fact in item.removed:
            print(f"    - {fact}")
        for key, before, after in item.changed:
            print(f"    ~ {key}")
            print(f"      before={before}")
            print(f"      after ={after}")

    print()
    print(
        "result: semantic changes observed"
        if diff.has_changes
        else "result: no semantic changes observed"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read-only inspection and comparison of EventStore streams."
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"EventStore SQLite path (default: {DEFAULT_DB_PATH})",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list", help="List persisted stream ids in append order.")

    show_parser = subparsers.add_parser("show", help="Summarize one stream.")
    show_parser.add_argument(
        "stream_id",
        nargs="?",
        help="Stream id. Defaults to the latest persisted stream.",
    )

    compare_parser = subparsers.add_parser(
        "compare",
        help="Compare two streams. With no ids, compare the latest two streams.",
    )
    compare_parser.add_argument("before_stream_id", nargs="?")
    compare_parser.add_argument("after_stream_id", nargs="?")
    compare_parser.add_argument(
        "--details",
        action="store_true",
        help="Print canonical added, removed, and changed facts.",
    )

    args = parser.parse_args(argv)

    if not args.db.is_file():
        print(f"Inspection failed: EventStore does not exist: {args.db}", file=sys.stderr)
        return 1

    try:
        store = EventStore(args.db)

        if args.command == "list":
            return _print_stream_list(store)

        if args.command == "show":
            stream_id = _resolve_stream(store, args.stream_id)
            return _print_stream_summary(store, stream_id)

        if args.command == "compare":
            if (args.before_stream_id is None) != (args.after_stream_id is None):
                parser.error("compare requires either zero stream ids or exactly two")

            before = _resolve_stream(
                store,
                args.before_stream_id,
                offset_from_latest=1,
            )
            after = _resolve_stream(store, args.after_stream_id)
            return _print_diff(
                store,
                before,
                after,
                details=args.details,
            )

    except (OSError, ValueError) as exc:
        print(f"Inspection failed: {exc}", file=sys.stderr)
        return 1

    raise RuntimeError(f"unsupported command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
