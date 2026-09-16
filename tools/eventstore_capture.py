from __future__ import annotations

import argparse
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from agent_observatory.endpoint.windows_capture import (
    WindowsCapture,
    collect_windows_capture,
)
from agent_observatory.evidence import append_windows_capture
from agent_observatory.storage import EventStore, EventType, StoredEvent


DEFAULT_DB_PATH = Path(".local") / "agent-observatory.sqlite3"
DEFAULT_SOURCE = "windows-live-capture"


def _stream_id(application_names: Iterable[str] | None) -> str:
    names = tuple(application_names or ())
    target = "all" if not names else "+".join(name.casefold() for name in names)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"windows-capture:{target}:{timestamp}:{uuid4().hex[:8]}"


def _application_names(targets: Iterable[str]) -> tuple[str, ...] | None:
    values = tuple(target.strip() for target in targets if target.strip())
    if not values:
        return None
    if len(values) == 1 and values[0].casefold() == "all":
        return None
    if any(value.casefold() == "all" for value in values):
        raise ValueError("'all' cannot be combined with named application targets")
    return values


def capture_into_store(
    store: EventStore,
    *,
    application_names: Iterable[str] | None,
    source: str,
    stream_id: str,
    hash_executables: bool = True,
    capture_provider: Callable[[], WindowsCapture] = collect_windows_capture,
) -> tuple[StoredEvent, ...]:
    if store.stream_exists(stream_id):
        raise ValueError(f"stream already exists: {stream_id}")

    capture = capture_provider()
    return append_windows_capture(
        store,
        capture,
        source=source,
        stream_id=stream_id,
        application_names=application_names,
        hash_executables=hash_executables,
    )


def _print_summary(
    store: EventStore,
    events: tuple[StoredEvent, ...],
    *,
    stream_id: str,
) -> None:
    counts = Counter(event.event_type for event in events)

    print(f"EventStore: {store.path}")
    print(f"journal_mode: {store.journal_mode()}")
    print(f"stream_id: {stream_id}")
    print(f"events_appended: {len(events)}")
    if events:
        print(f"event_id_range: {events[0].event_id}..{events[-1].event_id}")
    else:
        print("event_id_range: none")

    print()
    print("DISCOVERY:")
    discovery = tuple(
        event
        for event in events
        if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED
    )
    if not discovery:
        print("  none")
    else:
        for event in discovery:
            print(
                "  "
                f"{event.payload.get('application')}: "
                f"{event.payload.get('outcome')} "
                f"candidates={event.payload.get('candidate_count')}"
            )

    print()
    print("EVENT COUNTS:")
    for event_type in EventType:
        count = counts.get(event_type, 0)
        if count:
            print(f"  {event_type.value:<34} {count}")


def _print_timeline(events: tuple[StoredEvent, ...]) -> None:
    print()
    print("OBSERVED TIMELINE:")
    print("  sorted by observed_at; event_id is append order")
    if not events:
        print("  none")
        return

    ordered = sorted(
        events,
        key=lambda event: (event.observed_at, event.event_id),
    )

    for event in ordered:
        process = event.payload.get("process")
        process_text = ""
        if isinstance(process, dict) and "pid" in process:
            process_text = f" pid={process.get('pid')}"
        elif "pid" in event.payload:
            process_text = f" pid={event.payload.get('pid')}"

        detail = ""
        if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED:
            detail = (
                f" app={event.payload.get('application')}"
                f" outcome={event.payload.get('outcome')}"
            )
        elif event.event_type is EventType.TCP_CONNECTION_OBSERVED:
            detail = (
                f" state={event.payload.get('state')}"
                f" remote={event.payload.get('remote_address')}:"
                f"{event.payload.get('remote_port')}"
            )
        elif event.event_type is EventType.FILE_HASH_OBSERVED:
            detail = f" state={event.payload.get('state')}"
        elif event.event_type is EventType.PROCESS_RELATIONSHIP_OBSERVED:
            detail = (
                f" state={event.payload.get('state')}"
                f" basis={event.payload.get('basis')}"
            )

        observed = datetime.fromtimestamp(
            event.observed_at,
            timezone.utc,
        ).isoformat()
        print(
            f"  {event.event_id:>6}  {observed}  "
            f"{event.event_type.value}{process_text}{detail}"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Capture live Windows endpoint evidence and append it atomically "
            "to the local SQLite/WAL EventStore."
        )
    )
    parser.add_argument(
        "targets",
        nargs="*",
        default=("all",),
        help=(
            "Application profile names to retain, or 'all'. "
            "Examples: Gemini | Claude Codex | all"
        ),
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"EventStore SQLite path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"Evidence source label (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--stream-id",
        help="Explicit stream id. A unique id is generated when omitted.",
    )
    parser.add_argument(
        "--no-hash",
        action="store_true",
        help="Do not hash executable files for this capture.",
    )
    parser.add_argument(
        "--timeline",
        action="store_true",
        help=(
            "Print persisted events for this capture sorted by observation time; "
            "event ids still show append order."
        ),
    )
    args = parser.parse_args(argv)

    try:
        application_names = _application_names(args.targets)
    except ValueError as exc:
        parser.error(str(exc))

    stream_id = args.stream_id or _stream_id(application_names)

    try:
        store = EventStore(args.db)
        appended = capture_into_store(
            store,
            application_names=application_names,
            source=args.source,
            stream_id=stream_id,
            hash_executables=not args.no_hash,
        )
    except Exception as exc:
        print(f"Capture failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    persisted = store.read_events(stream_id=stream_id)
    if tuple(event.event_id for event in persisted) != tuple(
        event.event_id for event in appended
    ):
        print(
            "Capture failed: persisted stream does not match appended event ids",
            file=sys.stderr,
        )
        return 2

    _print_summary(store, persisted, stream_id=stream_id)
    if args.timeline:
        _print_timeline(persisted)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
