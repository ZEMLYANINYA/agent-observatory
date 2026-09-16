from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass

from agent_observatory.storage import EventStore, EventType, StoredEvent


@dataclass(frozen=True, slots=True)
class StreamSummary:
    stream_id: str
    event_count: int
    first_event_id: int
    last_event_id: int
    observed_start: float
    observed_end: float
    event_counts: tuple[tuple[EventType, int], ...]
    sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EventTypeDiff:
    event_type: EventType
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[tuple[str, str, str], ...]
    unchanged_count: int

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)


@dataclass(frozen=True, slots=True)
class StreamDiff:
    before_stream_id: str
    after_stream_id: str
    by_type: tuple[EventTypeDiff, ...]

    @property
    def has_changes(self) -> bool:
        return any(item.has_changes for item in self.by_type)


def summarize_stream(
    store: EventStore,
    stream_id: str,
) -> StreamSummary | None:
    events = store.read_events(stream_id=stream_id)
    if not events:
        return None

    counts = Counter(event.event_type for event in events)
    return StreamSummary(
        stream_id=stream_id,
        event_count=len(events),
        first_event_id=min(event.event_id for event in events),
        last_event_id=max(event.event_id for event in events),
        observed_start=min(event.observed_at for event in events),
        observed_end=max(event.observed_at for event in events),
        event_counts=tuple(
            (event_type, counts[event_type])
            for event_type in EventType
            if counts[event_type]
        ),
        sources=tuple(sorted({event.source for event in events})),
    )


def _semantic_payload(event: StoredEvent) -> dict[str, object]:
    payload = event.payload

    if event.event_type is EventType.PROCESS_OBSERVED:
        fields = (
            "pid",
            "ppid",
            "started_at",
            "name",
            "executable_path",
            "command_line_sha256",
        )
    elif event.event_type is EventType.PROCESS_RELATIONSHIP_OBSERVED:
        fields = (
            "child",
            "reported_parent_pid",
            "parent",
            "state",
            "basis",
            "reason",
        )
    elif event.event_type is EventType.FILE_IDENTITY_OBSERVED:
        fields = (
            "process",
            "path",
            "state",
            "volume_serial",
            "file_id",
        )
    elif event.event_type is EventType.FILE_HASH_OBSERVED:
        fields = (
            "process",
            "path",
            "file_identity",
            "sha256",
            "state",
        )
    elif event.event_type is EventType.TCP_CONNECTION_OBSERVED:
        fields = (
            "process",
            "state",
            "local_address",
            "local_port",
            "remote_address",
            "remote_port",
            "attribution_basis",
        )
    elif event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED:
        fields = (
            "application",
            "outcome",
            "candidate_count",
            "candidates",
        )
    elif event.event_type is EventType.OPERATOR_MARKER_OBSERVED:
        fields = ("marker", "details")
    else:
        return dict(payload)

    return {field: payload.get(field) for field in fields}


def _canonical_fact(event: StoredEvent) -> str:
    return json.dumps(
        {
            "event_version": event.event_version,
            "payload": _semantic_payload(event),
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _process_ref_key(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    if "pid" not in value or "started_at" not in value:
        return None
    return f"{value.get('pid')}@{value.get('started_at')}"


def _entity_key(event: StoredEvent) -> str | None:
    payload = event.payload

    if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED:
        application = payload.get("application")
        return f"application:{str(application).casefold()}"

    if event.event_type is EventType.PROCESS_OBSERVED:
        if "pid" in payload and "started_at" in payload:
            return f"process:{payload.get('pid')}@{payload.get('started_at')}"
        return None

    if event.event_type is EventType.PROCESS_RELATIONSHIP_OBSERVED:
        child = _process_ref_key(payload.get("child"))
        return f"relationship:{child}" if child is not None else None

    if event.event_type in (
        EventType.FILE_IDENTITY_OBSERVED,
        EventType.FILE_HASH_OBSERVED,
    ):
        process = _process_ref_key(payload.get("process"))
        if process is None:
            return None
        return f"file:{process}:{payload.get('path')}"

    return None


def _diff_event_type(
    event_type: EventType,
    before_events: tuple[StoredEvent, ...],
    after_events: tuple[StoredEvent, ...],
) -> EventTypeDiff:
    before_facts = Counter(_canonical_fact(event) for event in before_events)
    after_facts = Counter(_canonical_fact(event) for event in after_events)

    unchanged_count = sum((before_facts & after_facts).values())
    removed_counter = before_facts - after_facts
    added_counter = after_facts - before_facts

    before_by_key: dict[str, list[str]] = defaultdict(list)
    after_by_key: dict[str, list[str]] = defaultdict(list)

    for event in before_events:
        key = _entity_key(event)
        if key is not None:
            before_by_key[key].append(_canonical_fact(event))
    for event in after_events:
        key = _entity_key(event)
        if key is not None:
            after_by_key[key].append(_canonical_fact(event))

    changed: list[tuple[str, str, str]] = []
    for key in sorted(set(before_by_key) & set(after_by_key)):
        before_values = before_by_key[key]
        after_values = after_by_key[key]
        if len(before_values) != 1 or len(after_values) != 1:
            continue
        before_value = before_values[0]
        after_value = after_values[0]
        if before_value == after_value:
            continue
        if removed_counter[before_value] <= 0 or added_counter[after_value] <= 0:
            continue

        removed_counter[before_value] -= 1
        added_counter[after_value] -= 1
        changed.append((key, before_value, after_value))

    removed = tuple(
        fact
        for fact in sorted(removed_counter)
        for _ in range(removed_counter[fact])
        if removed_counter[fact] > 0
    )
    added = tuple(
        fact
        for fact in sorted(added_counter)
        for _ in range(added_counter[fact])
        if added_counter[fact] > 0
    )

    return EventTypeDiff(
        event_type=event_type,
        added=added,
        removed=removed,
        changed=tuple(changed),
        unchanged_count=unchanged_count,
    )


def compare_streams(
    store: EventStore,
    before_stream_id: str,
    after_stream_id: str,
) -> StreamDiff:
    before = store.read_events(stream_id=before_stream_id)
    after = store.read_events(stream_id=after_stream_id)

    if not before:
        raise KeyError(f"stream not found: {before_stream_id}")
    if not after:
        raise KeyError(f"stream not found: {after_stream_id}")

    by_type: list[EventTypeDiff] = []
    for event_type in EventType:
        before_events = tuple(
            event for event in before if event.event_type is event_type
        )
        after_events = tuple(
            event for event in after if event.event_type is event_type
        )
        if not before_events and not after_events:
            continue
        by_type.append(
            _diff_event_type(event_type, before_events, after_events)
        )

    return StreamDiff(
        before_stream_id=before_stream_id,
        after_stream_id=after_stream_id,
        by_type=tuple(by_type),
    )
