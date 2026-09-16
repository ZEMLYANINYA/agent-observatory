from __future__ import annotations

import time
from collections.abc import Callable, Iterable

from agent_observatory.endpoint.discovery import DEFAULT_PROFILES, discover_root_processes
from agent_observatory.endpoint.identity import (
    FileIdentity,
    build_process_identities,
    get_windows_file_identity,
    sha256_file,
)
from agent_observatory.endpoint.models import ParentRelation, ProcessSnapshot, RelationBasis
from agent_observatory.endpoint.process_tree import build_capture_parent_relations
from agent_observatory.endpoint.windows_capture import (
    WindowsCapture,
    attributable_tcp_connections,
    stable_processes,
)
from agent_observatory.endpoint.windows_snapshot import collect_application_snapshots
from agent_observatory.storage import EventStore, ObservationEvent, StoredEvent

from .endpoint_events import (
    application_discovery_event,
    executable_evidence_events,
    process_observed_event,
    process_relationship_event,
    tcp_connection_event,
)


PROCESS_TIME_BASIS = "process_before_inventory_end; stable_across_bracketing_capture"
RELATION_TIME_BASIS = "process_after_inventory_end; relation_derived_from_bracketing_capture"
TCP_TIME_BASIS = "network_inventory_end; owner_validated_as_stable_process_instance"
FILE_IDENTITY_TIME_BASIS = (
    "identity_build_window_end; exact_per_file_identity_timestamp_unavailable"
)


def _with_payload_fields(
    event: ObservationEvent,
    **fields: object,
) -> ObservationEvent:
    payload = dict(event.payload)
    payload.update(fields)
    return ObservationEvent(
        event_type=event.event_type,
        observed_at=event.observed_at,
        source=event.source,
        payload=payload,
        stream_id=event.stream_id,
        event_version=event.event_version,
    )


def _configured_application_names() -> tuple[str, ...]:
    return tuple(profile.name for profile in DEFAULT_PROFILES)


def _normalize_application_names(
    application_names: Iterable[str] | None,
) -> tuple[str, ...]:
    configured_names = _configured_application_names()
    configured_by_key = {name.casefold(): name for name in configured_names}
    raw_names = (
        tuple(application_names)
        if application_names is not None
        else configured_names
    )

    names: list[str] = []
    seen: set[str] = set()

    for name in raw_names:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("application_names must contain non-empty strings")
        requested = name.strip()
        key = requested.casefold()
        canonical = configured_by_key.get(key)
        if canonical is None:
            configured_text = ", ".join(configured_names)
            raise ValueError(
                f"unknown application target {requested!r}; configured targets: "
                f"{configured_text}"
            )
        if key in seen:
            continue
        seen.add(key)
        names.append(canonical)

    if not names:
        raise ValueError("at least one application name is required")

    return tuple(names)


def _selected_processes(
    capture: WindowsCapture,
    application_names: tuple[str, ...],
) -> tuple[ProcessSnapshot, ...]:
    stable = stable_processes(capture)
    snapshots = collect_application_snapshots(stable)
    allowed = {name.casefold() for name in application_names}

    by_pid: dict[int, ProcessSnapshot] = {}
    for snapshot in snapshots:
        if snapshot.application.profile.name.casefold() not in allowed:
            continue
        for process in snapshot.processes:
            by_pid.setdefault(process.pid, process)

    return tuple(by_pid[pid] for pid in sorted(by_pid))


def _parent_started_at(
    relation: ParentRelation,
    capture: WindowsCapture,
) -> float | None:
    if relation.basis is RelationBasis.CURRENT_SNAPSHOT:
        parent = next(
            (
                process
                for process in capture.processes_after
                if process.pid == relation.reported_parent_pid
            ),
            None,
        )
        return parent.started_at if parent is not None else None

    if relation.basis is RelationBasis.PARENT_OBSERVED_BEFORE_ONLY:
        parent = next(
            (
                process
                for process in capture.processes_before
                if process.pid == relation.reported_parent_pid
            ),
            None,
        )
        return parent.started_at if parent is not None else None

    return None


def windows_capture_event_batch(
    capture: WindowsCapture,
    *,
    source: str,
    stream_id: str,
    application_names: Iterable[str] | None = None,
    hash_executables: bool = True,
    file_hasher: Callable[[str], str | None] = sha256_file,
    file_identity_provider: Callable[[str], FileIdentity | None] = get_windows_file_identity,
    clock: Callable[[], float] = time.time,
) -> tuple[ObservationEvent, ...]:
    """Adapt one bracketed Windows capture into one deterministic evidence batch.

    Only processes belonging to the requested configured application trees are
    emitted. TCP records are emitted only when the capture attribution guard
    validated their owning process instance as stable across the before/after
    process inventories.

    The returned tuple is ready for one atomic ``EventStore.append_many`` call.
    ``event_id`` order reflects deterministic serialization order only and must
    not be interpreted as causal order.
    """

    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")
    if not isinstance(stream_id, str) or not stream_id.strip():
        raise ValueError("stream_id must be a non-empty string")

    names = _normalize_application_names(application_names)
    stable = stable_processes(capture)
    discovered = discover_root_processes(stable)
    selected = _selected_processes(capture, names)
    selected_by_pid = {process.pid: process for process in selected}
    selected_pids = set(selected_by_pid)

    events: list[ObservationEvent] = []

    discovery_observed_at = capture.process_after_interval.finished_at
    for application_name in names:
        events.append(
            _with_payload_fields(
                application_discovery_event(
                    application_name,
                    discovered,
                    observed_at=discovery_observed_at,
                    source=source,
                    stream_id=stream_id,
                ),
                observation_time_basis=(
                    "process_after_inventory_end; discovery_over_stable_process_set"
                ),
            )
        )

    process_observed_at = capture.process_before_interval.finished_at
    for process in selected:
        events.append(
            _with_payload_fields(
                process_observed_event(
                    process,
                    observed_at=process_observed_at,
                    source=source,
                    stream_id=stream_id,
                ),
                observation_time_basis=PROCESS_TIME_BASIS,
            )
        )

    relations = tuple(
        relation
        for relation in build_capture_parent_relations(
            capture.processes_before,
            capture.processes_after,
        )
        if relation.child_pid in selected_pids
    )
    for relation in sorted(relations, key=lambda item: item.child_pid):
        child = selected_by_pid[relation.child_pid]
        events.append(
            _with_payload_fields(
                process_relationship_event(
                    relation,
                    child_started_at=child.started_at,
                    parent_started_at=_parent_started_at(relation, capture),
                    observed_at=capture.process_after_interval.finished_at,
                    source=source,
                    stream_id=stream_id,
                ),
                observation_time_basis=RELATION_TIME_BASIS,
            )
        )

    identity_window_started_at = clock()
    identities = build_process_identities(
        selected,
        hash_executables=hash_executables,
        file_hasher=file_hasher,
        file_identity_provider=file_identity_provider,
        process_observed_at=process_observed_at,
        clock=clock,
    )
    identity_window_finished_at = clock()

    for identity in sorted(identities, key=lambda item: item.pid):
        file_identity, file_hash = executable_evidence_events(
            identity,
            file_identity_observed_at=identity_window_finished_at,
            file_identity_time_basis=FILE_IDENTITY_TIME_BASIS,
            hash_fallback_observed_at=identity_window_finished_at,
            source=source,
            stream_id=stream_id,
        )
        events.append(
            _with_payload_fields(
                file_identity,
                identity_build_window_started_at=identity_window_started_at,
                identity_build_window_finished_at=identity_window_finished_at,
            )
        )
        events.append(
            _with_payload_fields(
                file_hash,
                identity_build_window_started_at=identity_window_started_at,
                identity_build_window_finished_at=identity_window_finished_at,
            )
        )

    tcp_records = tuple(
        connection
        for connection in attributable_tcp_connections(capture)
        if connection.pid in selected_pids
    )
    for connection in sorted(
        tcp_records,
        key=lambda item: (
            item.pid,
            item.state.casefold(),
            item.local_address,
            item.local_port,
            item.remote_address,
            item.remote_port,
        ),
    ):
        process = selected_by_pid[connection.pid]
        events.append(
            _with_payload_fields(
                tcp_connection_event(
                    connection,
                    process_started_at=process.started_at,
                    observed_at=capture.network_interval.finished_at,
                    source=source,
                    stream_id=stream_id,
                ),
                observation_time_basis=TCP_TIME_BASIS,
            )
        )

    return tuple(events)


def append_windows_capture(
    store: EventStore,
    capture: WindowsCapture,
    *,
    source: str,
    stream_id: str,
    application_names: Iterable[str] | None = None,
    hash_executables: bool = True,
    file_hasher: Callable[[str], str | None] = sha256_file,
    file_identity_provider: Callable[[str], FileIdentity | None] = get_windows_file_identity,
    clock: Callable[[], float] = time.time,
) -> tuple[StoredEvent, ...]:
    """Adapt and atomically append one Windows capture to an EventStore."""

    return store.append_many(
        windows_capture_event_batch(
            capture,
            source=source,
            stream_id=stream_id,
            application_names=application_names,
            hash_executables=hash_executables,
            file_hasher=file_hasher,
            file_identity_provider=file_identity_provider,
            clock=clock,
        )
    )
