from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from agent_observatory.storage import EventStore, EventType, StoredEvent

from .models import (
    EvidenceGraph,
    EvidenceRef,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    GraphProjectionNote,
)


class EvidenceGraphProjectionError(RuntimeError):
    """Raised when one stream cannot be projected without inventing identity."""


@dataclass(slots=True)
class _NodeBuilder:
    node_type: GraphNodeType
    attributes: dict[str, object]
    evidence: dict[int, EvidenceRef] = field(default_factory=dict)


def _ref(event: StoredEvent) -> EvidenceRef:
    return EvidenceRef(
        event_id=event.event_id,
        event_type=event.event_type,
        observed_at=event.observed_at,
        source=event.source,
        stream_id=event.stream_id,
    )


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) else None


def _integer(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _process_ref(value: object) -> tuple[int, float] | None:
    if not isinstance(value, dict):
        return None
    pid = _integer(value.get("pid"))
    started_at = _finite_number(value.get("started_at"))
    if pid is None or pid <= 0 or started_at is None:
        return None
    return pid, started_at


def _process_node_id(pid: int, started_at: float) -> str:
    return f"process:{pid}@{repr(float(started_at))}"


def _application_node_id(name: str) -> str:
    return f"application:{name.casefold()}"


def _file_node_id(volume_serial: int, file_id: int) -> str:
    return f"file:{volume_serial}:{file_id}"


def _remote_node_id(protocol: str, address: str, port: int) -> str:
    return f"remote:{protocol.casefold()}:[{address}]:{port}"


def _edge_id(
    event: StoredEvent,
    edge_type: GraphEdgeType,
    sequence: int = 0,
) -> str:
    return f"event:{event.event_id}:{edge_type.value}:{sequence}"


def _add_note(
    notes: list[GraphProjectionNote],
    event: StoredEvent,
    reason: str,
) -> None:
    notes.append(
        GraphProjectionNote(
            event_id=event.event_id,
            event_type=event.event_type,
            reason=reason,
        )
    )


def _ensure_node(
    builders: dict[str, _NodeBuilder],
    notes: list[GraphProjectionNote],
    event: StoredEvent,
    *,
    node_id: str,
    node_type: GraphNodeType,
    attributes: Mapping[str, object],
) -> None:
    ref = _ref(event)
    builder = builders.get(node_id)
    if builder is None:
        builders[node_id] = _NodeBuilder(
            node_type=node_type,
            attributes=dict(attributes),
            evidence={event.event_id: ref},
        )
        return

    if builder.node_type is not node_type:
        raise EvidenceGraphProjectionError(
            f"node id {node_id!r} maps to both "
            f"{builder.node_type.value} and {node_type.value}"
        )

    for key, value in attributes.items():
        if key not in builder.attributes or builder.attributes[key] is None:
            builder.attributes[key] = value
            continue
        if value is None or builder.attributes[key] == value:
            continue
        _add_note(notes, event, f"node_attribute_conflict:{node_id}:{key}")

    builder.evidence[event.event_id] = ref


def _ensure_process_node(
    builders: dict[str, _NodeBuilder],
    notes: list[GraphProjectionNote],
    event: StoredEvent,
    process_ref: tuple[int, float],
    *,
    name: object = None,
    executable_path: object = None,
) -> str:
    pid, started_at = process_ref
    node_id = _process_node_id(pid, started_at)
    attributes: dict[str, object] = {
        "pid": pid,
        "started_at": started_at,
    }
    if isinstance(name, str):
        attributes["name"] = name
    if executable_path is None or isinstance(executable_path, str):
        attributes["executable_path"] = executable_path

    _ensure_node(
        builders,
        notes,
        event,
        node_id=node_id,
        node_type=GraphNodeType.PROCESS_INSTANCE,
        attributes=attributes,
    )
    return node_id


def _project_application_discovery(
    event: StoredEvent,
    builders: dict[str, _NodeBuilder],
    edges: list[GraphEdge],
    notes: list[GraphProjectionNote],
) -> None:
    application = event.payload.get("application")
    if not isinstance(application, str) or not application.strip():
        _add_note(notes, event, "application_identity_invalid")
        return

    application_node_id = _application_node_id(application)
    _ensure_node(
        builders,
        notes,
        event,
        node_id=application_node_id,
        node_type=GraphNodeType.APPLICATION,
        attributes={"name": application},
    )

    candidates = event.payload.get("candidates")
    if not isinstance(candidates, list):
        _add_note(notes, event, "discovery_candidates_invalid")
        return

    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            _add_note(notes, event, f"discovery_candidate_invalid:{index}")
            continue
        process_ref = _process_ref(candidate)
        if process_ref is None:
            _add_note(notes, event, f"discovery_candidate_identity_invalid:{index}")
            continue
        process_node_id = _ensure_process_node(
            builders,
            notes,
            event,
            process_ref,
            name=candidate.get("name"),
            executable_path=candidate.get("executable_path"),
        )
        edges.append(
            GraphEdge(
                edge_id=_edge_id(event, GraphEdgeType.DISCOVERED_AS, index),
                edge_type=GraphEdgeType.DISCOVERED_AS,
                source_node_id=application_node_id,
                target_node_id=process_node_id,
                attributes={
                    "outcome": event.payload.get("outcome"),
                    "candidate_count": event.payload.get("candidate_count"),
                },
                evidence=(_ref(event),),
            )
        )


def _project_process(
    event: StoredEvent,
    builders: dict[str, _NodeBuilder],
    notes: list[GraphProjectionNote],
) -> None:
    process_ref = _process_ref(event.payload)
    if process_ref is None:
        _add_note(notes, event, "process_identity_invalid")
        return
    _ensure_process_node(
        builders,
        notes,
        event,
        process_ref,
        name=event.payload.get("name"),
        executable_path=event.payload.get("executable_path"),
    )


def _project_relationship(
    event: StoredEvent,
    builders: dict[str, _NodeBuilder],
    edges: list[GraphEdge],
    notes: list[GraphProjectionNote],
) -> None:
    child_ref = _process_ref(event.payload.get("child"))
    if child_ref is None:
        _add_note(notes, event, "relationship_child_identity_invalid")
        return
    child_node_id = _ensure_process_node(
        builders,
        notes,
        event,
        child_ref,
    )

    parent_ref = _process_ref(event.payload.get("parent"))
    parent_node_id: str | None = None
    if parent_ref is not None:
        parent_node_id = _ensure_process_node(
            builders,
            notes,
            event,
            parent_ref,
        )

    state = event.payload.get("state")
    if state != "valid":
        _add_note(notes, event, f"relationship_not_valid:{state}")
        return
    if parent_node_id is None:
        _add_note(notes, event, "relationship_parent_identity_unavailable")
        return

    edges.append(
        GraphEdge(
            edge_id=_edge_id(event, GraphEdgeType.PARENT_OF),
            edge_type=GraphEdgeType.PARENT_OF,
            source_node_id=parent_node_id,
            target_node_id=child_node_id,
            attributes={
                "state": state,
                "basis": event.payload.get("basis"),
                "reason": event.payload.get("reason"),
                "reported_parent_pid": event.payload.get("reported_parent_pid"),
            },
            evidence=(_ref(event),),
        )
    )


def _project_file_identity(
    event: StoredEvent,
    builders: dict[str, _NodeBuilder],
    edges: list[GraphEdge],
    notes: list[GraphProjectionNote],
) -> None:
    process_ref = _process_ref(event.payload.get("process"))
    if process_ref is None:
        _add_note(notes, event, "file_identity_process_invalid")
        return
    process_node_id = _ensure_process_node(builders, notes, event, process_ref)

    volume_serial = _integer(event.payload.get("volume_serial"))
    file_id = _integer(event.payload.get("file_id"))
    if (
        event.payload.get("state") != "observed"
        or volume_serial is None
        or file_id is None
    ):
        _add_note(notes, event, "file_identity_unavailable")
        return

    file_node_id = _file_node_id(volume_serial, file_id)
    _ensure_node(
        builders,
        notes,
        event,
        node_id=file_node_id,
        node_type=GraphNodeType.FILE_IDENTITY,
        attributes={
            "volume_serial": volume_serial,
            "file_id": file_id,
        },
    )
    edges.append(
        GraphEdge(
            edge_id=_edge_id(event, GraphEdgeType.EXECUTED_FROM),
            edge_type=GraphEdgeType.EXECUTED_FROM,
            source_node_id=process_node_id,
            target_node_id=file_node_id,
            attributes={
                "path": event.payload.get("path"),
                "state": event.payload.get("state"),
                "observation_time_basis": event.payload.get("observation_time_basis"),
            },
            evidence=(_ref(event),),
        )
    )


def _remote_endpoint(payload: Mapping[str, object]) -> tuple[str, int] | None:
    address = payload.get("remote_address")
    port = _integer(payload.get("remote_port"))
    if not isinstance(address, str) or not address.strip() or port is None or port <= 0:
        return None
    if address.casefold() in {"0.0.0.0", "::", "::0", "*"}:
        return None
    return address, port


def _project_tcp(
    event: StoredEvent,
    builders: dict[str, _NodeBuilder],
    edges: list[GraphEdge],
    notes: list[GraphProjectionNote],
) -> None:
    process_ref = _process_ref(event.payload.get("process"))
    if process_ref is None:
        _add_note(notes, event, "tcp_process_identity_invalid")
        return
    process_node_id = _ensure_process_node(builders, notes, event, process_ref)

    remote = _remote_endpoint(event.payload)
    if remote is None:
        _add_note(notes, event, "tcp_remote_endpoint_unavailable")
        return

    address, port = remote
    remote_node_id = _remote_node_id("tcp", address, port)
    _ensure_node(
        builders,
        notes,
        event,
        node_id=remote_node_id,
        node_type=GraphNodeType.REMOTE_ENDPOINT,
        attributes={
            "protocol": "tcp",
            "address": address,
            "port": port,
        },
    )
    edges.append(
        GraphEdge(
            edge_id=_edge_id(event, GraphEdgeType.OBSERVED_TCP_TO),
            edge_type=GraphEdgeType.OBSERVED_TCP_TO,
            source_node_id=process_node_id,
            target_node_id=remote_node_id,
            attributes={
                "state": event.payload.get("state"),
                "local_address": event.payload.get("local_address"),
                "local_port": event.payload.get("local_port"),
                "attribution_basis": event.payload.get("attribution_basis"),
            },
            evidence=(_ref(event),),
        )
    )


def project_events(
    events: Iterable[StoredEvent],
    *,
    stream_id: str | None = None,
) -> EvidenceGraph:
    """Project one EventStore stream into a deterministic evidence graph.

    Projection never changes EventStore and never treats event ordering as
    causality. Unsupported or intentionally omitted semantics remain explicit
    in ``projection_notes``.
    """

    ordered = tuple(sorted(events, key=lambda event: event.event_id))
    if not ordered:
        raise ValueError("at least one stored event is required")

    event_ids = [event.event_id for event in ordered]
    if len(set(event_ids)) != len(event_ids):
        raise ValueError("event ids must be unique")

    observed_streams = {event.stream_id for event in ordered}
    if None in observed_streams:
        raise EvidenceGraphProjectionError(
            "Evidence Graph v1 requires events with an explicit stream_id"
        )
    if len(observed_streams) != 1:
        raise EvidenceGraphProjectionError(
            "Evidence Graph v1 can project exactly one stream at a time"
        )

    actual_stream_id = next(iter(observed_streams))
    assert actual_stream_id is not None
    if stream_id is not None and stream_id != actual_stream_id:
        raise EvidenceGraphProjectionError(
            f"requested stream {stream_id!r} does not match event stream "
            f"{actual_stream_id!r}"
        )

    builders: dict[str, _NodeBuilder] = {}
    edges: list[GraphEdge] = []
    notes: list[GraphProjectionNote] = []

    for event in ordered:
        if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED:
            _project_application_discovery(event, builders, edges, notes)
        elif event.event_type is EventType.PROCESS_OBSERVED:
            _project_process(event, builders, notes)
        elif event.event_type is EventType.PROCESS_RELATIONSHIP_OBSERVED:
            _project_relationship(event, builders, edges, notes)
        elif event.event_type is EventType.FILE_IDENTITY_OBSERVED:
            _project_file_identity(event, builders, edges, notes)
        elif event.event_type is EventType.TCP_CONNECTION_OBSERVED:
            _project_tcp(event, builders, edges, notes)
        elif event.event_type is EventType.FILE_HASH_OBSERVED:
            _add_note(notes, event, "file_hash_not_projected_v1")
        elif event.event_type is EventType.OPERATOR_MARKER_OBSERVED:
            _add_note(notes, event, "operator_marker_not_projected_v1")
        else:
            _add_note(notes, event, "event_type_not_projected_v1")

    nodes = tuple(
        GraphNode(
            node_id=node_id,
            node_type=builder.node_type,
            attributes=dict(builder.attributes),
            evidence=tuple(
                builder.evidence[event_id]
                for event_id in sorted(builder.evidence)
            ),
        )
        for node_id, builder in sorted(
            builders.items(),
            key=lambda item: (item[1].node_type.value, item[0]),
        )
    )

    return EvidenceGraph(
        stream_id=actual_stream_id,
        nodes=nodes,
        edges=tuple(sorted(edges, key=lambda edge: edge.edge_id)),
        projection_notes=tuple(
            sorted(notes, key=lambda note: (note.event_id, note.reason))
        ),
    )


def project_stream(store: EventStore, stream_id: str) -> EvidenceGraph:
    events = store.read_events(stream_id=stream_id)
    if not events:
        raise KeyError(f"stream not found: {stream_id}")
    return project_events(events, stream_id=stream_id)
