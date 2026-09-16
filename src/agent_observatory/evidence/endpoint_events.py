from __future__ import annotations

from enum import Enum
from typing import Iterable, Mapping

from agent_observatory.endpoint.application_models import DiscoveredApplication
from agent_observatory.endpoint.identity import (
    ProcessInstanceIdentity,
    hash_command_line,
)
from agent_observatory.endpoint.models import ParentRelation, ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.storage import EventType, ObservationEvent


class ApplicationDiscoveryOutcome(str, Enum):
    ABSENT = "absent"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


def _event(
    event_type: EventType,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None,
    payload: Mapping[str, object],
) -> ObservationEvent:
    return ObservationEvent(
        event_type=event_type,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload=dict(payload),
    )


def _process_ref(pid: int, started_at: float) -> dict[str, object]:
    return {
        "pid": pid,
        "started_at": started_at,
    }


def process_observed_event(
    process: ProcessSnapshot,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    """Adapt one process observation without persisting its raw command line."""

    return _event(
        EventType.PROCESS_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "pid": process.pid,
            "ppid": process.ppid,
            "started_at": process.started_at,
            "name": process.name,
            "executable_path": process.executable_path,
            "command_line_sha256": hash_command_line(process.command_line),
        },
    )


def process_relationship_event(
    relation: ParentRelation,
    *,
    child_started_at: float,
    parent_started_at: float | None,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    """Persist relationship evidence with process-instance timing, not PID alone."""

    return _event(
        EventType.PROCESS_RELATIONSHIP_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "child": _process_ref(relation.child_pid, child_started_at),
            "reported_parent_pid": relation.reported_parent_pid,
            "parent": (
                _process_ref(relation.reported_parent_pid, parent_started_at)
                if parent_started_at is not None
                else None
            ),
            "state": relation.state.value,
            "basis": relation.basis.value,
            "reason": relation.reason,
        },
    )


def tcp_connection_event(
    connection: TcpConnection,
    *,
    process_started_at: float,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
    attribution_basis: str = "stable_process_instance",
) -> ObservationEvent:
    """Adapt one TCP record while preserving the owning process instance."""

    return _event(
        EventType.TCP_CONNECTION_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "process": _process_ref(connection.pid, process_started_at),
            "state": connection.state,
            "local_address": connection.local_address,
            "local_port": connection.local_port,
            "remote_address": connection.remote_address,
            "remote_port": connection.remote_port,
            "attribution_basis": attribution_basis,
        },
    )


def file_identity_event(
    identity: ProcessInstanceIdentity,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
    observation_time_basis: str,
) -> ObservationEvent:
    """
    Adapt filesystem identity evidence.

    ``FileIdentity`` currently has no independent timestamp, so the caller must
    provide an explicit observation anchor and describe its basis. This prevents
    the adapter from manufacturing timestamp precision that the endpoint model
    does not contain.
    """

    file_identity = identity.executable.file_identity
    payload: dict[str, object] = {
        "process": _process_ref(identity.pid, identity.started_at),
        "path": identity.executable.path,
        "state": "observed" if file_identity is not None else "unavailable",
        "observation_time_basis": observation_time_basis,
        "volume_serial": None,
        "file_id": None,
    }

    if file_identity is not None:
        payload["volume_serial"] = file_identity.volume_serial
        payload["file_id"] = file_identity.file_id

    return _event(
        EventType.FILE_IDENTITY_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload=payload,
    )


def file_hash_event(
    identity: ProcessInstanceIdentity,
    *,
    fallback_observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    """Adapt executable hash evidence, preferring its own observation timestamp."""

    executable = identity.executable
    observation = executable.hash_observation
    file_identity = executable.file_identity

    if observation.observed_at is not None:
        observed_at = observation.observed_at
        time_basis = "hash_observation"
    else:
        observed_at = fallback_observed_at
        time_basis = "caller_fallback"

    return _event(
        EventType.FILE_HASH_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "process": _process_ref(identity.pid, identity.started_at),
            "path": executable.path,
            "file_identity": (
                {
                    "volume_serial": file_identity.volume_serial,
                    "file_id": file_identity.file_id,
                }
                if file_identity is not None
                else None
            ),
            "sha256": observation.sha256,
            "state": observation.state.value,
            "hash_gap_ms": observation.hash_gap_ms,
            "observation_time_basis": time_basis,
        },
    )


def executable_evidence_events(
    identity: ProcessInstanceIdentity,
    *,
    file_identity_observed_at: float,
    file_identity_time_basis: str,
    hash_fallback_observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> tuple[ObservationEvent, ObservationEvent]:
    """Return file-identity and file-hash events for one process instance."""

    return (
        file_identity_event(
            identity,
            observed_at=file_identity_observed_at,
            source=source,
            stream_id=stream_id,
            observation_time_basis=file_identity_time_basis,
        ),
        file_hash_event(
            identity,
            fallback_observed_at=hash_fallback_observed_at,
            source=source,
            stream_id=stream_id,
        ),
    )


def application_discovery_event(
    application_name: str,
    candidates: Iterable[DiscoveredApplication],
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    """Represent absent, unique, and ambiguous discovery outcomes explicitly."""

    selected = tuple(
        candidate
        for candidate in candidates
        if candidate.profile.name.casefold() == application_name.casefold()
    )

    if not selected:
        outcome = ApplicationDiscoveryOutcome.ABSENT
    elif len(selected) == 1:
        outcome = ApplicationDiscoveryOutcome.UNIQUE
    else:
        outcome = ApplicationDiscoveryOutcome.AMBIGUOUS

    return _event(
        EventType.APPLICATION_DISCOVERY_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "application": application_name,
            "outcome": outcome.value,
            "candidate_count": len(selected),
            "candidates": [
                {
                    "pid": candidate.root_process.pid,
                    "ppid": candidate.root_process.ppid,
                    "started_at": candidate.root_process.started_at,
                    "name": candidate.root_process.name,
                    "executable_path": candidate.root_process.executable_path,
                }
                for candidate in selected
            ],
        },
    )


def operator_marker_event(
    marker: str,
    *,
    observed_at: float,
    stream_id: str,
    source: str = "operator",
    details: Mapping[str, object] | None = None,
) -> ObservationEvent:
    """Persist a source-attributed operator marker without assigning causality."""

    if not isinstance(marker, str) or not marker.strip():
        raise ValueError("marker must be a non-empty string")

    return _event(
        EventType.OPERATOR_MARKER_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "marker": marker,
            "details": dict(details or {}),
        },
    )
