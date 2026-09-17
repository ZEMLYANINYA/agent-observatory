from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class EventType(str, Enum):
    PROCESS_OBSERVED = "PROCESS_OBSERVED"
    PROCESS_RELATIONSHIP_OBSERVED = "PROCESS_RELATIONSHIP_OBSERVED"
    FILE_IDENTITY_OBSERVED = "FILE_IDENTITY_OBSERVED"
    FILE_HASH_OBSERVED = "FILE_HASH_OBSERVED"
    TCP_CONNECTION_OBSERVED = "TCP_CONNECTION_OBSERVED"
    TCP_LISTENER_OBSERVED = "TCP_LISTENER_OBSERVED"
    WINDOWS_PROCESS_PRINCIPAL_OBSERVED = "WINDOWS_PROCESS_PRINCIPAL_OBSERVED"
    WINDOWS_SERVICE_OBSERVED = "WINDOWS_SERVICE_OBSERVED"
    WINDOWS_FIREWALL_PROFILE_OBSERVED = "WINDOWS_FIREWALL_PROFILE_OBSERVED"
    WINDOWS_NETWORK_PROFILE_OBSERVED = "WINDOWS_NETWORK_PROFILE_OBSERVED"
    WINDOWS_FIREWALL_RULE_OBSERVED = "WINDOWS_FIREWALL_RULE_OBSERVED"
    DOCKER_PORT_PUBLISHED = "DOCKER_PORT_PUBLISHED"
    SERVICE_EXPOSURE_CAPTURE_MANIFEST = "SERVICE_EXPOSURE_CAPTURE_MANIFEST"
    APPLICATION_DISCOVERY_OBSERVED = "APPLICATION_DISCOVERY_OBSERVED"
    OPERATOR_MARKER_OBSERVED = "OPERATOR_MARKER_OBSERVED"


@dataclass(frozen=True, slots=True)
class ObservationEvent:
    """One source-attributed fact ready to be appended to the EventStore."""

    event_type: EventType
    observed_at: float
    source: str
    payload: Mapping[str, object]
    stream_id: str | None = None
    event_version: int = 1


@dataclass(frozen=True, slots=True)
class StoredEvent:
    """One immutable event as persisted by the local EventStore."""

    event_id: int
    event_type: EventType
    event_version: int
    observed_at: float
    recorded_at: float
    source: str
    stream_id: str | None
    payload: dict[str, object]
