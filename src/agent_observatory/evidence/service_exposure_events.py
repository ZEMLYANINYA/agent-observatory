from __future__ import annotations

from agent_observatory.endpoint.service_exposure import (
    DockerPublishedPort,
    HostTcpListener,
)
from agent_observatory.storage import EventType, ObservationEvent


def tcp_listener_event(
    listener: HostTcpListener,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
    observation_basis: str = "windows_get_nettcpconnection_snapshot",
) -> ObservationEvent:
    """Adapt one point-in-time listener without upgrading PID to process identity."""

    if not isinstance(observation_basis, str) or not observation_basis.strip():
        raise ValueError("observation_basis must be a non-empty string")

    return ObservationEvent(
        event_type=EventType.TCP_LISTENER_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "protocol": listener.protocol,
            "owner_pid": listener.owner_pid,
            "owner_identity_basis": listener.owner_identity_basis,
            "state": listener.state,
            "local_address": listener.local_address,
            "local_port": listener.local_port,
            "bind_scope": listener.bind_scope.value,
            "observation_basis": observation_basis,
        },
    )


def docker_published_port_event(
    published: DockerPublishedPort,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    """Adapt one Docker host-port publication without inferring reachability."""

    return ObservationEvent(
        event_type=EventType.DOCKER_PORT_PUBLISHED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "container": {
                "id": published.container_id,
                "name": published.container_name,
                "image": published.image,
            },
            "protocol": published.protocol,
            "container_port": published.container_port,
            "host_address": published.host_address,
            "host_port": published.host_port,
            "bind_scope": published.bind_scope.value,
            "observation_basis": published.observation_basis,
        },
    )
