from __future__ import annotations

from collections.abc import Iterable

from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.service_exposure import (
    DockerPublishedPort,
    listeners_from_tcp_connections,
)
from agent_observatory.storage import EventStore, ObservationEvent, StoredEvent

from .service_exposure_events import (
    docker_published_port_event,
    tcp_listener_event,
)


def service_exposure_event_batch(
    tcp_connections: Iterable[TcpConnection],
    docker_ports: Iterable[DockerPublishedPort],
    *,
    tcp_observed_at: float,
    docker_observed_at: float,
    source: str,
    stream_id: str,
) -> tuple[ObservationEvent, ...]:
    """Build one deterministic batch from explicit host and Docker observations.

    Host TCP and Docker observations keep separate time anchors because the two
    collectors are not simultaneous. The batch contains observations only; it
    does not infer reachability, authentication, exploitability, or service
    identity from port numbers.
    """

    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")
    if not isinstance(stream_id, str) or not stream_id.strip():
        raise ValueError("stream_id must be a non-empty string")

    listener_events = tuple(
        tcp_listener_event(
            listener,
            observed_at=tcp_observed_at,
            source=source,
            stream_id=stream_id,
        )
        for listener in listeners_from_tcp_connections(tcp_connections)
    )

    ordered_docker_ports = tuple(
        sorted(
            docker_ports,
            key=lambda item: (
                item.container_name.casefold(),
                item.protocol,
                item.container_port,
                item.host_address,
                item.host_port,
                item.container_id,
            ),
        )
    )
    docker_events = tuple(
        docker_published_port_event(
            published,
            observed_at=docker_observed_at,
            source=source,
            stream_id=stream_id,
        )
        for published in ordered_docker_ports
    )

    return (*listener_events, *docker_events)


def append_service_exposure_batch(
    store: EventStore,
    tcp_connections: Iterable[TcpConnection],
    docker_ports: Iterable[DockerPublishedPort],
    *,
    tcp_observed_at: float,
    docker_observed_at: float,
    source: str,
    stream_id: str,
) -> tuple[StoredEvent, ...]:
    """Build and atomically append one service-exposure evidence batch."""

    batch = service_exposure_event_batch(
        tcp_connections,
        docker_ports,
        tcp_observed_at=tcp_observed_at,
        docker_observed_at=docker_observed_at,
        source=source,
        stream_id=stream_id,
    )
    return store.append_many(batch)
