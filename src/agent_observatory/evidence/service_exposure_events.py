from __future__ import annotations

from agent_observatory.endpoint.service_exposure import (
    DockerPublishedPort,
    HostTcpListener,
)
from agent_observatory.endpoint.windows_process_principals import (
    WindowsProcessPrincipalObservation,
)
from agent_observatory.endpoint.windows_services import WindowsServiceProcessObservation
from agent_observatory.storage import EventType, ObservationEvent


def tcp_listener_event(
    listener: HostTcpListener,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
    observation_basis: str = "windows_get_nettcpconnection_snapshot",
) -> ObservationEvent:
    """Adapt one listener while preserving explicit process-attribution quality."""

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
            "attribution_state": listener.attribution_state.value,
            "attribution_reason": listener.attribution_reason,
            "process": listener.process_ref,
            "process_name": listener.process_name,
            "executable_path": listener.executable_path,
            "state": listener.state,
            "local_address": listener.local_address,
            "local_port": listener.local_port,
            "bind_scope": listener.bind_scope.value,
            "observation_basis": observation_basis,
        },
    )


def windows_process_principal_event(
    observation: WindowsProcessPrincipalObservation,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
    observation_basis: str = (
        "windows_cim_win32_process_getownersid; process_verified_after_principal_query"
    ),
) -> ObservationEvent:
    """Persist one process-principal query without inventing missing ownership."""

    if not isinstance(observation_basis, str) or not observation_basis.strip():
        raise ValueError("observation_basis must be a non-empty string")

    return ObservationEvent(
        event_type=EventType.WINDOWS_PROCESS_PRINCIPAL_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "process_id": observation.process_id,
            "process": observation.process_ref,
            "process_name": observation.process_name,
            "process_identity_basis": observation.process_identity_basis,
            "owner_sid": observation.owner_sid,
            "resolution_state": observation.resolution_state.value,
            "resolution_reason": observation.resolution_reason,
            "get_owner_sid_return_value": observation.return_value,
            "observation_basis": observation_basis,
        },
    )


def windows_service_event(
    observation: WindowsServiceProcessObservation,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
    observation_basis: str = "windows_cim_win32_service_running_snapshot",
) -> ObservationEvent:
    """Persist one running Win32_Service fact without inventing service ownership."""

    if not isinstance(observation_basis, str) or not observation_basis.strip():
        raise ValueError("observation_basis must be a non-empty string")

    service = observation.service
    return ObservationEvent(
        event_type=EventType.WINDOWS_SERVICE_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "service_name": service.name,
            "display_name": service.display_name,
            "state": service.state,
            "start_mode": service.start_mode,
            "service_type": service.service_type,
            "process_id": service.process_id,
            "process": observation.process_ref,
            "process_name": observation.process_name,
            "executable_path": observation.executable_path,
            "process_attribution_state": observation.attribution_state.value,
            "process_attribution_basis": observation.attribution_basis,
            "process_attribution_reason": observation.attribution_reason,
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
