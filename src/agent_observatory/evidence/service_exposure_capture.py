from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

from agent_observatory.endpoint.docker_ports import collect_docker_published_ports
from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.service_exposure import (
    DockerPublishedPort,
    HostTcpListener,
    listeners_from_tcp_connections,
    listeners_from_windows_capture,
)
from agent_observatory.endpoint.windows_capture import (
    WindowsCapture,
    collect_windows_capture,
)
from agent_observatory.endpoint.windows_services import (
    WindowsServiceProcessObservation,
    WindowsServiceSnapshot,
    collect_windows_services,
    service_observations_for_listeners,
    service_processes_stable_across_inventory,
)
from agent_observatory.endpoint.windows_snapshot import collect_processes
from agent_observatory.storage import EventStore, EventType, ObservationEvent, StoredEvent

from .service_exposure_events import (
    docker_published_port_event,
    tcp_listener_event,
    windows_service_event,
)


UNBRACKETED_LISTENER_OBSERVATION_BASIS = "windows_get_nettcpconnection_snapshot"
BRACKETED_LISTENER_OBSERVATION_BASIS = "windows_bracketed_get_nettcpconnection_snapshot"
WINDOWS_SERVICE_OBSERVATION_BASIS = (
    "windows_cim_win32_service_running_snapshot; "
    "process_verified_after_service_inventory"
)


class CollectorStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True, slots=True)
class ServiceExposureCollectorReport:
    collector: str
    status: CollectorStatus
    record_count: int | None
    observation_basis: str | None = None
    error_type: str | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.collector, str) or not self.collector.strip():
            raise ValueError("collector must be a non-empty string")
        if not isinstance(self.status, CollectorStatus):
            raise TypeError("status must be CollectorStatus")
        if self.record_count is not None:
            if isinstance(self.record_count, bool) or not isinstance(self.record_count, int):
                raise TypeError("record_count must be an integer or None")
            if self.record_count < 0:
                raise ValueError("record_count must be non-negative")
        if self.status is CollectorStatus.SUCCEEDED and self.record_count is None:
            raise ValueError("succeeded collector must have record_count")
        if self.status is not CollectorStatus.SUCCEEDED and self.record_count is not None:
            raise ValueError("failed/skipped collector must have record_count=None")
        if self.status is CollectorStatus.FAILED:
            if not self.error_type or not self.error_message:
                raise ValueError("failed collector must preserve error type and message")
        elif self.error_type is not None or self.error_message is not None:
            raise ValueError("only failed collectors may carry error details")
        if self.observation_basis is not None and (
            not isinstance(self.observation_basis, str)
            or not self.observation_basis.strip()
        ):
            raise ValueError("observation_basis must be a non-empty string or None")


@dataclass(frozen=True, slots=True)
class ServiceExposureCapture:
    listeners: tuple[HostTcpListener, ...]
    docker_ports: tuple[DockerPublishedPort, ...]
    listener_observed_at: float | None
    docker_observed_at: float | None
    manifest_observed_at: float
    collector_reports: tuple[ServiceExposureCollectorReport, ...]
    windows_services: tuple[WindowsServiceProcessObservation, ...] = ()
    service_observed_at: float | None = None

    @property
    def has_failures(self) -> bool:
        return any(
            report.status is CollectorStatus.FAILED
            for report in self.collector_reports
        )


def _failure_report(collector: str, exc: Exception) -> ServiceExposureCollectorReport:
    return ServiceExposureCollectorReport(
        collector=collector,
        status=CollectorStatus.FAILED,
        record_count=None,
        error_type=type(exc).__name__,
        error_message=str(exc) or type(exc).__name__,
    )


def collect_service_exposure_capture(
    *,
    include_docker: bool = True,
    windows_capture_provider: Callable[[], WindowsCapture] = collect_windows_capture,
    windows_service_provider: Callable[[], Iterable[WindowsServiceSnapshot]] = collect_windows_services,
    process_verification_provider: Callable[[], Iterable[ProcessSnapshot]] = collect_processes,
    docker_provider: Callable[[], Iterable[DockerPublishedPort]] = collect_docker_published_ports,
    clock: Callable[[], float] = time.time,
) -> ServiceExposureCapture:
    """Collect bracket-attributed listener, service, and Docker publication evidence.

    Listener ownership reuses the existing process/TCP/process bracket. Running
    Win32_Service records are collected only after listener collection succeeds,
    then a fresh process inventory verifies that a service PID still represents
    the same process instance across the service snapshot. Docker collection is
    independent and keeps its own observation anchor.

    Collector failures are preserved in the manifest instead of being converted
    into empty successful observations.
    """

    listeners: tuple[HostTcpListener, ...] = ()
    windows_services: tuple[WindowsServiceProcessObservation, ...] = ()
    docker_ports: tuple[DockerPublishedPort, ...] = ()
    listener_observed_at: float | None = None
    service_observed_at: float | None = None
    docker_observed_at: float | None = None
    reports: list[ServiceExposureCollectorReport] = []
    windows_capture: WindowsCapture | None = None

    try:
        windows_capture = windows_capture_provider()
        listeners = listeners_from_windows_capture(windows_capture)
        listener_observed_at = windows_capture.network_interval.finished_at
        reports.append(
            ServiceExposureCollectorReport(
                collector="windows_tcp_listeners",
                status=CollectorStatus.SUCCEEDED,
                record_count=len(listeners),
                observation_basis=BRACKETED_LISTENER_OBSERVATION_BASIS,
            )
        )
    except Exception as exc:
        reports.append(_failure_report("windows_tcp_listeners", exc))

    if windows_capture is None:
        reports.append(
            ServiceExposureCollectorReport(
                collector="windows_listener_services",
                status=CollectorStatus.SKIPPED,
                record_count=None,
            )
        )
    elif not listeners:
        reports.append(
            ServiceExposureCollectorReport(
                collector="windows_listener_services",
                status=CollectorStatus.SKIPPED,
                record_count=None,
            )
        )
    else:
        try:
            service_inventory = tuple(windows_service_provider())
            service_snapshot_finished_at = float(clock())
            verification_processes = tuple(process_verification_provider())
            verified_processes = service_processes_stable_across_inventory(
                windows_capture,
                verification_processes,
            )
            windows_services = service_observations_for_listeners(
                service_inventory,
                listeners,
                verified_processes=verified_processes,
            )
            service_observed_at = service_snapshot_finished_at
            reports.append(
                ServiceExposureCollectorReport(
                    collector="windows_listener_services",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=len(windows_services),
                    observation_basis=WINDOWS_SERVICE_OBSERVATION_BASIS,
                )
            )
        except Exception as exc:
            reports.append(_failure_report("windows_listener_services", exc))

    if include_docker:
        try:
            docker_ports = tuple(docker_provider())
            docker_observed_at = float(clock())
            reports.append(
                ServiceExposureCollectorReport(
                    collector="docker_published_ports",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=len(docker_ports),
                    observation_basis="docker_inspect_running_container",
                )
            )
        except Exception as exc:
            reports.append(_failure_report("docker_published_ports", exc))
    else:
        reports.append(
            ServiceExposureCollectorReport(
                collector="docker_published_ports",
                status=CollectorStatus.SKIPPED,
                record_count=None,
            )
        )

    return ServiceExposureCapture(
        listeners=listeners,
        docker_ports=docker_ports,
        listener_observed_at=listener_observed_at,
        docker_observed_at=docker_observed_at,
        manifest_observed_at=float(clock()),
        collector_reports=tuple(reports),
        windows_services=windows_services,
        service_observed_at=service_observed_at,
    )


def service_exposure_manifest_event(
    capture: ServiceExposureCapture,
    *,
    source: str,
    stream_id: str,
) -> ObservationEvent:
    """Persist collector completeness separately from collected service facts."""

    return ObservationEvent(
        event_type=EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
        observed_at=capture.manifest_observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "capture_kind": "service_exposure",
            "partial": capture.has_failures,
            "collectors": [
                {
                    "collector": report.collector,
                    "status": report.status.value,
                    "record_count": report.record_count,
                    "observation_basis": report.observation_basis,
                    "error_type": report.error_type,
                    "error_message": report.error_message,
                }
                for report in capture.collector_reports
            ],
        },
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
    """Build one deterministic batch from explicit successful observations.

    This lower-level helper accepts an unbracketed TCP inventory and therefore
    preserves PID-only listener ownership. Use
    ``service_exposure_capture_event_batch`` for live collector runs where
    bracket attribution and completeness must also be persisted.
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
            observation_basis=UNBRACKETED_LISTENER_OBSERVATION_BASIS,
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


def service_exposure_capture_event_batch(
    capture: ServiceExposureCapture,
    *,
    source: str,
    stream_id: str,
) -> tuple[ObservationEvent, ...]:
    """Build deterministic live-capture facts plus one completeness manifest."""

    listener_events: tuple[ObservationEvent, ...] = ()
    if capture.listeners:
        if capture.listener_observed_at is None:
            raise ValueError("listener observations require listener_observed_at")
        listener_events = tuple(
            tcp_listener_event(
                listener,
                observed_at=capture.listener_observed_at,
                source=source,
                stream_id=stream_id,
                observation_basis=BRACKETED_LISTENER_OBSERVATION_BASIS,
            )
            for listener in capture.listeners
        )

    service_events: tuple[ObservationEvent, ...] = ()
    if capture.windows_services:
        if capture.service_observed_at is None:
            raise ValueError("Windows service observations require service_observed_at")
        service_events = tuple(
            windows_service_event(
                observation,
                observed_at=capture.service_observed_at,
                source=source,
                stream_id=stream_id,
                observation_basis=WINDOWS_SERVICE_OBSERVATION_BASIS,
            )
            for observation in capture.windows_services
        )

    docker_events: tuple[ObservationEvent, ...] = ()
    if capture.docker_ports:
        if capture.docker_observed_at is None:
            raise ValueError("Docker observations require docker_observed_at")
        docker_events = tuple(
            docker_published_port_event(
                published,
                observed_at=capture.docker_observed_at,
                source=source,
                stream_id=stream_id,
            )
            for published in capture.docker_ports
        )

    return (
        *listener_events,
        *service_events,
        *docker_events,
        service_exposure_manifest_event(capture, source=source, stream_id=stream_id),
    )


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
    """Build and atomically append one explicit service-exposure evidence batch."""

    batch = service_exposure_event_batch(
        tcp_connections,
        docker_ports,
        tcp_observed_at=tcp_observed_at,
        docker_observed_at=docker_observed_at,
        source=source,
        stream_id=stream_id,
    )
    return store.append_many(batch)


def append_service_exposure_capture(
    store: EventStore,
    capture: ServiceExposureCapture,
    *,
    source: str,
    stream_id: str,
) -> tuple[StoredEvent, ...]:
    """Atomically append live facts and their collector-completeness manifest."""

    return store.append_many(
        service_exposure_capture_event_batch(
            capture,
            source=source,
            stream_id=stream_id,
        )
    )
