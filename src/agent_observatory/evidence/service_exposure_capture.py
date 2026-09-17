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
    ListenerAttributionState,
    listeners_from_tcp_connections,
    listeners_from_windows_capture,
)
from agent_observatory.endpoint.windows_capture import (
    WindowsCapture,
    collect_windows_capture,
    stable_processes,
)
from agent_observatory.endpoint.windows_firewall import (
    WindowsFirewallContext,
    collect_windows_firewall_context,
)
from agent_observatory.endpoint.windows_firewall_rules import (
    WindowsFirewallRuleInventory,
    collect_windows_firewall_rule_inventory,
)
from agent_observatory.endpoint.windows_process_principals import (
    WindowsProcessPrincipalObservation,
    WindowsProcessPrincipalSnapshot,
    collect_windows_process_principals,
    principal_observations_for_processes,
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
    windows_process_principal_event,
    windows_service_event,
)
from .windows_firewall_events import windows_firewall_context_event_batch
from .windows_firewall_rule_events import windows_firewall_rule_event_batch


UNBRACKETED_LISTENER_OBSERVATION_BASIS = "windows_get_nettcpconnection_snapshot"
BRACKETED_LISTENER_OBSERVATION_BASIS = "windows_bracketed_get_nettcpconnection_snapshot"
WINDOWS_PROCESS_PRINCIPAL_OBSERVATION_BASIS = (
    "windows_cim_win32_process_getownersid; "
    "process_verified_after_principal_query"
)
WINDOWS_SERVICE_OBSERVATION_BASIS = (
    "windows_cim_win32_service_running_snapshot; "
    "process_verified_after_service_inventory"
)
WINDOWS_FIREWALL_CONTEXT_OBSERVATION_BASIS = (
    "windows_get_netfirewallprofile_active_store+windows_get_netconnectionprofile"
)
WINDOWS_FIREWALL_RULE_OBSERVATION_BASIS = (
    "windows_get_netfirewallrule_active_store_inbound_with_filters"
)
_WINDOWS_PROCESS_PRINCIPAL_COLLECTOR = "windows_listener_process_principals"


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
    windows_process_principals: tuple[WindowsProcessPrincipalObservation, ...] = ()
    principal_observed_at: float | None = None
    windows_services: tuple[WindowsServiceProcessObservation, ...] = ()
    service_observed_at: float | None = None
    firewall_context: WindowsFirewallContext | None = None
    firewall_rule_inventory: WindowsFirewallRuleInventory | None = None

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


def _collector_reports_by_name(
    capture: ServiceExposureCapture,
) -> dict[str, ServiceExposureCollectorReport]:
    reports: dict[str, ServiceExposureCollectorReport] = {}
    for report in capture.collector_reports:
        if report.collector in reports:
            raise ValueError(
                f"collector report names must be unique: {report.collector}"
            )
        reports[report.collector] = report
    return reports


def _validate_capture_manifest_consistency(capture: ServiceExposureCapture) -> None:
    """Reject live captures whose principal facts disagree with their manifest.

    The manifest is the completeness contract for optional collectors. Principal
    evidence is particularly sensitive because a missing SID must remain an
    explicit unresolved observation or collector failure, never a silent gap.
    """

    reports = _collector_reports_by_name(capture)
    principal_report = reports.get(_WINDOWS_PROCESS_PRINCIPAL_COLLECTOR)
    principal_count = len(capture.windows_process_principals)

    if principal_report is None:
        if principal_count or capture.principal_observed_at is not None:
            raise ValueError(
                "process principal evidence requires a principal collector report"
            )
        return

    if principal_report.status is CollectorStatus.SUCCEEDED:
        if principal_report.record_count != principal_count:
            raise ValueError(
                "principal collector record_count must match principal observations"
            )
        if principal_count and capture.principal_observed_at is None:
            raise ValueError(
                "process principal observations require principal_observed_at"
            )
        return

    if principal_count:
        raise ValueError(
            "failed/skipped principal collector cannot carry principal observations"
        )
    if capture.principal_observed_at is not None:
        raise ValueError(
            "failed/skipped principal collector cannot carry principal_observed_at"
        )


def collect_service_exposure_capture(
    *,
    include_docker: bool = True,
    include_firewall: bool = False,
    include_firewall_rules: bool = False,
    include_process_principals: bool = False,
    windows_capture_provider: Callable[[], WindowsCapture] = collect_windows_capture,
    windows_service_provider: Callable[[], Iterable[WindowsServiceSnapshot]] = collect_windows_services,
    process_verification_provider: Callable[[], Iterable[ProcessSnapshot]] = collect_processes,
    process_principal_provider: Callable[
        [Iterable[int]], Iterable[WindowsProcessPrincipalSnapshot]
    ] = collect_windows_process_principals,
    firewall_context_provider: Callable[[], WindowsFirewallContext] = collect_windows_firewall_context,
    firewall_rule_provider: Callable[[], WindowsFirewallRuleInventory] = collect_windows_firewall_rule_inventory,
    docker_provider: Callable[[], Iterable[DockerPublishedPort]] = collect_docker_published_ports,
    clock: Callable[[], float] = time.time,
) -> ServiceExposureCapture:
    """Collect listener, principal, service, firewall, and Docker evidence.

    Listener ownership reuses the existing process/TCP/process bracket. Optional
    principal collection calls Win32_Process.GetOwnerSid only for bracket-stable
    listener process instances and then verifies those process instances again.

    Running Win32_Service records are collected only after listener collection
    succeeds, followed by their own fresh process verification snapshot.

    Firewall context and inbound ActiveStore rule inventory are independent
    evidence sources. Neither decides whether any particular listener is
    allowed, blocked, reachable, or exposed. Docker collection is also
    independent and keeps its own observation anchor.

    Collector failures are preserved in the manifest instead of being converted
    into empty successful observations.
    """

    listeners: tuple[HostTcpListener, ...] = ()
    windows_process_principals: tuple[WindowsProcessPrincipalObservation, ...] = ()
    windows_services: tuple[WindowsServiceProcessObservation, ...] = ()
    firewall_context: WindowsFirewallContext | None = None
    firewall_rule_inventory: WindowsFirewallRuleInventory | None = None
    docker_ports: tuple[DockerPublishedPort, ...] = ()
    listener_observed_at: float | None = None
    principal_observed_at: float | None = None
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

    if include_process_principals:
        if windows_capture is None or not listeners:
            reports.append(
                ServiceExposureCollectorReport(
                    collector=_WINDOWS_PROCESS_PRINCIPAL_COLLECTOR,
                    status=CollectorStatus.SKIPPED,
                    record_count=None,
                )
            )
        else:
            stable_by_pid = {
                process.pid: process
                for process in stable_processes(windows_capture)
            }
            target_processes = tuple(
                stable_by_pid[pid]
                for pid in sorted(
                    {
                        listener.owner_pid
                        for listener in listeners
                        if listener.attribution_state is ListenerAttributionState.ATTRIBUTED
                    }
                )
                if pid in stable_by_pid
            )
            if not target_processes:
                reports.append(
                    ServiceExposureCollectorReport(
                        collector=_WINDOWS_PROCESS_PRINCIPAL_COLLECTOR,
                        status=CollectorStatus.SKIPPED,
                        record_count=None,
                    )
                )
            else:
                try:
                    principal_inventory = tuple(
                        process_principal_provider(
                            tuple(process.pid for process in target_processes)
                        )
                    )
                    principal_snapshot_finished_at = float(clock())
                    principal_verification_processes = tuple(
                        process_verification_provider()
                    )
                    windows_process_principals = principal_observations_for_processes(
                        principal_inventory,
                        target_processes,
                        principal_verification_processes,
                    )
                    principal_observed_at = principal_snapshot_finished_at
                    reports.append(
                        ServiceExposureCollectorReport(
                            collector=_WINDOWS_PROCESS_PRINCIPAL_COLLECTOR,
                            status=CollectorStatus.SUCCEEDED,
                            record_count=len(windows_process_principals),
                            observation_basis=WINDOWS_PROCESS_PRINCIPAL_OBSERVATION_BASIS,
                        )
                    )
                except Exception as exc:
                    reports.append(
                        _failure_report(_WINDOWS_PROCESS_PRINCIPAL_COLLECTOR, exc)
                    )

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

    if include_firewall:
        try:
            firewall_context = firewall_context_provider()
            reports.append(
                ServiceExposureCollectorReport(
                    collector="windows_firewall_context",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=(
                        len(firewall_context.firewall_profiles)
                        + len(firewall_context.network_profiles)
                    ),
                    observation_basis=WINDOWS_FIREWALL_CONTEXT_OBSERVATION_BASIS,
                )
            )
        except Exception as exc:
            reports.append(_failure_report("windows_firewall_context", exc))

    if include_firewall_rules:
        try:
            firewall_rule_inventory = firewall_rule_provider()
            reports.append(
                ServiceExposureCollectorReport(
                    collector="windows_firewall_rules",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=len(firewall_rule_inventory.rules),
                    observation_basis=WINDOWS_FIREWALL_RULE_OBSERVATION_BASIS,
                )
            )
        except Exception as exc:
            reports.append(_failure_report("windows_firewall_rules", exc))

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
        windows_process_principals=windows_process_principals,
        principal_observed_at=principal_observed_at,
        windows_services=windows_services,
        service_observed_at=service_observed_at,
        firewall_context=firewall_context,
        firewall_rule_inventory=firewall_rule_inventory,
    )


def service_exposure_manifest_event(
    capture: ServiceExposureCapture,
    *,
    source: str,
    stream_id: str,
) -> ObservationEvent:
    """Persist collector completeness separately from collected service facts."""

    _validate_capture_manifest_consistency(capture)

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

    _validate_capture_manifest_consistency(capture)

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

    principal_events: tuple[ObservationEvent, ...] = ()
    if capture.windows_process_principals:
        if capture.principal_observed_at is None:
            raise ValueError("process principal observations require principal_observed_at")
        principal_events = tuple(
            windows_process_principal_event(
                observation,
                observed_at=capture.principal_observed_at,
                source=source,
                stream_id=stream_id,
                observation_basis=WINDOWS_PROCESS_PRINCIPAL_OBSERVATION_BASIS,
            )
            for observation in capture.windows_process_principals
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

    firewall_events: tuple[ObservationEvent, ...] = ()
    if capture.firewall_context is not None:
        firewall_events = windows_firewall_context_event_batch(
            capture.firewall_context,
            source=source,
            stream_id=stream_id,
        )

    firewall_rule_events: tuple[ObservationEvent, ...] = ()
    if capture.firewall_rule_inventory is not None:
        firewall_rule_events = windows_firewall_rule_event_batch(
            capture.firewall_rule_inventory,
            source=source,
            stream_id=stream_id,
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
        *principal_events,
        *service_events,
        *firewall_events,
        *firewall_rule_events,
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
