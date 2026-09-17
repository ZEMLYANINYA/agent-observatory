from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable

from .models import ProcessSnapshot
from .service_exposure import HostTcpListener, ListenerAttributionState
from .windows_capture import WindowsCapture, same_process_instance
from .windows_powershell import run_powershell_text


class ServiceProcessAttributionState(str, Enum):
    ATTRIBUTED = "attributed"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class WindowsServiceSnapshot:
    """One point-in-time Win32_Service record for a running service process."""

    name: str
    display_name: str
    state: str
    start_mode: str
    process_id: int
    service_type: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise ValueError("display_name must be a non-empty string")
        if not isinstance(self.state, str) or not self.state.strip():
            raise ValueError("state must be a non-empty string")
        if not isinstance(self.start_mode, str) or not self.start_mode.strip():
            raise ValueError("start_mode must be a non-empty string")
        if isinstance(self.process_id, bool) or not isinstance(self.process_id, int):
            raise TypeError("process_id must be an integer")
        if self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        if self.service_type is not None and not isinstance(self.service_type, str):
            raise TypeError("service_type must be a string or None")


@dataclass(frozen=True, slots=True)
class WindowsServiceProcessObservation:
    """Service source record plus explicit process-attribution quality."""

    service: WindowsServiceSnapshot
    attribution_state: ServiceProcessAttributionState
    attribution_basis: str
    process_started_at: float | None = None
    process_name: str | None = None
    executable_path: str | None = None
    attribution_reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.service, WindowsServiceSnapshot):
            raise TypeError("service must be WindowsServiceSnapshot")
        if not isinstance(self.attribution_state, ServiceProcessAttributionState):
            raise TypeError("attribution_state must be ServiceProcessAttributionState")
        if not isinstance(self.attribution_basis, str) or not self.attribution_basis.strip():
            raise ValueError("attribution_basis must be a non-empty string")

        if self.attribution_state is ServiceProcessAttributionState.ATTRIBUTED:
            if self.process_started_at is None:
                raise ValueError("attributed service requires process_started_at")
            if not self.process_name:
                raise ValueError("attributed service requires process_name")
            if self.attribution_basis != "stable_process_instance":
                raise ValueError("attributed service requires stable_process_instance basis")
            if self.attribution_reason is not None:
                raise ValueError("attributed service must not carry attribution_reason")
        else:
            if self.process_started_at is not None:
                raise ValueError("unresolved service must not carry process_started_at")
            if not self.attribution_reason:
                raise ValueError("unresolved service requires attribution_reason")

    @property
    def process_ref(self) -> dict[str, object] | None:
        if self.attribution_state is not ServiceProcessAttributionState.ATTRIBUTED:
            return None
        assert self.process_started_at is not None
        return {
            "pid": self.service.process_id,
            "started_at": self.process_started_at,
        }


def _powershell_service_inventory() -> str:
    command = r"""
Get-CimInstance Win32_Service |
Where-Object { $_.State -eq 'Running' -and $_.ProcessId -gt 0 } |
Select-Object `
    @{Name='name';Expression={$_.Name}},
    @{Name='display_name';Expression={$_.DisplayName}},
    @{Name='state';Expression={$_.State}},
    @{Name='start_mode';Expression={$_.StartMode}},
    @{Name='process_id';Expression={$_.ProcessId}},
    @{Name='service_type';Expression={$_.ServiceType}} |
ConvertTo-Json -Compress
"""
    return run_powershell_text(command)


def parse_windows_service_records(
    records: Iterable[dict[str, Any]],
) -> tuple[WindowsServiceSnapshot, ...]:
    services: list[WindowsServiceSnapshot] = []
    for record in records:
        services.append(
            WindowsServiceSnapshot(
                name=str(record["name"]),
                display_name=str(record["display_name"]),
                state=str(record["state"]),
                start_mode=str(record["start_mode"]),
                process_id=int(record["process_id"]),
                service_type=(
                    None
                    if record.get("service_type") is None
                    else str(record.get("service_type"))
                ),
            )
        )
    return tuple(
        sorted(
            services,
            key=lambda item: (
                item.process_id,
                item.name.casefold(),
                item.display_name.casefold(),
            ),
        )
    )


def parse_windows_service_inventory(raw: str) -> tuple[WindowsServiceSnapshot, ...]:
    raw = raw.strip()
    if not raw:
        return ()

    records = json.loads(raw)
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise TypeError("Windows service inventory must be a JSON object or array")
    return parse_windows_service_records(records)


def collect_windows_services() -> tuple[WindowsServiceSnapshot, ...]:
    return parse_windows_service_inventory(_powershell_service_inventory())


def service_processes_stable_across_inventory(
    capture: WindowsCapture,
    verification_processes: Iterable[ProcessSnapshot],
) -> tuple[ProcessSnapshot, ...]:
    """Return process instances that survive from capture-after through service inventory.

    Live service attribution is intentionally stricter than PID matching. The
    Win32_Service snapshot is collected after the listener bracket, followed by
    a fresh process inventory. A process is eligible only when the process seen
    at the end of the listener bracket is the same instance seen after the
    service inventory.
    """

    verification_by_pid = {
        process.pid: process
        for process in verification_processes
    }
    stable: list[ProcessSnapshot] = []
    for process in capture.processes_after:
        verified = verification_by_pid.get(process.pid)
        if verified is not None and same_process_instance(process, verified):
            stable.append(process)
    return tuple(stable)


def service_observations_for_listeners(
    services: Iterable[WindowsServiceSnapshot],
    listeners: Iterable[HostTcpListener],
    *,
    verified_processes: Iterable[ProcessSnapshot] | None = None,
) -> tuple[WindowsServiceProcessObservation, ...]:
    """Retain all service records whose ProcessId owns at least one listener.

    A service receives a process-instance reference only when at least one
    listener for the same PID carries bracket-validated process identity. When
    ``verified_processes`` is supplied, the listener process must also appear in
    that post-service verified set with the same PID and creation time. Multiple
    services sharing one PID are all preserved.
    """

    listeners_by_pid: dict[int, list[HostTcpListener]] = {}
    for listener in listeners:
        listeners_by_pid.setdefault(listener.owner_pid, []).append(listener)

    verified_by_pid = (
        None
        if verified_processes is None
        else {process.pid: process for process in verified_processes}
    )

    observations: list[WindowsServiceProcessObservation] = []
    for service in services:
        candidates = listeners_by_pid.get(service.process_id)
        if not candidates:
            continue

        attributed = tuple(
            listener
            for listener in candidates
            if listener.attribution_state is ListenerAttributionState.ATTRIBUTED
        )
        identities = {
            (
                listener.process_started_at,
                listener.process_name,
                listener.executable_path,
            )
            for listener in attributed
        }

        if len(identities) == 1:
            process_started_at, process_name, executable_path = next(iter(identities))
            assert process_started_at is not None
            assert process_name is not None

            if verified_by_pid is not None:
                verified = verified_by_pid.get(service.process_id)
                if (
                    verified is None
                    or verified.started_at != process_started_at
                ):
                    observations.append(
                        WindowsServiceProcessObservation(
                            service=service,
                            attribution_state=ServiceProcessAttributionState.UNRESOLVED,
                            attribution_basis="pid_only_snapshot",
                            attribution_reason=(
                                "service_process_not_stable_across_post_service_snapshot"
                            ),
                        )
                    )
                    continue

            observations.append(
                WindowsServiceProcessObservation(
                    service=service,
                    attribution_state=ServiceProcessAttributionState.ATTRIBUTED,
                    attribution_basis="stable_process_instance",
                    process_started_at=process_started_at,
                    process_name=process_name,
                    executable_path=executable_path,
                    attribution_reason=None,
                )
            )
        elif len(identities) > 1:
            observations.append(
                WindowsServiceProcessObservation(
                    service=service,
                    attribution_state=ServiceProcessAttributionState.UNRESOLVED,
                    attribution_basis="pid_only_snapshot",
                    attribution_reason="conflicting_listener_process_attribution",
                )
            )
        else:
            observations.append(
                WindowsServiceProcessObservation(
                    service=service,
                    attribution_state=ServiceProcessAttributionState.UNRESOLVED,
                    attribution_basis="pid_only_snapshot",
                    attribution_reason="listener_process_not_bracket_attributed",
                )
            )

    return tuple(
        sorted(
            observations,
            key=lambda item: (
                item.service.process_id,
                item.service.name.casefold(),
                item.service.display_name.casefold(),
            ),
        )
    )
