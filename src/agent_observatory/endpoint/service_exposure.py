from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .network import TcpConnection
from .windows_capture import WindowsCapture, stable_processes


class BindScope(str, Enum):
    """Topological bind-address class, not a reachability verdict."""

    LOOPBACK = "loopback"
    WILDCARD = "wildcard"
    SPECIFIC = "specific"
    UNKNOWN = "unknown"


class ListenerAttributionState(str, Enum):
    ATTRIBUTED = "attributed"
    UNRESOLVED = "unresolved"


def classify_bind_scope(address: str) -> BindScope:
    """Classify one IP bind address without inferring network reachability."""

    normalized = address.strip()
    if normalized in {"0.0.0.0", "::", "::0", "*"}:
        return BindScope.WILDCARD

    try:
        parsed = ipaddress.ip_address(normalized)
    except ValueError:
        return BindScope.UNKNOWN

    if parsed.is_unspecified:
        return BindScope.WILDCARD
    if parsed.is_loopback:
        return BindScope.LOOPBACK
    return BindScope.SPECIFIC


@dataclass(frozen=True, slots=True)
class HostTcpListener:
    """One point-in-time TCP listener with explicit owner-attribution quality."""

    owner_pid: int
    local_address: str
    local_port: int
    state: str = "Listen"
    owner_identity_basis: str = "pid_only_snapshot"
    attribution_state: ListenerAttributionState = ListenerAttributionState.UNRESOLVED
    process_started_at: float | None = None
    process_name: str | None = None
    executable_path: str | None = None
    attribution_reason: str | None = "process_instance_not_bracket_validated"

    def __post_init__(self) -> None:
        if isinstance(self.owner_pid, bool) or not isinstance(self.owner_pid, int):
            raise TypeError("owner_pid must be an integer")
        if self.owner_pid < 0:
            raise ValueError("owner_pid must be non-negative")
        if not isinstance(self.local_address, str) or not self.local_address.strip():
            raise ValueError("local_address must be a non-empty string")
        if isinstance(self.local_port, bool) or not isinstance(self.local_port, int):
            raise TypeError("local_port must be an integer")
        if not 0 < self.local_port <= 65535:
            raise ValueError("local_port must be between 1 and 65535")
        if not isinstance(self.state, str) or not self.state.strip():
            raise ValueError("state must be a non-empty string")
        if not isinstance(self.owner_identity_basis, str) or not self.owner_identity_basis.strip():
            raise ValueError("owner_identity_basis must be a non-empty string")
        if not isinstance(self.attribution_state, ListenerAttributionState):
            raise TypeError("attribution_state must be ListenerAttributionState")
        if self.attribution_state is ListenerAttributionState.ATTRIBUTED:
            if self.process_started_at is None:
                raise ValueError("attributed listener requires process_started_at")
            if not self.process_name:
                raise ValueError("attributed listener requires process_name")
            if self.owner_identity_basis != "stable_process_instance":
                raise ValueError("attributed listener requires stable_process_instance basis")
            if self.attribution_reason is not None:
                raise ValueError("attributed listener must not carry attribution_reason")
        elif self.process_started_at is not None:
            raise ValueError("unresolved listener must not carry process_started_at")

    @property
    def protocol(self) -> str:
        return "tcp"

    @property
    def bind_scope(self) -> BindScope:
        return classify_bind_scope(self.local_address)

    @property
    def process_ref(self) -> dict[str, object] | None:
        if self.attribution_state is not ListenerAttributionState.ATTRIBUTED:
            return None
        assert self.process_started_at is not None
        return {"pid": self.owner_pid, "started_at": self.process_started_at}


def listeners_from_tcp_connections(
    connections: Iterable[TcpConnection],
) -> tuple[HostTcpListener, ...]:
    """Project listening sockets from an unbracketed TCP inventory."""

    listeners = [
        HostTcpListener(
            owner_pid=connection.pid,
            local_address=connection.local_address,
            local_port=connection.local_port,
            state=connection.state,
        )
        for connection in connections
        if connection.is_listening
    ]
    return tuple(
        sorted(
            listeners,
            key=lambda item: (
                item.local_address,
                item.local_port,
                item.owner_pid,
                item.state.casefold(),
            ),
        )
    )


def listeners_from_windows_capture(capture: WindowsCapture) -> tuple[HostTcpListener, ...]:
    """Project listeners and attribute only bracket-stable process instances."""

    stable_by_pid = {process.pid: process for process in stable_processes(capture)}
    listeners: list[HostTcpListener] = []

    for connection in capture.tcp_connections:
        if not connection.is_listening:
            continue
        process = stable_by_pid.get(connection.pid)
        if process is None:
            listeners.append(
                HostTcpListener(
                    owner_pid=connection.pid,
                    local_address=connection.local_address,
                    local_port=connection.local_port,
                    state=connection.state,
                    attribution_reason="owner_pid_not_stable_across_process_bracket",
                )
            )
            continue
        listeners.append(
            HostTcpListener(
                owner_pid=connection.pid,
                local_address=connection.local_address,
                local_port=connection.local_port,
                state=connection.state,
                owner_identity_basis="stable_process_instance",
                attribution_state=ListenerAttributionState.ATTRIBUTED,
                process_started_at=process.started_at,
                process_name=process.name,
                executable_path=process.executable_path,
                attribution_reason=None,
            )
        )

    return tuple(
        sorted(
            listeners,
            key=lambda item: (
                item.local_address,
                item.local_port,
                item.owner_pid,
                item.state.casefold(),
            ),
        )
    )


@dataclass(frozen=True, slots=True)
class DockerPublishedPort:
    """One Docker host-port publication observed through Docker inspect."""

    container_id: str
    container_name: str
    image: str | None
    protocol: str
    container_port: int
    host_address: str
    host_port: int
    observation_basis: str = "docker_inspect_running_container"

    def __post_init__(self) -> None:
        if not isinstance(self.container_id, str) or not self.container_id.strip():
            raise ValueError("container_id must be a non-empty string")
        if not isinstance(self.container_name, str) or not self.container_name.strip():
            raise ValueError("container_name must be a non-empty string")
        if self.image is not None and not isinstance(self.image, str):
            raise TypeError("image must be a string or None")
        if not isinstance(self.protocol, str) or not self.protocol.strip():
            raise ValueError("protocol must be a non-empty string")
        if isinstance(self.container_port, bool) or not isinstance(self.container_port, int):
            raise TypeError("container_port must be an integer")
        if not 0 < self.container_port <= 65535:
            raise ValueError("container_port must be between 1 and 65535")
        if not isinstance(self.host_address, str) or not self.host_address.strip():
            raise ValueError("host_address must be a non-empty string")
        if isinstance(self.host_port, bool) or not isinstance(self.host_port, int):
            raise TypeError("host_port must be an integer")
        if not 0 < self.host_port <= 65535:
            raise ValueError("host_port must be between 1 and 65535")
        if not isinstance(self.observation_basis, str) or not self.observation_basis.strip():
            raise ValueError("observation_basis must be a non-empty string")

    @property
    def bind_scope(self) -> BindScope:
        return classify_bind_scope(self.host_address)
