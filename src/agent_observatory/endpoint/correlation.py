from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .network import TcpConnection
from .roles import ProcessRole, classify_process_role
from .application_models import ApplicationSnapshot


@dataclass(frozen=True, slots=True)
class ProcessNetworkSnapshot:
    pid: int
    ppid: int
    name: str
    role: ProcessRole
    connections: tuple[TcpConnection, ...]


@dataclass(frozen=True, slots=True)
class ApplicationNetworkSnapshot:
    application_name: str
    root_pid: int
    processes: tuple[ProcessNetworkSnapshot, ...]


def correlate_application_network(
    snapshots: Iterable[ApplicationSnapshot],
    connections: Iterable[TcpConnection],
) -> tuple[ApplicationNetworkSnapshot, ...]:
    """
    Correlate validated AI application process trees with TCP connections.

    Connection ownership is attributed using the owning PID reported by
    the operating system. Only processes already present in a validated
    application snapshot are included.
    """

    connections_by_pid: dict[int, list[TcpConnection]] = {}

    for connection in connections:
        connections_by_pid.setdefault(
            connection.pid,
            [],
        ).append(connection)

    results: list[ApplicationNetworkSnapshot] = []

    for snapshot in snapshots:
        root_pid = snapshot.application.root_process.pid
        process_rows: list[ProcessNetworkSnapshot] = []

        for process in snapshot.processes:
            role = classify_process_role(
                process.command_line,
                is_root=process.pid == root_pid,
            )

            process_rows.append(
                ProcessNetworkSnapshot(
                    pid=process.pid,
                    ppid=process.ppid,
                    name=process.name,
                    role=role,
                    connections=tuple(
                        connections_by_pid.get(
                            process.pid,
                            (),
                        )
                    ),
                )
            )

        results.append(
            ApplicationNetworkSnapshot(
                application_name=snapshot.application.profile.name,
                root_pid=root_pid,
                processes=tuple(process_rows),
            )
        )

    return tuple(results)


def format_network_snapshot(
    snapshots: Iterable[ApplicationNetworkSnapshot],
    *,
    established_only: bool = True,
) -> str:
    lines: list[str] = []

    for snapshot in snapshots:
        lines.append(
            f"{snapshot.application_name} "
            f"(root PID {snapshot.root_pid})"
        )

        for process in snapshot.processes:
            visible_connections = tuple(
                connection
                for connection in process.connections
                if (
                    not established_only
                    or connection.is_established
                )
            )

            lines.append(
                f"  PID={process.pid:<6} "
                f"ROLE={process.role.value:<13} "
                f"TCP={len(visible_connections)}"
            )

            for connection in visible_connections:
                lines.append(
                    f"    "
                    f"{connection.local_address}:"
                    f"{connection.local_port} "
                    f"-> "
                    f"{connection.remote_address}:"
                    f"{connection.remote_port} "
                    f"[{connection.state}]"
                )

        lines.append("")

    return "\n".join(lines).rstrip()