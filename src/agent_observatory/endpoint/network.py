from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True, slots=True)
class TcpConnection:
    pid: int
    state: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int

    @property
    def is_established(self) -> bool:
        return self.state.casefold() == "established"


def connections_by_pid(
    connections: Iterable[TcpConnection],
) -> dict[int, tuple[TcpConnection, ...]]:
    grouped: dict[int, list[TcpConnection]] = {}

    for connection in connections:
        grouped.setdefault(connection.pid, []).append(connection)

    return {
        pid: tuple(items)
        for pid, items in grouped.items()
    }


def connections_for_processes(
    connections: Iterable[TcpConnection],
    process_ids: Iterable[int],
) -> tuple[TcpConnection, ...]:
    allowed_pids = set(process_ids)

    return tuple(
        connection
        for connection in connections
        if connection.pid in allowed_pids
    )