from __future__ import annotations

import json
from typing import Any, Iterable

from .network import TcpConnection
from .windows_powershell import run_powershell_text


def _powershell_tcp_inventory() -> str:
    command = r"""
Get-NetTCPConnection -ErrorAction SilentlyContinue |
Select-Object `
    @{Name='pid';Expression={$_.OwningProcess}},
    @{Name='state';Expression={$_.State.ToString()}},
    @{Name='local_address';Expression={$_.LocalAddress}},
    @{Name='local_port';Expression={$_.LocalPort}},
    @{Name='remote_address';Expression={$_.RemoteAddress}},
    @{Name='remote_port';Expression={$_.RemotePort}} |
ConvertTo-Json -Compress
"""

    return run_powershell_text(command)


def parse_tcp_records(
    records: Iterable[dict[str, Any]],
) -> tuple[TcpConnection, ...]:
    connections: list[TcpConnection] = []

    for record in records:
        connections.append(
            TcpConnection(
                pid=int(record["pid"]),
                state=str(record["state"]),
                local_address=str(record["local_address"]),
                local_port=int(record["local_port"]),
                remote_address=str(record["remote_address"]),
                remote_port=int(record["remote_port"]),
            )
        )

    return tuple(connections)


def parse_tcp_inventory(raw: str) -> tuple[TcpConnection, ...]:
    raw = raw.strip()

    if not raw:
        return ()

    records = json.loads(raw)

    if isinstance(records, dict):
        records = [records]

    return parse_tcp_records(records)


def collect_tcp_connections() -> tuple[TcpConnection, ...]:
    return parse_tcp_inventory(
        _powershell_tcp_inventory()
    )
