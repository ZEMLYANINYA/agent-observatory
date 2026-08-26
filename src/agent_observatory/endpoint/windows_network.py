from __future__ import annotations

import json
import subprocess

from .network import TcpConnection


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

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    return result.stdout


def parse_tcp_inventory(raw: str) -> tuple[TcpConnection, ...]:
    raw = raw.strip()

    if not raw:
        return ()

    records = json.loads(raw)

    if isinstance(records, dict):
        records = [records]

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


def collect_tcp_connections() -> tuple[TcpConnection, ...]:
    return parse_tcp_inventory(
        _powershell_tcp_inventory()
    )