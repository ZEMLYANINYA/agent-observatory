from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from .identity import capture_identity_key
from .models import ProcessSnapshot
from .network import TcpConnection
from .windows_network import parse_tcp_records
from .windows_snapshot import parse_process_records


@dataclass(frozen=True, slots=True)
class CaptureInterval:
    started_at: float
    finished_at: float

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.finished_at - self.started_at)


@dataclass(frozen=True, slots=True)
class WindowsCapture:
    processes_before: tuple[ProcessSnapshot, ...]
    tcp_connections: tuple[TcpConnection, ...]
    processes_after: tuple[ProcessSnapshot, ...]
    process_before_interval: CaptureInterval
    network_interval: CaptureInterval
    process_after_interval: CaptureInterval

    @property
    def total_duration_seconds(self) -> float:
        return max(
            0.0,
            (
                self.process_after_interval.finished_at
                - self.process_before_interval.started_at
            ),
        )


def _powershell_capture_inventory() -> str:
    command = r"""
$collectProcesses = {
    Get-CimInstance Win32_Process |
    Select-Object `
        @{Name='pid';Expression={$_.ProcessId}},
        @{Name='ppid';Expression={$_.ParentProcessId}},
        @{Name='name';Expression={$_.Name}},
        @{Name='started_at';Expression={
            if ($_.CreationDate) {
                $_.CreationDate.ToUniversalTime().ToString("o")
            }
            else {
                $null
            }
        }},
        @{Name='command_line';Expression={$_.CommandLine}},
        @{Name='executable_path';Expression={$_.ExecutablePath}}
}

$processBeforeStartedAt = [DateTime]::UtcNow
$processesBefore = @(& $collectProcesses)
$processBeforeFinishedAt = [DateTime]::UtcNow

$networkStartedAt = [DateTime]::UtcNow
$tcpConnections = @(
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
    Select-Object `
        @{Name='pid';Expression={$_.OwningProcess}},
        @{Name='state';Expression={$_.State.ToString()}},
        @{Name='local_address';Expression={$_.LocalAddress}},
        @{Name='local_port';Expression={$_.LocalPort}},
        @{Name='remote_address';Expression={$_.RemoteAddress}},
        @{Name='remote_port';Expression={$_.RemotePort}}
)
$networkFinishedAt = [DateTime]::UtcNow

$processAfterStartedAt = [DateTime]::UtcNow
$processesAfter = @(& $collectProcesses)
$processAfterFinishedAt = [DateTime]::UtcNow

[PSCustomObject]@{
    process_before_started_at = $processBeforeStartedAt.ToString("o")
    process_before_finished_at = $processBeforeFinishedAt.ToString("o")
    network_started_at = $networkStartedAt.ToString("o")
    network_finished_at = $networkFinishedAt.ToString("o")
    process_after_started_at = $processAfterStartedAt.ToString("o")
    process_after_finished_at = $processAfterFinishedAt.ToString("o")
    processes_before = $processesBefore
    tcp_connections = $tcpConnections
    processes_after = $processesAfter
} | ConvertTo-Json -Compress -Depth 5
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


def _timestamp(value: Any) -> float:
    return datetime.fromisoformat(
        str(value).replace("Z", "+00:00")
    ).timestamp()


def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []

    if isinstance(value, dict):
        return [value]

    if isinstance(value, list):
        return value

    raise TypeError(
        f"expected capture records to be a list or object, got {type(value).__name__}"
    )


def parse_windows_capture(raw: str) -> WindowsCapture:
    raw = raw.strip()

    if not raw:
        raise ValueError("empty Windows capture")

    payload = json.loads(raw)

    if not isinstance(payload, dict):
        raise ValueError("Windows capture must be a JSON object")

    return WindowsCapture(
        processes_before=parse_process_records(
            _records(payload.get("processes_before"))
        ),
        tcp_connections=parse_tcp_records(
            _records(payload.get("tcp_connections"))
        ),
        processes_after=parse_process_records(
            _records(payload.get("processes_after"))
        ),
        process_before_interval=CaptureInterval(
            started_at=_timestamp(payload["process_before_started_at"]),
            finished_at=_timestamp(payload["process_before_finished_at"]),
        ),
        network_interval=CaptureInterval(
            started_at=_timestamp(payload["network_started_at"]),
            finished_at=_timestamp(payload["network_finished_at"]),
        ),
        process_after_interval=CaptureInterval(
            started_at=_timestamp(payload["process_after_started_at"]),
            finished_at=_timestamp(payload["process_after_finished_at"]),
        ),
    )


def collect_windows_capture() -> WindowsCapture:
    return parse_windows_capture(
        _powershell_capture_inventory()
    )


def same_process_instance(
    before: ProcessSnapshot,
    after: ProcessSnapshot,
) -> bool:
    """
    Conservatively decide whether two snapshots represent the same process.

    The comparison uses PID, PPID, creation time, executable name/path, and an
    exact command-line digest. File hashing is intentionally excluded from this
    time-sensitive guard and is performed after capture when requested.
    """

    return capture_identity_key(before) == capture_identity_key(after)


def stable_processes(
    capture: WindowsCapture,
) -> tuple[ProcessSnapshot, ...]:
    after_by_pid = {
        process.pid: process
        for process in capture.processes_after
    }

    return tuple(
        process
        for process in capture.processes_before
        if (
            (after := after_by_pid.get(process.pid)) is not None
            and same_process_instance(process, after)
        )
    )


def attributable_tcp_connections(
    capture: WindowsCapture,
) -> tuple[TcpConnection, ...]:
    stable_pids = {
        process.pid
        for process in stable_processes(capture)
    }

    return tuple(
        connection
        for connection in capture.tcp_connections
        if connection.pid in stable_pids
    )


def rejected_tcp_connections(
    capture: WindowsCapture,
    process_ids: Iterable[int] | None = None,
) -> tuple[TcpConnection, ...]:
    stable_pids = {
        process.pid
        for process in stable_processes(capture)
    }
    candidate_pids = (
        set(process_ids)
        if process_ids is not None
        else {
            connection.pid
            for connection in capture.tcp_connections
        }
    )

    return tuple(
        connection
        for connection in capture.tcp_connections
        if (
            connection.pid in candidate_pids
            and connection.pid not in stable_pids
        )
    )
