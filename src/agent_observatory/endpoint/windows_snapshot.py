from __future__ import annotations

import subprocess
from datetime import datetime
from typing import Iterable

from .application_models import ApplicationSnapshot
from .discovery import discover_root_processes
from .models import ProcessSnapshot
from .process_tree import build_validated_process_tree
from .roles import classify_process_role


def _powershell_process_inventory() -> str:
    command = r"""
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
    @{Name='command_line';Expression={$_.CommandLine}} |
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


def collect_processes() -> tuple[ProcessSnapshot, ...]:
    import json

    raw = _powershell_process_inventory().strip()

    if not raw:
        return ()

    records = json.loads(raw)

    if isinstance(records, dict):
        records = [records]

    processes: list[ProcessSnapshot] = []

    for record in records:
        started_at = record.get("started_at")

        if not started_at:
            continue

        dt = datetime.fromisoformat(
            started_at.replace("Z", "+00:00")
        )

        processes.append(
            ProcessSnapshot(
                pid=int(record["pid"]),
                ppid=int(record["ppid"]),
                name=str(record["name"]),
                started_at=dt.timestamp(),
                command_line=record.get("command_line"),
            )
        )

    return tuple(processes)


def _walk_validated_descendants(
    root_pid: int,
    tree: dict[int, tuple[ProcessSnapshot, ...]],
) -> tuple[ProcessSnapshot, ...]:
    result: list[ProcessSnapshot] = []
    queue = [root_pid]

    while queue:
        parent_pid = queue.pop(0)

        for child in tree.get(parent_pid, ()):
            result.append(child)
            queue.append(child.pid)

    return tuple(result)


def collect_application_snapshots(
    processes: Iterable[ProcessSnapshot] | None = None,
) -> tuple[ApplicationSnapshot, ...]:
    process_list = tuple(
        processes
        if processes is not None
        else collect_processes()
    )

    by_pid = {
        process.pid: process
        for process in process_list
    }

    applications = discover_root_processes(process_list)
    validated_tree, _rejected = build_validated_process_tree(process_list)

    snapshots: list[ApplicationSnapshot] = []

    for application in applications:
        root = by_pid.get(application.root_process.pid)

        if root is None:
            continue

        descendants = _walk_validated_descendants(
            root.pid,
            validated_tree,
        )

        snapshots.append(
            ApplicationSnapshot(
                application=application,
                processes=(root, *descendants),
            )
        )

    return tuple(snapshots)


def format_snapshot(
    snapshots: Iterable[ApplicationSnapshot],
) -> str:
    lines: list[str] = []

    for snapshot in snapshots:
        lines.append(
            f"{snapshot.application.profile.name} "
            f"(root PID {snapshot.application.root_process.pid})"
        )

        for process in snapshot.processes:
            role = classify_process_role(
                process.command_line,
                is_root=(
                    process.pid
                    == snapshot.application.root_process.pid
                ),
            )

            lines.append(
                f" PID={process.pid:<6} "
                f"PPID={process.ppid:<6} "
                f"ROLE={role.value:<13} "
                f"{process.name}"
            )
        lines.append("")

    return "\n".join(lines).rstrip()


def main() -> int:
    snapshots = collect_application_snapshots()

    if not snapshots:
        print("No configured AI desktop applications detected.")
        return 1

    print(format_snapshot(snapshots))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())