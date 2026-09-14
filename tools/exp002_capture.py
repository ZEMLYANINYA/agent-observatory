from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from agent_observatory.endpoint.identity import build_process_identities
from agent_observatory.endpoint.network import TcpConnection, connections_by_pid
from agent_observatory.endpoint.roles import classify_process_role
from agent_observatory.endpoint.windows_capture import (
    WindowsCapture,
    attributable_tcp_connections,
    collect_windows_capture,
    rejected_tcp_connections,
    stable_processes,
)
from agent_observatory.endpoint.windows_snapshot import collect_application_snapshots


OUTPUT_DIR = Path(".local") / "exp002"
VALID_STATES = {
    "STARTUP",
    "IDLE",
    "ACTIVE_QUERY",
    "POST_ACTION_IDLE",
    "CORESIDENCY",
}


def _utc_iso(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _capture_intervals(capture: WindowsCapture) -> dict[str, object]:
    def interval_payload(interval):
        return {
            "started_at": _utc_iso(interval.started_at),
            "finished_at": _utc_iso(interval.finished_at),
            "duration_seconds": interval.duration_seconds,
        }

    return {
        "process_before": interval_payload(capture.process_before_interval),
        "network": interval_payload(capture.network_interval),
        "process_after": interval_payload(capture.process_after_interval),
        "total_duration_seconds": capture.total_duration_seconds,
    }


def _connection_payload(connection: TcpConnection) -> dict[str, object]:
    return {
        "state": connection.state,
        "local_address": connection.local_address,
        "local_port": connection.local_port,
        "remote_address": connection.remote_address,
        "remote_port": connection.remote_port,
    }


def _application_payload(snapshot, connections: Iterable[TcpConnection], capture):
    grouped_connections = connections_by_pid(connections)
    identities = {
        identity.pid: identity
        for identity in build_process_identities(snapshot.processes)
    }

    root_pid = snapshot.application.root_process.pid
    process_ids = {process.pid for process in snapshot.processes}
    rejected = rejected_tcp_connections(capture, process_ids)

    processes = []

    for process in snapshot.processes:
        identity = identities[process.pid]
        role = classify_process_role(
            process.command_line,
            is_root=(process.pid == root_pid),
        )

        processes.append(
            {
                "pid": process.pid,
                "ppid": process.ppid,
                "started_at": _utc_iso(process.started_at),
                "name": process.name,
                "role": role.value,
                "command_line_sha256": identity.command_line_sha256,
                "executable": {
                    "path": identity.executable.path,
                    "sha256": identity.executable.sha256,
                    "hash_state": identity.executable.hash_state.value,
                },
                "tcp_connections": [
                    _connection_payload(connection)
                    for connection in grouped_connections.get(process.pid, ())
                ],
            }
        )

    return {
        "application": snapshot.application.profile.name,
        "root_pid": root_pid,
        "process_count": len(snapshot.processes),
        "attribution_guard_rejected_tcp_count": len(rejected),
        "processes": processes,
    }


def build_evidence(target: str, state: str) -> dict[str, object]:
    capture = collect_windows_capture()
    stable = stable_processes(capture)
    snapshots = collect_application_snapshots(stable)
    attributable = attributable_tcp_connections(capture)

    if target.casefold() == "all":
        selected = snapshots
    else:
        selected = tuple(
            snapshot
            for snapshot in snapshots
            if snapshot.application.profile.name.casefold() == target.casefold()
        )

        if not selected:
            discovered = ", ".join(
                snapshot.application.profile.name
                for snapshot in snapshots
            ) or "none"
            raise ValueError(
                f"application {target!r} not discovered; discovered: {discovered}"
            )

        if len(selected) > 1:
            raise ValueError(
                f"application {target!r} matched multiple roots; capture separately"
            )

    selected_pids = {
        process.pid
        for snapshot in selected
        for process in snapshot.processes
    }
    selected_connections = tuple(
        connection
        for connection in attributable
        if connection.pid in selected_pids
    )

    return {
        "schema_version": 1,
        "experiment": "EXP-002",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "state": state,
        "capture": _capture_intervals(capture),
        "applications": [
            _application_payload(snapshot, selected_connections, capture)
            for snapshot in selected
        ],
    }


def save_evidence(evidence: dict[str, object]) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = str(evidence["target"]).casefold().replace(" ", "-")
    state = str(evidence["state"]).casefold().replace("_", "-")
    path = OUTPUT_DIR / f"{timestamp}-{target}-{state}.json"

    path.write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture structured EXP-002 multi-client evidence."
    )
    parser.add_argument(
        "target",
        help="Application profile name (Claude, Codex, Gemini, Manus, Perplexity) or 'all'.",
    )
    parser.add_argument(
        "state",
        help="STARTUP, IDLE, ACTIVE_QUERY, POST_ACTION_IDLE, or CORESIDENCY.",
    )
    args = parser.parse_args()

    state = args.state.upper().replace("-", "_")

    if state not in VALID_STATES:
        parser.error(
            "state must be one of: " + ", ".join(sorted(VALID_STATES))
        )

    try:
        evidence = build_evidence(args.target, state)
    except ValueError as exc:
        print(f"Capture failed: {exc}")
        return 2

    path = save_evidence(evidence)

    print(f"EXP-002 evidence saved: {path}")

    for application in evidence["applications"]:
        tcp_count = sum(
            len(process["tcp_connections"])
            for process in application["processes"]
        )
        unknown_count = sum(
            1
            for process in application["processes"]
            if process["role"] == "unknown"
        )
        print(
            f"{application['application']}: "
            f"processes={application['process_count']} "
            f"tcp={tcp_count} "
            f"unknown={unknown_count} "
            f"guard_rejected={application['attribution_guard_rejected_tcp_count']}"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
