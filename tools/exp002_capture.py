from __future__ import annotations

import argparse
import json
import threading
import time
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
DEFAULT_BURST_INTERVAL_SECONDS = 1.0
DEFAULT_POST_DELAYS_SECONDS = (2.0, 5.0, 15.0, 60.0)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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


def _file_identity_payload(file_identity) -> dict[str, int] | None:
    if file_identity is None:
        return None

    return {
        "volume_serial": file_identity.volume_serial,
        "file_id": file_identity.file_id,
    }


def _hash_observation_payload(hash_observation) -> dict[str, object]:
    return {
        "sha256": hash_observation.sha256,
        "state": hash_observation.state.value,
        "observed_at": (
            _utc_iso(hash_observation.observed_at)
            if hash_observation.observed_at is not None
            else None
        ),
        "hash_gap_ms": hash_observation.hash_gap_ms,
    }


def _application_payload(
    snapshot,
    connections: Iterable[TcpConnection],
    capture: WindowsCapture,
    identities_by_pid,
):
    grouped_connections = connections_by_pid(connections)

    root_pid = snapshot.application.root_process.pid
    process_ids = {process.pid for process in snapshot.processes}
    rejected = rejected_tcp_connections(capture, process_ids)

    processes = []

    for process in snapshot.processes:
        identity = identities_by_pid[process.pid]
        role = classify_process_role(
            process.command_line,
            is_root=(process.pid == root_pid),
        )
        executable = identity.executable

        processes.append(
            {
                "pid": process.pid,
                "ppid": process.ppid,
                "started_at": _utc_iso(process.started_at),
                "name": process.name,
                "role": role.value,
                "command_line_sha256": identity.command_line_sha256,
                "executable": {
                    "path": executable.path,
                    "file_identity": _file_identity_payload(
                        executable.file_identity
                    ),
                    "hash_observation": _hash_observation_payload(
                        executable.hash_observation
                    ),
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

    selected_processes = tuple(
        process
        for snapshot in selected
        for process in snapshot.processes
    )
    selected_pids = {
        process.pid
        for process in selected_processes
    }
    selected_connections = tuple(
        connection
        for connection in attributable
        if connection.pid in selected_pids
    )
    identities_by_pid = {
        identity.pid: identity
        for identity in build_process_identities(
            selected_processes,
            process_observed_at=capture.process_before_interval.finished_at,
        )
    }

    return {
        "schema_version": 2,
        "experiment": "EXP-002",
        "captured_at": _utc_now_iso(),
        "target": target,
        "state": state,
        "capture": _capture_intervals(capture),
        "hash_timing": {
            "process_observation_anchor": "capture.process_before.finished_at",
            "note": (
                "hash_gap_ms is measured from the end of the pre-network process "
                "inventory to executable hash start. Exact per-process CIM row "
                "observation timestamps are not available."
            ),
        },
        "applications": [
            _application_payload(
                snapshot,
                selected_connections,
                capture,
                identities_by_pid,
            )
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


def _parse_post_delays(raw: str) -> tuple[float, ...]:
    try:
        values = tuple(float(value.strip()) for value in raw.split(",") if value.strip())
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "post delays must be comma-separated numbers of seconds"
        ) from exc

    if not values:
        raise argparse.ArgumentTypeError("at least one post delay is required")

    if any(value < 0 for value in values):
        raise argparse.ArgumentTypeError("post delays must be non-negative")

    if tuple(sorted(values)) != values:
        raise argparse.ArgumentTypeError("post delays must be in ascending order")

    return values


def _session_path(target: str) -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_target = target.casefold().replace(" ", "-")
    return OUTPUT_DIR / f"{timestamp}-{safe_target}-transition-query.json"


def _persist_transition(path: Path, session: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(session, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _relative_ms(origin_ns: int | None, value_ns: int) -> float | None:
    if origin_ns is None:
        return None
    return round((value_ns - origin_ns) / 1_000_000, 3)


def _event_payload(
    event_type: str,
    *,
    monotonic_ns: int,
    query_origin_ns: int | None,
    source: str = "operator",
) -> dict[str, object]:
    return {
        "type": event_type,
        "source": source,
        "observed_at": _utc_now_iso(),
        "monotonic_ns": monotonic_ns,
        "t_relative_ms": _relative_ms(query_origin_ns, monotonic_ns),
    }


def _capture_summary(evidence: dict[str, object]) -> dict[str, int]:
    applications = evidence["applications"]
    process_count = sum(
        int(application["process_count"])
        for application in applications
    )
    tcp_count = sum(
        len(process["tcp_connections"])
        for application in applications
        for process in application["processes"]
    )
    unknown_count = sum(
        1
        for application in applications
        for process in application["processes"]
        if process["role"] == "unknown"
    )
    guard_rejected_count = sum(
        int(application["attribution_guard_rejected_tcp_count"])
        for application in applications
    )
    non_hashed_count = sum(
        1
        for application in applications
        for process in application["processes"]
        if process["executable"]["hash_observation"]["state"] != "hashed"
    )
    return {
        "process_count": process_count,
        "tcp_count": tcp_count,
        "unknown_count": unknown_count,
        "guard_rejected_tcp_count": guard_rejected_count,
        "non_hashed_count": non_hashed_count,
    }


def _transition_observation(
    target: str,
    phase: str,
    sequence: int,
    query_origin_ns: int | None,
) -> dict[str, object]:
    started_ns = time.monotonic_ns()
    observation: dict[str, object] = {
        "sequence": sequence,
        "phase": phase,
        "observed_at": _utc_now_iso(),
        "monotonic_ns": started_ns,
        "t_relative_ms": _relative_ms(query_origin_ns, started_ns),
    }

    try:
        evidence = build_evidence(target, phase)
    except ValueError as exc:
        observation.update(
            {
                "status": "discovery_empty",
                "error": str(exc),
            }
        )
        return observation
    except Exception as exc:
        observation.update(
            {
                "status": "capture_error",
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        return observation

    observation.update(
        {
            "status": "ok",
            "summary": _capture_summary(evidence),
            "evidence": evidence,
        }
    )
    return observation


def _print_transition_observation(observation: dict[str, object]) -> None:
    relative = observation["t_relative_ms"]
    relative_text = "pre-query" if relative is None else f"{relative / 1000:+.3f}s"
    phase = observation["phase"]
    status = observation["status"]

    if status != "ok":
        print(f"{relative_text:>12}  {phase:<20} {status}: {observation['error']}")
        return

    summary = observation["summary"]
    print(
        f"{relative_text:>12}  {phase:<20} "
        f"processes={summary['process_count']} "
        f"tcp={summary['tcp_count']} "
        f"unknown={summary['unknown_count']} "
        f"non_hashed={summary['non_hashed_count']} "
        f"guard_rejected={summary['guard_rejected_tcp_count']}"
    )


def _append_observation(
    session: dict[str, object],
    path: Path,
    *,
    target: str,
    phase: str,
    query_origin_ns: int | None,
) -> None:
    observations = session["observations"]
    observation = _transition_observation(
        target,
        phase,
        len(observations) + 1,
        query_origin_ns,
    )
    observations.append(observation)
    _persist_transition(path, session)
    _print_transition_observation(observation)


def _append_event(
    session: dict[str, object],
    path: Path,
    event_type: str,
    *,
    monotonic_ns: int,
    query_origin_ns: int | None,
) -> None:
    session["events"].append(
        _event_payload(
            event_type,
            monotonic_ns=monotonic_ns,
            query_origin_ns=query_origin_ns,
        )
    )
    _persist_transition(path, session)


def _wait_until_monotonic(target_ns: int) -> None:
    while True:
        remaining = (target_ns - time.monotonic_ns()) / 1_000_000_000
        if remaining <= 0:
            return
        time.sleep(min(remaining, 0.1))


def run_transition_query(
    target: str,
    *,
    interval_seconds: float,
    post_delays_seconds: tuple[float, ...],
) -> int:
    if target.casefold() == "all":
        print("Transition-query mode requires one application target, not 'all'.")
        return 2

    session_started_ns = time.monotonic_ns()
    path = _session_path(target)
    session: dict[str, object] = {
        "schema_version": 3,
        "experiment": "EXP-002",
        "mode": "transition_query",
        "target": target,
        "started_at": _utc_now_iso(),
        "monotonic_origin_ns": session_started_ns,
        "embedded_evidence_schema_version": 2,
        "capture_policy": {
            "burst_interval_seconds": interval_seconds,
            "post_response_delays_seconds": list(post_delays_seconds),
            "operator_events": [
                "QUERY_SENT",
                "RESPONSE_COMPLETE",
            ],
            "semantic_note": (
                "Operator events are markers, not proof of server-side inference state."
            ),
        },
        "events": [],
        "observations": [],
        "status": "running",
    }
    _persist_transition(path, session)

    print(f"EXP-002 transition session: {path}")
    print()
    print(f"1. Start {target} and let it settle.")
    input("2. Press ENTER when the application is ready for the pre-query capture... ")

    _append_observation(
        session,
        path,
        target=target,
        phase="PRE_QUERY_IDLE",
        query_origin_ns=None,
    )

    print()
    print(f"3. Send the test prompt in {target}.")
    input("4. Press ENTER immediately after sending the prompt... ")

    query_origin_ns = time.monotonic_ns()
    _append_event(
        session,
        path,
        "QUERY_SENT",
        monotonic_ns=query_origin_ns,
        query_origin_ns=query_origin_ns,
    )

    print()
    print(
        f"Automatic capture started every {interval_seconds:g}s. "
        "Press ENTER when the response is visibly complete."
    )

    response_complete = threading.Event()

    def wait_for_response_complete() -> None:
        input()
        response_complete.set()

    input_thread = threading.Thread(
        target=wait_for_response_complete,
        name="exp002-response-complete",
        daemon=True,
    )
    input_thread.start()

    next_capture_ns = query_origin_ns
    interval_ns = max(1, int(interval_seconds * 1_000_000_000))

    try:
        while not response_complete.is_set():
            _wait_until_monotonic(next_capture_ns)
            if response_complete.is_set():
                break

            _append_observation(
                session,
                path,
                target=target,
                phase="QUERY_WINDOW",
                query_origin_ns=query_origin_ns,
            )
            next_capture_ns += interval_ns

            now_ns = time.monotonic_ns()
            if next_capture_ns <= now_ns:
                next_capture_ns = now_ns + interval_ns

        response_complete_ns = time.monotonic_ns()
        _append_event(
            session,
            path,
            "RESPONSE_COMPLETE",
            monotonic_ns=response_complete_ns,
            query_origin_ns=query_origin_ns,
        )

        print()
        print("Response complete marker recorded. Starting scheduled post-response captures.")

        for delay_seconds in post_delays_seconds:
            scheduled_ns = response_complete_ns + int(delay_seconds * 1_000_000_000)
            _wait_until_monotonic(scheduled_ns)
            phase = "IDLE_LONG" if delay_seconds >= 30 else "POST_RESPONSE"
            _append_observation(
                session,
                path,
                target=target,
                phase=phase,
                query_origin_ns=query_origin_ns,
            )

    except KeyboardInterrupt:
        interrupted_ns = time.monotonic_ns()
        session["events"].append(
            _event_payload(
                "INTERRUPTED",
                monotonic_ns=interrupted_ns,
                query_origin_ns=query_origin_ns,
                source="operator",
            )
        )
        session["status"] = "interrupted"
        session["finished_at"] = _utc_now_iso()
        _persist_transition(path, session)
        print(f"\nSession interrupted; partial evidence preserved: {path}")
        return 130

    session["status"] = "complete"
    session["finished_at"] = _utc_now_iso()
    _persist_transition(path, session)

    ok_count = sum(
        1 for observation in session["observations"]
        if observation["status"] == "ok"
    )
    failed_count = len(session["observations"]) - ok_count
    print()
    print(
        f"EXP-002 transition evidence saved: {path} "
        f"(observations={len(session['observations'])}, "
        f"ok={ok_count}, non_ok={failed_count})"
    )
    return 0


def _run_single_capture(target: str, state: str) -> int:
    try:
        evidence = build_evidence(target, state)
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
        non_hashed_count = sum(
            1
            for process in application["processes"]
            if process["executable"]["hash_observation"]["state"] != "hashed"
        )
        print(
            f"{application['application']}: "
            f"processes={application['process_count']} "
            f"tcp={tcp_count} "
            f"unknown={unknown_count} "
            f"non_hashed={non_hashed_count} "
            f"guard_rejected={application['attribution_guard_rejected_tcp_count']}"
        )

    return 0


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
        nargs="?",
        help="STARTUP, IDLE, ACTIVE_QUERY, POST_ACTION_IDLE, or CORESIDENCY.",
    )
    parser.add_argument(
        "--transition-query",
        action="store_true",
        help=(
            "Run an operator-marked query transition session with automatic "
            "burst and post-response captures."
        ),
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_BURST_INTERVAL_SECONDS,
        help=(
            "Seconds between automatic query-window captures "
            f"(default: {DEFAULT_BURST_INTERVAL_SECONDS:g})."
        ),
    )
    parser.add_argument(
        "--post-delays",
        type=_parse_post_delays,
        default=DEFAULT_POST_DELAYS_SECONDS,
        metavar="SECONDS",
        help=(
            "Comma-separated post-response capture delays "
            "(default: 2,5,15,60)."
        ),
    )
    args = parser.parse_args()

    if args.transition_query:
        if args.state is not None:
            parser.error("state cannot be used together with --transition-query")
        if args.interval <= 0:
            parser.error("--interval must be greater than zero")
        return run_transition_query(
            args.target,
            interval_seconds=args.interval,
            post_delays_seconds=args.post_delays,
        )

    if args.state is None:
        parser.error("state is required unless --transition-query is used")

    state = args.state.upper().replace("-", "_")

    if state not in VALID_STATES:
        parser.error(
            "state must be one of: " + ", ".join(sorted(VALID_STATES))
        )

    return _run_single_capture(args.target, state)


if __name__ == "__main__":
    raise SystemExit(main())
