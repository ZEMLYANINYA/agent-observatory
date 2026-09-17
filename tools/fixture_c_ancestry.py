from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from agent_observatory.endpoint.discovery import DEFAULT_PROFILES
from agent_observatory.endpoint.models import RelationBasis, RelationState
from agent_observatory.endpoint.process_tree import build_capture_parent_relations
from agent_observatory.endpoint.windows_capture import (
    CaptureInterval,
    WindowsCapture,
    same_process_instance,
)
from agent_observatory.endpoint.windows_snapshot import (
    collect_application_snapshots,
    collect_processes,
)
from agent_observatory.evidence import windows_capture_event_batch
from agent_observatory.storage import EventStore, EventType


DEFAULT_SESSION_ROOT = Path(tempfile.gettempdir()) / "agent-observatory-fixture-c"
DEFAULT_DB_PATH = Path(".local") / "fixture-c.sqlite3"
DEFAULT_SOURCE = "fixture-c-ancestry"


class FixtureContractError(RuntimeError):
    """Raised when the controlled Fixture C ancestry contract is not observed."""


@dataclass(frozen=True, slots=True)
class FixtureEvaluation:
    agent_name: str
    agent_root_pid: int
    powershell_pid: int
    powershell_started_at: float
    child_pid: int
    child_started_at: float
    relation_state: str
    relation_basis: str


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _canonical_agent_name(value: str) -> str:
    configured = {profile.name.casefold(): profile.name for profile in DEFAULT_PROFILES}
    canonical = configured.get(value.strip().casefold())
    if canonical is None:
        raise ValueError(
            "unknown agent target; configured targets: "
            + ", ".join(profile.name for profile in DEFAULT_PROFILES)
        )
    return canonical


def _capture_process_inventory() -> tuple[tuple, CaptureInterval]:
    started_at = time.time()
    processes = collect_processes()
    finished_at = time.time()
    return processes, CaptureInterval(started_at, finished_at)


def _process_by_pid(processes, pid: int):
    return next((process for process in processes if process.pid == pid), None)


def _agent_snapshot_containing(
    processes,
    *,
    agent_name: str,
    required_pids: set[int],
):
    matches = []
    for snapshot in collect_application_snapshots(processes):
        if snapshot.application.profile.name.casefold() != agent_name.casefold():
            continue
        pids = {process.pid for process in snapshot.processes}
        if required_pids <= pids:
            matches.append(snapshot)

    if not matches:
        raise FixtureContractError(
            "fixture processes were not observed inside the requested agent pre-capture tree"
        )
    if len(matches) > 1:
        raise FixtureContractError(
            "fixture processes matched more than one requested agent root"
        )
    return matches[0]


def _validate_before_snapshot(
    processes,
    *,
    agent_name: str,
    powershell_pid: int,
    child_pid: int,
):
    powershell = _process_by_pid(processes, powershell_pid)
    child = _process_by_pid(processes, child_pid)

    if powershell is None:
        raise FixtureContractError("PowerShell intermediary is missing from before snapshot")
    if powershell.name.casefold() != "powershell.exe":
        raise FixtureContractError(
            f"intermediary PID {powershell_pid} is {powershell.name!r}, expected powershell.exe"
        )
    if child is None:
        raise FixtureContractError("fixture child is missing from before snapshot")
    if child.ppid != powershell_pid:
        raise FixtureContractError(
            f"fixture child PPID {child.ppid} does not match PowerShell PID {powershell_pid}"
        )

    snapshot = _agent_snapshot_containing(
        processes,
        agent_name=agent_name,
        required_pids={powershell_pid, child_pid},
    )
    return powershell, child, snapshot


def evaluate_fixture_capture(
    capture: WindowsCapture,
    *,
    agent_name: str,
    powershell_pid: int,
    child_pid: int,
) -> FixtureEvaluation:
    powershell_before, child_before, snapshot = _validate_before_snapshot(
        capture.processes_before,
        agent_name=agent_name,
        powershell_pid=powershell_pid,
        child_pid=child_pid,
    )

    agent_root_before = snapshot.application.root_process
    agent_root_after = _process_by_pid(capture.processes_after, agent_root_before.pid)
    if agent_root_after is None or not same_process_instance(
        agent_root_before,
        agent_root_after,
    ):
        raise FixtureContractError(
            "requested agent root did not remain the same stable process instance"
        )

    if _process_by_pid(capture.processes_after, powershell_pid) is not None:
        raise FixtureContractError("PowerShell intermediary is still present after release")

    child_after = _process_by_pid(capture.processes_after, child_pid)
    if child_after is None:
        raise FixtureContractError("fixture child did not survive into the after snapshot")
    if not same_process_instance(child_before, child_after):
        raise FixtureContractError("fixture child PID no longer refers to the same process instance")

    relation = next(
        (
            item
            for item in build_capture_parent_relations(
                capture.processes_before,
                capture.processes_after,
            )
            if item.child_pid == child_pid
        ),
        None,
    )
    if relation is None:
        raise FixtureContractError("no parent relation was produced for the fixture child")
    if relation.state is not RelationState.VALID:
        raise FixtureContractError(
            f"fixture child relation is {relation.state.value}, expected valid"
        )
    if relation.basis is not RelationBasis.PARENT_OBSERVED_BEFORE_ONLY:
        raise FixtureContractError(
            f"fixture child relation basis is {relation.basis.value}, "
            "expected parent_observed_before_only"
        )

    return FixtureEvaluation(
        agent_name=agent_name,
        agent_root_pid=agent_root_before.pid,
        powershell_pid=powershell_before.pid,
        powershell_started_at=powershell_before.started_at,
        child_pid=child_before.pid,
        child_started_at=child_before.started_at,
        relation_state=relation.state.value,
        relation_basis=relation.basis.value,
    )


def _fixture_relationship_event(events, child_pid: int):
    relationship_events = tuple(
        event
        for event in events
        if (
            event.event_type is EventType.PROCESS_RELATIONSHIP_OBSERVED
            and isinstance(event.payload.get("child"), dict)
            and event.payload["child"].get("pid") == child_pid
        )
    )
    if len(relationship_events) != 1:
        raise FixtureContractError(
            "expected exactly one relationship event for fixture child"
        )

    relationship_event = relationship_events[0]
    if relationship_event.payload.get("state") != RelationState.VALID.value:
        raise FixtureContractError("fixture relationship event is not valid")
    if (
        relationship_event.payload.get("basis")
        != RelationBasis.PARENT_OBSERVED_BEFORE_ONLY.value
    ):
        raise FixtureContractError(
            "fixture relationship event did not preserve before-only parent basis"
        )
    return relationship_event


def _wait_for_ready(path: Path, timeout_seconds: float) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8-sig"))
            if not isinstance(payload, dict):
                raise FixtureContractError("ready.json must contain one JSON object")
            return payload
        time.sleep(0.05)
    raise FixtureContractError("timed out waiting for the agent-triggered PowerShell fixture")


def _wait_for_before_snapshot(
    *,
    agent_name: str,
    powershell_pid: int,
    child_pid: int,
    timeout_seconds: float,
):
    deadline = time.monotonic() + timeout_seconds
    last_error: Exception | None = None

    while time.monotonic() < deadline:
        processes, interval = _capture_process_inventory()
        try:
            _validate_before_snapshot(
                processes,
                agent_name=agent_name,
                powershell_pid=powershell_pid,
                child_pid=child_pid,
            )
            return processes, interval
        except FixtureContractError as exc:
            last_error = exc
            time.sleep(0.1)

    raise FixtureContractError(
        "timed out waiting for a valid pre-capture agent/PowerShell/child tree: "
        f"{last_error or 'unknown state'}"
    )


def _wait_for_after_snapshot(
    *,
    child_before,
    powershell_pid: int,
    child_pid: int,
    timeout_seconds: float,
):
    deadline = time.monotonic() + timeout_seconds
    last_reason = "no after snapshot collected"

    while time.monotonic() < deadline:
        processes, interval = _capture_process_inventory()
        powershell = _process_by_pid(processes, powershell_pid)
        child = _process_by_pid(processes, child_pid)

        if powershell is None and child is not None and same_process_instance(child_before, child):
            return processes, interval

        if powershell is not None:
            last_reason = "PowerShell intermediary still present"
        elif child is None:
            last_reason = "fixture child missing"
        else:
            last_reason = "child PID no longer identifies the same process instance"
        time.sleep(0.1)

    raise FixtureContractError(f"timed out waiting for after snapshot: {last_reason}")


def _ps_single_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _fixture_command(repo_root: Path, session_dir: Path) -> str:
    repo_root = repo_root.resolve()
    session_dir = session_dir.resolve()
    script = "\n".join(
        (
            "$ErrorActionPreference = 'Stop'",
            (
                "& "
                + _ps_single_quote(str(repo_root / "tools" / "fixture_c_intermediate.ps1"))
                + " -SessionDir "
                + _ps_single_quote(str(session_dir))
                + " -PythonExe "
                + _ps_single_quote(str(Path(sys.executable).resolve()))
                + " -ChildScript "
                + _ps_single_quote(str(repo_root / "tools" / "fixture_c_child.py"))
            ),
        )
    )
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return (
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
        + encoded
    )


def _persist_result(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run EXP-003 Fixture C: verify a stable child keeps historical "
            "PowerShell ancestry after the intermediary exits."
        )
    )
    parser.add_argument("--agent", required=True, help="Configured AI desktop target.")
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Fixture EventStore path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--session-root",
        type=Path,
        default=DEFAULT_SESSION_ROOT,
        help=f"Fixture session directory root (default: {DEFAULT_SESSION_ROOT})",
    )
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)

    if os.name != "nt":
        print("Fixture C currently requires Windows.", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")

    try:
        agent_name = _canonical_agent_name(args.agent)
    except ValueError as exc:
        parser.error(str(exc))

    repo_root = Path(__file__).resolve().parents[1]
    session_dir = (
        args.session_root
        / f"{_utc_stamp()}-{agent_name.casefold()}-{uuid4().hex[:8]}"
    ).resolve()
    session_dir.mkdir(parents=True, exist_ok=False)
    ready_path = session_dir / "ready.json"
    release_path = session_dir / "release.signal"
    stop_path = session_dir / "child-stop.signal"
    result_path = session_dir / "result.json"
    command = _fixture_command(repo_root, session_dir)

    result: dict[str, object] = {
        "schema_version": 1,
        "experiment": "EXP-003",
        "fixture": "C",
        "agent": agent_name,
        "started_at": _utc_now_iso(),
        "status": "running",
        "session_dir": str(session_dir),
    }
    _persist_result(result_path, result)

    print(f"EXP-003 Fixture C session: {session_dir}")
    print()
    print(f"Ask {agent_name} to execute this exact command unchanged:")
    print(command)
    print()
    print("The visible command contains no file-system paths by design.")
    print("Do not decode, rewrite, escape, or normalize the encoded command.")
    print("Waiting for PowerShell intermediary and harmless child...")

    try:
        ready = _wait_for_ready(ready_path, args.timeout)
        powershell_pid = int(ready["powershell_pid"])
        child_pid = int(ready["child_pid"])

        before, before_interval = _wait_for_before_snapshot(
            agent_name=agent_name,
            powershell_pid=powershell_pid,
            child_pid=child_pid,
            timeout_seconds=min(args.timeout, 30.0),
        )
        child_before = _process_by_pid(before, child_pid)
        assert child_before is not None

        release_started_at = time.time()
        release_path.write_text("release\n", encoding="utf-8")
        release_finished_at = time.time()

        after, after_interval = _wait_for_after_snapshot(
            child_before=child_before,
            powershell_pid=powershell_pid,
            child_pid=child_pid,
            timeout_seconds=min(args.timeout, 30.0),
        )

        capture = WindowsCapture(
            processes_before=before,
            tcp_connections=(),
            processes_after=after,
            process_before_interval=before_interval,
            network_interval=CaptureInterval(release_started_at, release_finished_at),
            process_after_interval=after_interval,
        )
        evaluation = evaluate_fixture_capture(
            capture,
            agent_name=agent_name,
            powershell_pid=powershell_pid,
            child_pid=child_pid,
        )

        stream_id = (
            f"fixture-c:{agent_name.casefold()}:{_utc_stamp()}:{uuid4().hex[:8]}"
        )
        batch = windows_capture_event_batch(
            capture,
            source=DEFAULT_SOURCE,
            stream_id=stream_id,
            application_names=(agent_name,),
            hash_executables=False,
        )

        _fixture_relationship_event(batch, child_pid)

        store = EventStore(args.db)
        stored = store.append_many(batch, require_new_stream=True)
        relationship_event = _fixture_relationship_event(stored, child_pid)

        result.update(
            {
                "status": "pass",
                "finished_at": _utc_now_iso(),
                "stream_id": stream_id,
                "event_store": str(args.db),
                "event_count": len(stored),
                "relationship_event_id": relationship_event.event_id,
                "agent_root_pid": evaluation.agent_root_pid,
                "powershell_pid": evaluation.powershell_pid,
                "powershell_started_at": evaluation.powershell_started_at,
                "child_pid": evaluation.child_pid,
                "child_started_at": evaluation.child_started_at,
                "relation_state": evaluation.relation_state,
                "relation_basis": evaluation.relation_basis,
            }
        )
        _persist_result(result_path, result)

        print()
        print("Fixture C: PASS")
        print(f"  agent={evaluation.agent_name} root_pid={evaluation.agent_root_pid}")
        print(f"  powershell_pid={evaluation.powershell_pid} (before only)")
        print(f"  child_pid={evaluation.child_pid} (stable across capture)")
        print(
            f"  relation={evaluation.relation_state}/"
            f"{evaluation.relation_basis}"
        )
        print(f"  stream_id={stream_id}")
        print(f"  relationship_event_id={relationship_event.event_id}")
        print(f"  result={result_path}")
        return 0

    except KeyboardInterrupt:
        result.update(
            {
                "status": "interrupted",
                "finished_at": _utc_now_iso(),
            }
        )
        _persist_result(result_path, result)
        print(f"\nFixture interrupted; partial session preserved: {result_path}")
        return 130
    except (FixtureContractError, KeyError, TypeError, ValueError) as exc:
        result.update(
            {
                "status": "failed",
                "finished_at": _utc_now_iso(),
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        _persist_result(result_path, result)
        print(f"Fixture C failed: {exc}", file=sys.stderr)
        print(f"Session evidence: {result_path}", file=sys.stderr)
        return 2
    finally:
        try:
            release_path.write_text("release\n", encoding="utf-8")
        except OSError:
            pass
        try:
            stop_path.write_text("stop\n", encoding="utf-8")
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
