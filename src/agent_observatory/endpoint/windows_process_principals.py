from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Iterable

from .models import ProcessSnapshot
from .windows_capture import same_process_instance
from .windows_powershell import run_powershell_text


class ProcessPrincipalResolutionState(str, Enum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class WindowsProcessPrincipalSnapshot:
    """One raw Win32_Process.GetOwnerSid result for a queried PID."""

    process_id: int
    observed_started_at: float | None
    process_name: str | None
    owner_sid: str | None
    return_value: int | None
    query_error: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.process_id, bool) or not isinstance(self.process_id, int):
            raise TypeError("process_id must be an integer")
        if self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        if self.observed_started_at is not None and not isinstance(
            self.observed_started_at, (int, float)
        ):
            raise TypeError("observed_started_at must be numeric or None")
        if self.process_name is not None and not isinstance(self.process_name, str):
            raise TypeError("process_name must be a string or None")
        if self.owner_sid is not None and not isinstance(self.owner_sid, str):
            raise TypeError("owner_sid must be a string or None")
        if self.return_value is not None:
            if isinstance(self.return_value, bool) or not isinstance(self.return_value, int):
                raise TypeError("return_value must be an integer or None")
        if self.query_error is not None and not isinstance(self.query_error, str):
            raise TypeError("query_error must be a string or None")


@dataclass(frozen=True, slots=True)
class WindowsProcessPrincipalObservation:
    """Principal query result tied to a verified process instance when possible."""

    process_id: int
    resolution_state: ProcessPrincipalResolutionState
    process_identity_basis: str
    owner_sid: str | None
    return_value: int | None
    process_started_at: float | None = None
    process_name: str | None = None
    resolution_reason: str | None = None

    def __post_init__(self) -> None:
        if isinstance(self.process_id, bool) or not isinstance(self.process_id, int):
            raise TypeError("process_id must be an integer")
        if self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        if not isinstance(self.resolution_state, ProcessPrincipalResolutionState):
            raise TypeError("resolution_state must be ProcessPrincipalResolutionState")
        if not isinstance(self.process_identity_basis, str) or not self.process_identity_basis.strip():
            raise ValueError("process_identity_basis must be a non-empty string")
        if self.return_value is not None:
            if isinstance(self.return_value, bool) or not isinstance(self.return_value, int):
                raise TypeError("return_value must be an integer or None")

        if self.process_identity_basis == "stable_process_instance":
            if self.process_started_at is None or not self.process_name:
                raise ValueError("stable principal observation requires process identity")
        elif self.process_started_at is not None:
            raise ValueError("non-stable principal observation must not carry process_started_at")

        if self.resolution_state is ProcessPrincipalResolutionState.RESOLVED:
            if not self.owner_sid:
                raise ValueError("resolved principal observation requires owner_sid")
            if self.return_value != 0:
                raise ValueError("resolved principal observation requires return_value=0")
            if self.process_identity_basis != "stable_process_instance":
                raise ValueError("resolved principal observation requires stable process identity")
            if self.resolution_reason is not None:
                raise ValueError("resolved principal observation must not carry resolution_reason")
        else:
            if self.owner_sid is not None:
                raise ValueError("unresolved principal observation must not carry owner_sid")
            if not self.resolution_reason:
                raise ValueError("unresolved principal observation requires resolution_reason")

    @property
    def process_ref(self) -> dict[str, object] | None:
        if self.process_identity_basis != "stable_process_instance":
            return None
        assert self.process_started_at is not None
        return {"pid": self.process_id, "started_at": self.process_started_at}


def _timestamp(value: object) -> float | None:
    if value is None or value == "":
        return None
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def _powershell_process_principal_inventory(process_ids: tuple[int, ...]) -> str:
    pid_csv = ",".join(str(pid) for pid in process_ids)
    command = "$targetPids = @(" + pid_csv + ")\n" + r"""
$rows = foreach ($pid in $targetPids) {
    $process = Get-CimInstance Win32_Process -Filter "ProcessId = $pid" -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if ($null -eq $process) {
        [PSCustomObject]@{
            process_id = [int]$pid
            observed_started_at = $null
            process_name = $null
            owner_sid = $null
            return_value = $null
            query_error = 'process_not_found'
        }
        continue
    }

    $startedAt = if ($process.CreationDate) {
        $process.CreationDate.ToUniversalTime().ToString('o')
    } else {
        $null
    }

    try {
        $result = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid -ErrorAction Stop
        [PSCustomObject]@{
            process_id = [int]$process.ProcessId
            observed_started_at = $startedAt
            process_name = $process.Name
            owner_sid = $result.Sid
            return_value = [int]$result.ReturnValue
            query_error = $null
        }
    }
    catch {
        [PSCustomObject]@{
            process_id = [int]$process.ProcessId
            observed_started_at = $startedAt
            process_name = $process.Name
            owner_sid = $null
            return_value = $null
            query_error = $_.Exception.Message
        }
    }
}

$rows | ConvertTo-Json -Compress
"""
    return run_powershell_text(command)


def parse_windows_process_principal_records(
    records: Iterable[dict[str, Any]],
) -> tuple[WindowsProcessPrincipalSnapshot, ...]:
    snapshots: list[WindowsProcessPrincipalSnapshot] = []
    for record in records:
        return_value = record.get("return_value")
        snapshots.append(
            WindowsProcessPrincipalSnapshot(
                process_id=int(record["process_id"]),
                observed_started_at=_timestamp(record.get("observed_started_at")),
                process_name=(
                    None if record.get("process_name") is None else str(record.get("process_name"))
                ),
                owner_sid=(
                    None
                    if not record.get("owner_sid")
                    else str(record.get("owner_sid"))
                ),
                return_value=(None if return_value is None else int(return_value)),
                query_error=(
                    None if not record.get("query_error") else str(record.get("query_error"))
                ),
            )
        )
    return tuple(sorted(snapshots, key=lambda item: item.process_id))


def parse_windows_process_principal_inventory(
    raw: str,
) -> tuple[WindowsProcessPrincipalSnapshot, ...]:
    raw = raw.strip()
    if not raw:
        return ()
    records = json.loads(raw)
    if isinstance(records, dict):
        records = [records]
    if not isinstance(records, list):
        raise TypeError("Windows process principal inventory must be a JSON object or array")
    return parse_windows_process_principal_records(records)


def collect_windows_process_principals(
    process_ids: Iterable[int],
) -> tuple[WindowsProcessPrincipalSnapshot, ...]:
    normalized = tuple(
        sorted(
            {
                int(pid)
                for pid in process_ids
                if not isinstance(pid, bool) and int(pid) >= 0
            }
        )
    )
    if not normalized:
        return ()
    return parse_windows_process_principal_inventory(
        _powershell_process_principal_inventory(normalized)
    )


def _get_owner_sid_failure_reason(return_value: int | None) -> str:
    return {
        2: "access_denied",
        3: "insufficient_privilege",
        8: "unknown_failure",
        9: "path_not_found",
        21: "invalid_parameter",
        22: "other_error",
        4294967295: "other_error",
    }.get(return_value, "get_owner_sid_failed")


def principal_observations_for_processes(
    snapshots: Iterable[WindowsProcessPrincipalSnapshot],
    expected_processes: Iterable[ProcessSnapshot],
    verified_processes: Iterable[ProcessSnapshot],
) -> tuple[WindowsProcessPrincipalObservation, ...]:
    """Attach SID results only to process instances stable across the query."""

    raw_by_pid: dict[int, list[WindowsProcessPrincipalSnapshot]] = {}
    for snapshot in snapshots:
        raw_by_pid.setdefault(snapshot.process_id, []).append(snapshot)

    verified_by_pid = {process.pid: process for process in verified_processes}
    observations: list[WindowsProcessPrincipalObservation] = []

    for expected in sorted(expected_processes, key=lambda item: item.pid):
        verified = verified_by_pid.get(expected.pid)
        records = raw_by_pid.get(expected.pid, [])
        raw = records[0] if len(records) == 1 else None
        raw_return_value = None if raw is None else raw.return_value

        if verified is None or not same_process_instance(expected, verified):
            observations.append(
                WindowsProcessPrincipalObservation(
                    process_id=expected.pid,
                    resolution_state=ProcessPrincipalResolutionState.UNRESOLVED,
                    process_identity_basis="pid_only_snapshot",
                    owner_sid=None,
                    return_value=raw_return_value,
                    resolution_reason="process_not_stable_across_principal_query",
                )
            )
            continue

        common = {
            "process_id": expected.pid,
            "process_identity_basis": "stable_process_instance",
            "process_started_at": expected.started_at,
            "process_name": expected.name,
        }

        if not records:
            observations.append(
                WindowsProcessPrincipalObservation(
                    **common,
                    resolution_state=ProcessPrincipalResolutionState.UNRESOLVED,
                    owner_sid=None,
                    return_value=None,
                    resolution_reason="principal_query_missing_record",
                )
            )
            continue
        if len(records) != 1:
            observations.append(
                WindowsProcessPrincipalObservation(
                    **common,
                    resolution_state=ProcessPrincipalResolutionState.UNRESOLVED,
                    owner_sid=None,
                    return_value=None,
                    resolution_reason="principal_query_duplicate_records",
                )
            )
            continue

        assert raw is not None
        if (
            raw.observed_started_at != expected.started_at
            or not raw.process_name
            or raw.process_name.casefold() != expected.name.casefold()
        ):
            observations.append(
                WindowsProcessPrincipalObservation(
                    **common,
                    resolution_state=ProcessPrincipalResolutionState.UNRESOLVED,
                    owner_sid=None,
                    return_value=raw.return_value,
                    resolution_reason="principal_query_process_identity_mismatch",
                )
            )
            continue

        if raw.query_error:
            observations.append(
                WindowsProcessPrincipalObservation(
                    **common,
                    resolution_state=ProcessPrincipalResolutionState.UNRESOLVED,
                    owner_sid=None,
                    return_value=raw.return_value,
                    resolution_reason="principal_query_error",
                )
            )
            continue

        if raw.return_value == 0 and raw.owner_sid:
            observations.append(
                WindowsProcessPrincipalObservation(
                    **common,
                    resolution_state=ProcessPrincipalResolutionState.RESOLVED,
                    owner_sid=raw.owner_sid,
                    return_value=0,
                    resolution_reason=None,
                )
            )
            continue

        observations.append(
            WindowsProcessPrincipalObservation(
                **common,
                resolution_state=ProcessPrincipalResolutionState.UNRESOLVED,
                owner_sid=None,
                return_value=raw.return_value,
                resolution_reason=_get_owner_sid_failure_reason(raw.return_value),
            )
        )

    return tuple(observations)
