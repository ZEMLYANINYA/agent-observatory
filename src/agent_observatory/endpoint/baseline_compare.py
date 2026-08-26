from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .fingerprint import ProcessFingerprint, fingerprint_process
from .models import ProcessSnapshot


class DifferenceKind(str, Enum):
    KNOWN = "known"
    FIRST_SEEN = "first_seen"


@dataclass(frozen=True, slots=True)
class ProcessDifference:
    pid: int
    ppid: int
    name: str
    fingerprint: ProcessFingerprint
    kind: DifferenceKind


def compare_processes_to_baseline(
    processes: Iterable[ProcessSnapshot],
    baseline_fingerprints: Iterable[ProcessFingerprint],
    *,
    root_pids: Iterable[int] = (),
) -> tuple[ProcessDifference, ...]:
    """
    Compare current processes against a known fingerprint baseline.
    """

    known = set(baseline_fingerprints)
    root_pid_set = set(root_pids)

    results: list[ProcessDifference] = []

    for process in processes:
        fingerprint = fingerprint_process(
            process,
            is_root=process.pid in root_pid_set,
        )

        kind = (
            DifferenceKind.KNOWN
            if fingerprint in known
            else DifferenceKind.FIRST_SEEN
        )

        results.append(
            ProcessDifference(
                pid=process.pid,
                ppid=process.ppid,
                name=process.name,
                fingerprint=fingerprint,
                kind=kind,
            )
        )

    return tuple(results)