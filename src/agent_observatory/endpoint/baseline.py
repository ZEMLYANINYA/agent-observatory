from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import ProcessSnapshot
from .roles import ProcessRole, classify_process_role


@dataclass(frozen=True, slots=True)
class BaselineProcess:
    name: str
    role: ProcessRole
    command_line: str | None = None


def build_process_baseline(
    processes: Iterable[ProcessSnapshot],
    *,
    root_pids: Iterable[int] = (),
) -> tuple[BaselineProcess, ...]:
    """
    Build a unique process baseline from observed process snapshots.

    This first version intentionally preserves command-line metadata
    without treating it as a stable process identity.

    Stable fingerprinting is handled by a later layer.
    """

    root_pid_set = set(root_pids)

    unique: dict[
        tuple[str, ProcessRole, str | None],
        BaselineProcess,
    ] = {}

    for process in processes:
        role = classify_process_role(
            process.command_line,
            is_root=process.pid in root_pid_set,
        )

        item = BaselineProcess(
            name=process.name,
            role=role,
            command_line=process.command_line,
        )

        key = (
            process.name.casefold(),
            role,
            process.command_line,
        )

        unique[key] = item

    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.name.casefold(),
                item.role.value,
                item.command_line or "",
            ),
        )
    )