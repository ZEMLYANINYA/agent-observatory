from __future__ import annotations

from dataclasses import dataclass

from .models import ProcessSnapshot
from .roles import ProcessRole, classify_process_role


DYNAMIC_ARGUMENT_PREFIXES = (
    "--renderer-client-id=",
    "--trace-process-track-uuid=",
    "--mojo-platform-channel-handle=",
    "--launch-time-ticks=",
    "--time-ticks-at-unix-epoch=",
    "--field-trial-handle=",
    "--metrics-shmem-handle=",
    "--initial-client-data=",
    "--pseudonymization-salt-handle=",
)


@dataclass(frozen=True, slots=True)
class ProcessFingerprint:
    name: str
    role: ProcessRole
    markers: tuple[str, ...]


def _stable_markers(
    command_line: str | None,
) -> tuple[str, ...]:
    if not command_line:
        return ()

    markers: list[str] = []

    for token in command_line.split():
        normalized = token.strip().casefold()

        if not normalized.startswith("--"):
            continue

        if any(
            normalized.startswith(prefix)
            for prefix in DYNAMIC_ARGUMENT_PREFIXES
        ):
            continue

        if normalized.startswith("--type="):
            markers.append(normalized)
            continue

        if normalized.startswith("--utility-sub-type="):
            markers.append(normalized)
            continue

    return tuple(sorted(set(markers)))


def fingerprint_process(
    process: ProcessSnapshot,
    *,
    is_root: bool = False,
) -> ProcessFingerprint:
    role = classify_process_role(
        process.command_line,
        is_root=is_root,
    )

    return ProcessFingerprint(
        name=process.name.casefold(),
        role=role,
        markers=_stable_markers(process.command_line),
    )