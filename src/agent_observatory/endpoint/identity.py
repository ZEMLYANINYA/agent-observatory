from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

from .models import ProcessSnapshot


class ExecutableHashState(str, Enum):
    NOT_REQUESTED = "not-requested"
    MISSING_PATH = "missing-path"
    UNAVAILABLE = "unavailable"
    HASHED = "hashed"


@dataclass(frozen=True, slots=True)
class ExecutableIdentity:
    path: str | None
    sha256: str | None
    hash_state: ExecutableHashState


@dataclass(frozen=True, slots=True)
class ProcessInstanceIdentity:
    """Identity evidence for one observed process instance."""

    pid: int
    ppid: int
    started_at: float
    name: str
    command_line_sha256: str | None
    executable: ExecutableIdentity


def hash_command_line(command_line: str | None) -> str | None:
    """Hash the exact observed command line without normalizing dynamic data."""

    if command_line is None:
        return None

    return hashlib.sha256(
        command_line.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def normalize_executable_path(path: str | None) -> str | None:
    """Normalize a Windows executable path for identity comparison only."""

    if not path:
        return None

    return path.strip().replace("/", "\\").casefold()


def capture_identity_key(
    process: ProcessSnapshot,
) -> tuple[int, int, float, str, str | None, str | None]:
    """
    Build the identity key available inside a time-sensitive process capture.

    File hashing is intentionally excluded because reading executable files
    inside the process/TCP capture window would widen attribution uncertainty.
    """

    return (
        process.pid,
        process.ppid,
        process.started_at,
        process.name.casefold(),
        normalize_executable_path(process.executable_path),
        hash_command_line(process.command_line),
    )


def sha256_file(
    path: str,
    *,
    chunk_size: int = 1024 * 1024,
) -> str | None:
    """Return a streaming SHA-256 digest, or None when the file is unreadable."""

    digest = hashlib.sha256()

    try:
        with open(path, "rb") as handle:
            while chunk := handle.read(chunk_size):
                digest.update(chunk)
    except (OSError, ValueError):
        return None

    return digest.hexdigest()


def build_process_identities(
    processes: Iterable[ProcessSnapshot],
    *,
    hash_executables: bool = True,
    file_hasher: Callable[[str], str | None] = sha256_file,
) -> tuple[ProcessInstanceIdentity, ...]:
    """
    Build process identities and hash each executable path at most once.

    Executable hashing happens after capture and is best-effort. Missing or
    unreadable paths remain explicit evidence states rather than hard errors.
    """

    process_list = tuple(processes)
    hash_cache: dict[str, tuple[str | None, ExecutableHashState]] = {}
    identities: list[ProcessInstanceIdentity] = []

    for process in process_list:
        path = process.executable_path

        if not hash_executables:
            executable_sha256 = None
            hash_state = ExecutableHashState.NOT_REQUESTED
        elif not path:
            executable_sha256 = None
            hash_state = ExecutableHashState.MISSING_PATH
        else:
            cache_key = normalize_executable_path(path) or path
            cached = hash_cache.get(cache_key)

            if cached is None:
                executable_sha256 = file_hasher(path)
                hash_state = (
                    ExecutableHashState.HASHED
                    if executable_sha256 is not None
                    else ExecutableHashState.UNAVAILABLE
                )
                hash_cache[cache_key] = (
                    executable_sha256,
                    hash_state,
                )
            else:
                executable_sha256, hash_state = cached

        identities.append(
            ProcessInstanceIdentity(
                pid=process.pid,
                ppid=process.ppid,
                started_at=process.started_at,
                name=process.name,
                command_line_sha256=hash_command_line(
                    process.command_line
                ),
                executable=ExecutableIdentity(
                    path=path,
                    sha256=executable_sha256,
                    hash_state=hash_state,
                ),
            )
        )

    return tuple(identities)
