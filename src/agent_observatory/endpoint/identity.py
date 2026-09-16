from __future__ import annotations

import ctypes
import hashlib
import os
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .models import ProcessSnapshot


class ExecutableHashState(str, Enum):
    NOT_REQUESTED = "not-requested"
    MISSING_PATH = "missing-path"
    UNAVAILABLE = "unavailable"
    HASHED = "hashed"
    FILE_REPLACED_DURING_HASH = "file-replaced-during-hash"


@dataclass(frozen=True, slots=True)
class FileIdentity:
    """Stable filesystem identity observed for a Windows file handle."""

    volume_serial: int
    file_id: int


@dataclass(frozen=True, slots=True)
class FileHashObservation:
    sha256: str | None
    state: ExecutableHashState
    observed_at: float | None
    hash_gap_ms: float | None


@dataclass(frozen=True, slots=True)
class ExecutableIdentity:
    path: str | None
    file_identity: FileIdentity | None
    hash_observation: FileHashObservation

    @property
    def sha256(self) -> str | None:
        return self.hash_observation.sha256

    @property
    def hash_state(self) -> ExecutableHashState:
        return self.hash_observation.state


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
    """Normalize a Windows executable path for comparison/display only."""

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


def get_windows_file_identity(path: str) -> FileIdentity | None:
    """
    Read Windows VolumeSerial + FileID without using path spelling as identity.

    This observation is deliberately separate from process capture. It describes
    the file found at ``path`` when this function runs, not the exact bytes that
    were necessarily mapped into an already-running process.
    """

    if os.name != "nt":
        return None

    from ctypes import wintypes

    FILE_READ_ATTRIBUTES = 0x0080
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE

    get_info = kernel32.GetFileInformationByHandle
    get_info.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
    ]
    get_info.restype = wintypes.BOOL

    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        str(Path(path)),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    if handle == INVALID_HANDLE_VALUE:
        return None

    try:
        info = BY_HANDLE_FILE_INFORMATION()
        if not get_info(handle, ctypes.byref(info)):
            return None

        file_id = (int(info.nFileIndexHigh) << 32) | int(info.nFileIndexLow)
        return FileIdentity(
            volume_serial=int(info.dwVolumeSerialNumber),
            file_id=file_id,
        )
    finally:
        close_handle(handle)


def build_process_identities(
    processes: Iterable[ProcessSnapshot],
    *,
    hash_executables: bool = True,
    file_hasher: Callable[[str], str | None] = sha256_file,
    file_identity_provider: Callable[[str], FileIdentity | None] = get_windows_file_identity,
    process_observed_at: float | None = None,
    clock: Callable[[], float] = time.time,
) -> tuple[ProcessInstanceIdentity, ...]:
    """
    Build process identities with post-capture file/hash evidence.

    Hash reuse is keyed by filesystem identity, never by normalized path. That
    avoids treating a file replaced at the same path as the same executable.
    ``hash_gap_ms`` makes the process-observation -> file-hash TOCTOU window
    explicit instead of implying that the hash proves the bytes mapped by the
    running process.
    """

    process_list = tuple(processes)
    hash_cache: dict[FileIdentity, FileHashObservation] = {}
    identities: list[ProcessInstanceIdentity] = []

    for process in process_list:
        path = process.executable_path
        file_identity: FileIdentity | None = None

        if not hash_executables:
            hash_observation = FileHashObservation(
                sha256=None,
                state=ExecutableHashState.NOT_REQUESTED,
                observed_at=None,
                hash_gap_ms=None,
            )
        elif not path:
            hash_observation = FileHashObservation(
                sha256=None,
                state=ExecutableHashState.MISSING_PATH,
                observed_at=None,
                hash_gap_ms=None,
            )
        else:
            file_identity = file_identity_provider(path)
            cached = (
                hash_cache.get(file_identity)
                if file_identity is not None
                else None
            )

            if cached is not None:
                hash_observation = cached
            else:
                hash_started_at = clock()
                executable_sha256 = file_hasher(path)
                hash_finished_at = clock()
                file_identity_after = file_identity_provider(path)

                if (
                    file_identity is not None
                    and file_identity_after is not None
                    and file_identity_after != file_identity
                ):
                    hash_observation = FileHashObservation(
                        sha256=None,
                        state=ExecutableHashState.FILE_REPLACED_DURING_HASH,
                        observed_at=hash_finished_at,
                        hash_gap_ms=(
                            max(0.0, hash_started_at - process_observed_at) * 1000.0
                            if process_observed_at is not None
                            else None
                        ),
                    )
                    file_identity = file_identity_after
                else:
                    if file_identity is None:
                        file_identity = file_identity_after

                    hash_observation = FileHashObservation(
                        sha256=executable_sha256,
                        state=(
                            ExecutableHashState.HASHED
                            if executable_sha256 is not None
                            else ExecutableHashState.UNAVAILABLE
                        ),
                        observed_at=hash_finished_at,
                        hash_gap_ms=(
                            max(0.0, hash_started_at - process_observed_at) * 1000.0
                            if process_observed_at is not None
                            else None
                        ),
                    )

                    if file_identity is not None:
                        hash_cache[file_identity] = hash_observation

        identities.append(
            ProcessInstanceIdentity(
                pid=process.pid,
                ppid=process.ppid,
                started_at=process.started_at,
                name=process.name,
                command_line_sha256=hash_command_line(process.command_line),
                executable=ExecutableIdentity(
                    path=path,
                    file_identity=file_identity,
                    hash_observation=hash_observation,
                ),
            )
        )

    return tuple(identities)
