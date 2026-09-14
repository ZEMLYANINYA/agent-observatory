import hashlib
import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.identity import (
    ExecutableHashState,
    build_process_identities,
    capture_identity_key,
    hash_command_line,
    sha256_file,
)
from agent_observatory.endpoint.models import ProcessSnapshot


class ProcessIdentityTests(unittest.TestCase):
    def test_command_line_hash_preserves_instance_specific_data(self) -> None:
        first = 'claude.exe --type=renderer --renderer-client-id=1'
        second = 'claude.exe --type=renderer --renderer-client-id=2'

        self.assertNotEqual(
            hash_command_line(first),
            hash_command_line(second),
        )

    def test_missing_command_line_has_no_hash(self) -> None:
        self.assertIsNone(hash_command_line(None))

    def test_capture_identity_normalizes_windows_path_case_and_separators(self) -> None:
        first = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="Claude.exe",
            started_at=100.0,
            command_line="claude.exe --type=renderer",
            executable_path="C:/Program Files/Claude/Claude.exe",
        )
        second = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="CLAUDE.EXE",
            started_at=100.0,
            command_line="claude.exe --type=renderer",
            executable_path="c:\\program files\\claude\\claude.exe",
        )

        self.assertEqual(
            capture_identity_key(first),
            capture_identity_key(second),
        )

    def test_capture_identity_rejects_different_executable_path(self) -> None:
        first = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="Claude.exe",
            started_at=100.0,
            command_line="claude.exe",
            executable_path="C:\\Apps\\Claude.exe",
        )
        second = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="Claude.exe",
            started_at=100.0,
            command_line="claude.exe",
            executable_path="C:\\Temp\\Claude.exe",
        )

        self.assertNotEqual(
            capture_identity_key(first),
            capture_identity_key(second),
        )

    def test_sha256_file_streams_file_contents(self) -> None:
        payload = b"agent-observatory\x00identity-v2"

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(payload)

            self.assertEqual(
                sha256_file(str(path), chunk_size=5),
                hashlib.sha256(payload).hexdigest(),
            )

    def test_executable_hash_is_cached_by_normalized_path(self) -> None:
        calls: list[str] = []

        def fake_hasher(path: str) -> str:
            calls.append(path)
            return "a" * 64

        processes = (
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="Claude.exe",
                started_at=100.0,
                executable_path="C:\\Apps\\Claude.exe",
            ),
            ProcessSnapshot(
                pid=101,
                ppid=100,
                name="Claude.exe",
                started_at=101.0,
                executable_path="c:/apps/claude.exe",
            ),
        )

        identities = build_process_identities(
            processes,
            file_hasher=fake_hasher,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(
            identities[0].executable.sha256,
            "a" * 64,
        )
        self.assertEqual(
            identities[1].executable.sha256,
            "a" * 64,
        )
        self.assertEqual(
            identities[0].executable.hash_state,
            ExecutableHashState.HASHED,
        )

    def test_missing_executable_path_is_explicit(self) -> None:
        identities = build_process_identities(
            (
                ProcessSnapshot(
                    pid=100,
                    ppid=10,
                    name="Claude.exe",
                    started_at=100.0,
                ),
            )
        )

        self.assertEqual(
            identities[0].executable.hash_state,
            ExecutableHashState.MISSING_PATH,
        )
        self.assertIsNone(identities[0].executable.sha256)


if __name__ == "__main__":
    unittest.main()
