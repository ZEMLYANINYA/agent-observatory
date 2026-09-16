import hashlib
import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.identity import (
    ExecutableHashState,
    FileIdentity,
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

    def test_executable_hash_is_cached_by_file_identity_not_path(self) -> None:
        calls: list[str] = []
        identity = FileIdentity(volume_serial=7, file_id=11)

        def fake_hasher(path: str) -> str:
            calls.append(path)
            return "a" * 64

        def fake_identity(path: str) -> FileIdentity:
            return identity

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
            file_identity_provider=fake_identity,
        )

        self.assertEqual(len(calls), 1)
        self.assertEqual(identities[0].executable.file_identity, identity)
        self.assertEqual(identities[1].executable.file_identity, identity)
        self.assertEqual(identities[0].executable.sha256, "a" * 64)
        self.assertEqual(identities[1].executable.sha256, "a" * 64)
        self.assertEqual(
            identities[0].executable.hash_state,
            ExecutableHashState.HASHED,
        )

    def test_same_path_replacement_is_not_reused_from_cache(self) -> None:
        calls: list[str] = []
        identities_seen = iter(
            [
                FileIdentity(1, 100),
                FileIdentity(1, 100),
                FileIdentity(1, 200),
                FileIdentity(1, 200),
            ]
        )

        def fake_hasher(path: str) -> str:
            calls.append(path)
            return ("a" if len(calls) == 1 else "b") * 64

        def fake_identity(path: str) -> FileIdentity:
            return next(identities_seen)

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
                ppid=10,
                name="Claude.exe",
                started_at=101.0,
                executable_path="C:\\Apps\\Claude.exe",
            ),
        )

        result = build_process_identities(
            processes,
            file_hasher=fake_hasher,
            file_identity_provider=fake_identity,
        )

        self.assertEqual(len(calls), 2)
        self.assertEqual(result[0].executable.sha256, "a" * 64)
        self.assertEqual(result[1].executable.sha256, "b" * 64)
        self.assertNotEqual(
            result[0].executable.file_identity,
            result[1].executable.file_identity,
        )

    def test_replacement_during_hash_discards_digest(self) -> None:
        identities_seen = iter(
            [
                FileIdentity(1, 100),
                FileIdentity(1, 200),
            ]
        )

        def fake_identity(path: str) -> FileIdentity:
            return next(identities_seen)

        process = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="Claude.exe",
            started_at=100.0,
            executable_path="C:\\Apps\\Claude.exe",
        )

        result = build_process_identities(
            (process,),
            file_hasher=lambda _: "a" * 64,
            file_identity_provider=fake_identity,
        )

        self.assertEqual(
            result[0].executable.hash_state,
            ExecutableHashState.FILE_REPLACED_DURING_HASH,
        )
        self.assertIsNone(result[0].executable.sha256)
        self.assertEqual(
            result[0].executable.file_identity,
            FileIdentity(1, 200),
        )

    def test_hash_gap_is_explicit(self) -> None:
        ticks = iter([105.25, 105.50])
        identity = FileIdentity(1, 100)
        process = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="Claude.exe",
            started_at=100.0,
            executable_path="C:\\Apps\\Claude.exe",
        )

        result = build_process_identities(
            (process,),
            file_hasher=lambda _: "a" * 64,
            file_identity_provider=lambda _: identity,
            process_observed_at=105.0,
            clock=lambda: next(ticks),
        )

        self.assertEqual(
            result[0].executable.hash_state,
            ExecutableHashState.HASHED,
        )
        self.assertAlmostEqual(
            result[0].executable.hash_observation.hash_gap_ms,
            250.0,
        )
        self.assertEqual(
            result[0].executable.hash_observation.observed_at,
            105.50,
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
