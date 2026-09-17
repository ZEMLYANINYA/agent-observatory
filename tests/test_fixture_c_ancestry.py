import base64
import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from tools.fixture_c_ancestry import (
    DEFAULT_SESSION_ROOT,
    FixtureContractError,
    _fixture_command,
    evaluate_fixture_capture,
)


class FixtureCAncestryTests(unittest.TestCase):
    @staticmethod
    def _process(
        pid: int,
        ppid: int,
        name: str,
        started_at: float,
        *,
        executable_path: str | None = None,
        command_line: str | None = None,
    ) -> ProcessSnapshot:
        return ProcessSnapshot(
            pid=pid,
            ppid=ppid,
            name=name,
            started_at=started_at,
            executable_path=executable_path,
            command_line=command_line,
        )

    def _capture(
        self,
        *,
        keep_parent_after: bool = False,
        reuse_child: bool = False,
        reuse_root: bool = False,
    ):
        root_before = self._process(
            100,
            50,
            "Gemini.exe",
            100.0,
            executable_path=r"C:\Users\test\AppData\Local\Google\Gemini\Gemini.exe",
        )
        root_after = self._process(
            100,
            50,
            "Gemini.exe",
            101.0 if reuse_root else 100.0,
            executable_path=r"C:\Users\test\AppData\Local\Google\Gemini\Gemini.exe",
        )
        powershell = self._process(
            200,
            100,
            "powershell.exe",
            200.0,
            executable_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        )
        child_before = self._process(
            300,
            200,
            "python.exe",
            300.0,
            executable_path=r"C:\Python312\python.exe",
        )
        child_after = self._process(
            300,
            200,
            "python.exe",
            301.0 if reuse_child else 300.0,
            executable_path=r"C:\Python312\python.exe",
        )

        processes_after = [root_after, child_after]
        if keep_parent_after:
            processes_after.insert(1, powershell)

        return WindowsCapture(
            processes_before=(root_before, powershell, child_before),
            tcp_connections=(),
            processes_after=tuple(processes_after),
            process_before_interval=CaptureInterval(1_000.0, 1_001.0),
            network_interval=CaptureInterval(1_001.0, 1_002.0),
            process_after_interval=CaptureInterval(1_002.0, 1_003.0),
        )

    def test_default_session_root_uses_system_temp_directory(self) -> None:
        expected = Path(tempfile.gettempdir()) / "agent-observatory-fixture-c"

        self.assertEqual(DEFAULT_SESSION_ROOT, expected)
        self.assertTrue(DEFAULT_SESSION_ROOT.is_absolute())

    def test_fixture_command_encodes_paths_instead_of_exposing_them(self) -> None:
        repo_root = Path("relative_repo_тест")
        session_dir = Path("relative_session_тест")

        command = _fixture_command(repo_root, session_dir)

        prefix = "powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "
        self.assertTrue(command.startswith(prefix))
        self.assertNotIn("_", command)
        self.assertNotIn("\\", command)

        encoded = command[len(prefix) :]
        decoded = base64.b64decode(encoded).decode("utf-16le")

        self.assertIn(str(repo_root.resolve()), decoded)
        self.assertIn(str(session_dir.resolve()), decoded)
        self.assertIn("fixture_c_intermediate.ps1", decoded)
        self.assertIn("fixture_c_child.py", decoded)

    def test_stable_child_preserves_before_only_powershell_parent(self) -> None:
        evaluation = evaluate_fixture_capture(
            self._capture(),
            agent_name="Gemini",
            powershell_pid=200,
            child_pid=300,
        )

        self.assertEqual(evaluation.agent_root_pid, 100)
        self.assertEqual(evaluation.powershell_pid, 200)
        self.assertEqual(evaluation.child_pid, 300)
        self.assertEqual(evaluation.relation_state, "valid")
        self.assertEqual(
            evaluation.relation_basis,
            "parent_observed_before_only",
        )

    def test_parent_must_really_exit_before_after_snapshot(self) -> None:
        with self.assertRaisesRegex(FixtureContractError, "still present"):
            evaluate_fixture_capture(
                self._capture(keep_parent_after=True),
                agent_name="Gemini",
                powershell_pid=200,
                child_pid=300,
            )

    def test_child_pid_reuse_is_not_accepted_as_stable_ancestry(self) -> None:
        with self.assertRaisesRegex(FixtureContractError, "same process instance"):
            evaluate_fixture_capture(
                self._capture(reuse_child=True),
                agent_name="Gemini",
                powershell_pid=200,
                child_pid=300,
            )

    def test_agent_root_must_remain_same_stable_process_instance(self) -> None:
        with self.assertRaisesRegex(FixtureContractError, "agent root"):
            evaluate_fixture_capture(
                self._capture(reuse_root=True),
                agent_name="Gemini",
                powershell_pid=200,
                child_pid=300,
            )

    def test_fixture_processes_must_belong_to_requested_agent_tree(self) -> None:
        with self.assertRaisesRegex(FixtureContractError, "requested agent"):
            evaluate_fixture_capture(
                self._capture(),
                agent_name="Claude",
                powershell_pid=200,
                child_pid=300,
            )


if __name__ == "__main__":
    unittest.main()
