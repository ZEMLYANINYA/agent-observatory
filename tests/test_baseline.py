import unittest

from agent_observatory.endpoint.baseline import (
    build_process_baseline,
)
from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.roles import ProcessRole


class ProcessBaselineTests(unittest.TestCase):
    def test_builds_baseline_from_processes(self) -> None:
        processes = (
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="ai-client.exe",
                started_at=100.0,
            ),
            ProcessSnapshot(
                pid=101,
                ppid=100,
                name="ai-client.exe",
                started_at=101.0,
                command_line=(
                    '"ai-client.exe" '
                    '--type=renderer'
                ),
            ),
        )

        baseline = build_process_baseline(
            processes,
            root_pids=(100,),
        )

        self.assertEqual(len(baseline), 2)

        roles = {
            item.role
            for item in baseline
        }

        self.assertIn(ProcessRole.MAIN, roles)
        self.assertIn(ProcessRole.RENDERER, roles)

    def test_deduplicates_identical_observations(self) -> None:
        processes = (
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="helper.exe",
                started_at=100.0,
                command_line='"helper.exe" --mode=test',
            ),
            ProcessSnapshot(
                pid=200,
                ppid=20,
                name="helper.exe",
                started_at=200.0,
                command_line='"helper.exe" --mode=test',
            ),
        )

        baseline = build_process_baseline(processes)

        self.assertEqual(len(baseline), 1)
        self.assertEqual(
            baseline[0].name,
            "helper.exe",
        )

    def test_preserves_different_command_lines(self) -> None:
        processes = (
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="helper.exe",
                started_at=100.0,
                command_line='"helper.exe" --mode=a',
            ),
            ProcessSnapshot(
                pid=200,
                ppid=20,
                name="helper.exe",
                started_at=200.0,
                command_line='"helper.exe" --mode=b',
            ),
        )

        baseline = build_process_baseline(processes)

        self.assertEqual(len(baseline), 2)

    def test_unknown_process_role_is_preserved(self) -> None:
        processes = (
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="custom-tool.exe",
                started_at=100.0,
                command_line='"custom-tool.exe" --something',
            ),
        )

        baseline = build_process_baseline(processes)

        self.assertEqual(
            baseline[0].role,
            ProcessRole.UNKNOWN,
        )

    def test_matching_is_case_insensitive_for_name(self) -> None:
        processes = (
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="Helper.exe",
                started_at=100.0,
            ),
            ProcessSnapshot(
                pid=200,
                ppid=20,
                name="helper.EXE",
                started_at=200.0,
            ),
        )

        baseline = build_process_baseline(processes)

        self.assertEqual(len(baseline), 1)


if __name__ == "__main__":
    unittest.main()