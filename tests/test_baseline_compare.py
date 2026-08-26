import unittest

from agent_observatory.endpoint.baseline_compare import (
    DifferenceKind,
    compare_processes_to_baseline,
)
from agent_observatory.endpoint.fingerprint import (
    fingerprint_process,
)
from agent_observatory.endpoint.models import ProcessSnapshot


class BaselineCompareTests(unittest.TestCase):
    def test_known_process_matches_baseline(self) -> None:
        baseline_process = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="client.exe",
            started_at=100.0,
            command_line='"client.exe" --type=renderer',
        )

        current_process = ProcessSnapshot(
            pid=200,
            ppid=20,
            name="client.exe",
            started_at=200.0,
            command_line=(
                '"client.exe" '
                '--type=renderer '
                '--renderer-client-id=999'
            ),
        )

        baseline = (
            fingerprint_process(baseline_process),
        )

        differences = compare_processes_to_baseline(
            (current_process,),
            baseline,
        )

        self.assertEqual(
            differences[0].kind,
            DifferenceKind.KNOWN,
        )

    def test_first_seen_process_is_detected(self) -> None:
        baseline_process = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="known.exe",
            started_at=100.0,
        )

        new_process = ProcessSnapshot(
            pid=200,
            ppid=20,
            name="new-tool.exe",
            started_at=200.0,
        )

        baseline = (
            fingerprint_process(baseline_process),
        )

        differences = compare_processes_to_baseline(
            (new_process,),
            baseline,
        )

        self.assertEqual(
            differences[0].kind,
            DifferenceKind.FIRST_SEEN,
        )

    def test_dynamic_renderer_arguments_do_not_trigger_first_seen(self) -> None:
        baseline_process = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="client.exe",
            started_at=100.0,
            command_line=(
                '"client.exe" '
                '--type=renderer '
                '--renderer-client-id=1 '
                '--trace-process-track-uuid=111'
            ),
        )

        current_process = ProcessSnapshot(
            pid=200,
            ppid=20,
            name="client.exe",
            started_at=200.0,
            command_line=(
                '"client.exe" '
                '--type=renderer '
                '--renderer-client-id=999 '
                '--trace-process-track-uuid=999999'
            ),
        )

        baseline = (
            fingerprint_process(baseline_process),
        )

        differences = compare_processes_to_baseline(
            (current_process,),
            baseline,
        )

        self.assertEqual(
            differences[0].kind,
            DifferenceKind.KNOWN,
        )

    def test_root_process_uses_main_role(self) -> None:
        baseline_root = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="claude.exe",
            started_at=100.0,
        )

        current_root = ProcessSnapshot(
            pid=200,
            ppid=20,
            name="claude.exe",
            started_at=200.0,
        )

        baseline = (
            fingerprint_process(
                baseline_root,
                is_root=True,
            ),
        )

        differences = compare_processes_to_baseline(
            (current_root,),
            baseline,
            root_pids=(200,),
        )

        self.assertEqual(
            differences[0].kind,
            DifferenceKind.KNOWN,
        )

    def test_same_name_different_role_is_first_seen(self) -> None:
        renderer = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="client.exe",
            started_at=100.0,
            command_line='"client.exe" --type=renderer',
        )

        gpu = ProcessSnapshot(
            pid=200,
            ppid=20,
            name="client.exe",
            started_at=200.0,
            command_line='"client.exe" --type=gpu-process',
        )

        baseline = (
            fingerprint_process(renderer),
        )

        differences = compare_processes_to_baseline(
            (gpu,),
            baseline,
        )

        self.assertEqual(
            differences[0].kind,
            DifferenceKind.FIRST_SEEN,
        )


if __name__ == "__main__":
    unittest.main()