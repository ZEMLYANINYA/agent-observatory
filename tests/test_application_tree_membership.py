import unittest
from unittest.mock import patch

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.endpoint.windows_live import collect_live_snapshot
from agent_observatory.evidence import windows_capture_event_batch
from agent_observatory.storage import EventType


class ApplicationTreeMembershipRegressionTests(unittest.TestCase):
    @staticmethod
    def _process(
        pid: int,
        ppid: int,
        name: str,
        started_at: float,
        *,
        command_line: str | None = None,
        executable_path: str | None = None,
    ) -> ProcessSnapshot:
        return ProcessSnapshot(
            pid=pid,
            ppid=ppid,
            name=name,
            started_at=started_at,
            command_line=command_line,
            executable_path=executable_path,
        )

    def _capture_with_exited_intermediate(self) -> WindowsCapture:
        parent = self._process(
            50,
            4,
            "explorer.exe",
            50.0,
            executable_path=r"C:\Windows\explorer.exe",
        )
        root = self._process(
            100,
            50,
            "Gemini.exe",
            100.0,
            command_line='"Gemini.exe" --profile-directory=Default',
            executable_path=r"C:\Users\test\AppData\Local\Google\Gemini\Gemini.exe",
        )
        intermediate = self._process(
            101,
            100,
            "Gemini Helper.exe",
            101.0,
            command_line='"Gemini Helper.exe" --type=utility',
            executable_path=r"C:\Users\test\AppData\Local\Google\Gemini\Gemini Helper.exe",
        )
        child = self._process(
            102,
            101,
            "Gemini Helper.exe",
            102.0,
            command_line='"Gemini Helper.exe" --type=renderer',
            executable_path=r"C:\Users\test\AppData\Local\Google\Gemini\Gemini Helper.exe",
        )

        return WindowsCapture(
            processes_before=(parent, root, intermediate, child),
            tcp_connections=(
                TcpConnection(
                    pid=101,
                    state="Established",
                    local_address="10.0.0.2",
                    local_port=51001,
                    remote_address="203.0.113.10",
                    remote_port=443,
                ),
                TcpConnection(
                    pid=102,
                    state="Established",
                    local_address="10.0.0.2",
                    local_port=51002,
                    remote_address="203.0.113.20",
                    remote_port=443,
                ),
            ),
            processes_after=(parent, root, child),
            process_before_interval=CaptureInterval(1_000.0, 1_001.0),
            network_interval=CaptureInterval(1_001.0, 1_002.0),
            process_after_interval=CaptureInterval(1_002.0, 1_003.0),
        )

    def test_event_batch_keeps_stable_child_behind_exited_intermediate(self) -> None:
        capture = self._capture_with_exited_intermediate()
        clock_values = iter((2_000.0, 2_001.0))

        events = windows_capture_event_batch(
            capture,
            source="regression-test",
            stream_id="tree-membership",
            application_names=("Gemini",),
            hash_executables=False,
            clock=lambda: next(clock_values),
        )

        process_events = tuple(
            event
            for event in events
            if event.event_type is EventType.PROCESS_OBSERVED
        )
        self.assertEqual(
            tuple(event.payload["pid"] for event in process_events),
            (100, 102),
        )

        relationship_events = tuple(
            event
            for event in events
            if event.event_type is EventType.PROCESS_RELATIONSHIP_OBSERVED
        )
        child_relation = next(
            event
            for event in relationship_events
            if event.payload["child"]["pid"] == 102
        )
        self.assertEqual(child_relation.payload["state"], "valid")
        self.assertEqual(
            child_relation.payload["basis"],
            "parent_observed_before_only",
        )
        self.assertEqual(child_relation.payload["parent"]["pid"], 101)
        self.assertEqual(child_relation.payload["parent"]["started_at"], 101.0)

        tcp_events = tuple(
            event
            for event in events
            if event.event_type is EventType.TCP_CONNECTION_OBSERVED
        )
        self.assertEqual(
            tuple(event.payload["process"]["pid"] for event in tcp_events),
            (102,),
        )
        self.assertEqual(tcp_events[0].payload["remote_address"], "203.0.113.20")

    def test_live_view_keeps_stable_child_and_reports_unstable_owner(self) -> None:
        capture = self._capture_with_exited_intermediate()

        with patch(
            "agent_observatory.endpoint.windows_live.collect_windows_capture",
            return_value=capture,
        ):
            output = collect_live_snapshot()

        self.assertIn("Gemini (root PID 100)", output)
        self.assertIn("PID=102", output)
        self.assertIn("203.0.113.20:443", output)
        self.assertNotIn("203.0.113.10:443", output)
        self.assertIn("Attribution guard: skipped 1 TCP connection(s)", output)


if __name__ == "__main__":
    unittest.main()
