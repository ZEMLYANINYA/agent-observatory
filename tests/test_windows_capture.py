import json
import unittest

from agent_observatory.endpoint.windows_capture import (
    attributable_tcp_connections,
    parse_windows_capture,
    rejected_tcp_connections,
    same_process_instance,
    stable_processes,
)
from agent_observatory.endpoint.models import ProcessSnapshot


def _capture_payload() -> dict:
    return {
        "process_before_started_at": "2026-09-14T07:00:00.0000000Z",
        "process_before_finished_at": "2026-09-14T07:00:00.0500000Z",
        "network_started_at": "2026-09-14T07:00:00.0510000Z",
        "network_finished_at": "2026-09-14T07:00:00.0800000Z",
        "process_after_started_at": "2026-09-14T07:00:00.0810000Z",
        "process_after_finished_at": "2026-09-14T07:00:00.1300000Z",
        "processes_before": [
            {
                "pid": 100,
                "ppid": 1,
                "name": "ChatGPT.exe",
                "started_at": "2026-09-14T06:59:00.0000000Z",
                "command_line": "ChatGPT.exe --type=browser",
                "executable_path": "C:\\Apps\\ChatGPT.exe",
            },
            {
                "pid": 200,
                "ppid": 100,
                "name": "ChatGPT.exe",
                "started_at": "2026-09-14T06:59:30.0000000Z",
                "command_line": "ChatGPT.exe --type=renderer",
                "executable_path": "C:\\Apps\\ChatGPT.exe",
            },
        ],
        "tcp_connections": [
            {
                "pid": 100,
                "state": "Established",
                "local_address": "192.0.2.10",
                "local_port": 50000,
                "remote_address": "198.51.100.20",
                "remote_port": 443,
            },
            {
                "pid": 200,
                "state": "Established",
                "local_address": "192.0.2.10",
                "local_port": 50001,
                "remote_address": "198.51.100.30",
                "remote_port": 443,
            },
            {
                "pid": 300,
                "state": "Established",
                "local_address": "192.0.2.10",
                "local_port": 50002,
                "remote_address": "198.51.100.40",
                "remote_port": 443,
            },
        ],
        "processes_after": [
            {
                "pid": 100,
                "ppid": 1,
                "name": "ChatGPT.exe",
                "started_at": "2026-09-14T06:59:00.0000000Z",
                "command_line": "ChatGPT.exe --type=browser",
                "executable_path": "c:/apps/chatgpt.exe",
            },
            {
                "pid": 200,
                "ppid": 1,
                "name": "other.exe",
                "started_at": "2026-09-14T07:00:00.0600000Z",
                "command_line": "other.exe",
                "executable_path": "C:\\Temp\\other.exe",
            },
        ],
    }


class WindowsCaptureTests(unittest.TestCase):
    def test_parse_capture_preserves_intervals(self) -> None:
        capture = parse_windows_capture(json.dumps(_capture_payload()))

        self.assertEqual(len(capture.processes_before), 2)
        self.assertEqual(len(capture.tcp_connections), 3)
        self.assertEqual(len(capture.processes_after), 2)
        self.assertEqual(
            capture.processes_before[0].executable_path,
            "C:\\Apps\\ChatGPT.exe",
        )
        self.assertGreater(capture.total_duration_seconds, 0.0)
        self.assertGreater(capture.network_interval.duration_seconds, 0.0)

    def test_same_process_instance_rejects_reused_pid(self) -> None:
        before = ProcessSnapshot(
            pid=200,
            ppid=100,
            name="ChatGPT.exe",
            started_at=10.0,
            command_line="ChatGPT.exe --type=renderer",
            executable_path="C:\\Apps\\ChatGPT.exe",
        )
        after = ProcessSnapshot(
            pid=200,
            ppid=1,
            name="other.exe",
            started_at=11.0,
            command_line="other.exe",
            executable_path="C:\\Temp\\other.exe",
        )

        self.assertFalse(same_process_instance(before, after))

    def test_same_process_instance_rejects_path_change(self) -> None:
        before = ProcessSnapshot(
            pid=200,
            ppid=100,
            name="ChatGPT.exe",
            started_at=10.0,
            command_line="ChatGPT.exe --type=renderer",
            executable_path="C:\\Apps\\ChatGPT.exe",
        )
        after = ProcessSnapshot(
            pid=200,
            ppid=100,
            name="ChatGPT.exe",
            started_at=10.0,
            command_line="ChatGPT.exe --type=renderer",
            executable_path="C:\\Temp\\ChatGPT.exe",
        )

        self.assertFalse(same_process_instance(before, after))

    def test_stable_processes_keep_only_bracketed_identity(self) -> None:
        capture = parse_windows_capture(json.dumps(_capture_payload()))

        self.assertEqual(
            [process.pid for process in stable_processes(capture)],
            [100],
        )

    def test_tcp_attribution_rejects_reused_and_unseen_pids(self) -> None:
        capture = parse_windows_capture(json.dumps(_capture_payload()))

        self.assertEqual(
            [connection.pid for connection in attributable_tcp_connections(capture)],
            [100],
        )
        self.assertEqual(
            [connection.pid for connection in rejected_tcp_connections(capture)],
            [200, 300],
        )
        self.assertEqual(
            [
                connection.pid
                for connection in rejected_tcp_connections(
                    capture,
                    {100, 200},
                )
            ],
            [200],
        )


if __name__ == "__main__":
    unittest.main()
