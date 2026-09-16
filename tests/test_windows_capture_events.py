import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.evidence import append_windows_capture, windows_capture_event_batch
from agent_observatory.storage import EventStore, EventType


class WindowsCaptureEventBatchTests(unittest.TestCase):
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

    def _gemini_capture(self) -> WindowsCapture:
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
        child = self._process(
            101,
            100,
            "Gemini Helper.exe",
            101.0,
            command_line='"Gemini Helper.exe" --type=utility',
            executable_path=r"C:\Users\test\AppData\Local\Google\Gemini\Gemini Helper.exe",
        )

        return WindowsCapture(
            processes_before=(parent, root, child),
            tcp_connections=(
                TcpConnection(
                    pid=100,
                    state="Bound",
                    local_address="0.0.0.0",
                    local_port=50000,
                    remote_address="0.0.0.0",
                    remote_port=0,
                ),
                TcpConnection(
                    pid=101,
                    state="Established",
                    local_address="10.0.0.2",
                    local_port=50001,
                    remote_address="142.250.1.1",
                    remote_port=443,
                ),
                TcpConnection(
                    pid=50,
                    state="Established",
                    local_address="10.0.0.2",
                    local_port=50002,
                    remote_address="1.1.1.1",
                    remote_port=443,
                ),
                TcpConnection(
                    pid=999,
                    state="Established",
                    local_address="10.0.0.2",
                    local_port=50003,
                    remote_address="8.8.8.8",
                    remote_port=443,
                ),
            ),
            processes_after=(parent, root, child),
            process_before_interval=CaptureInterval(
                started_at=1_000.0,
                finished_at=1_001.0,
            ),
            network_interval=CaptureInterval(
                started_at=1_001.0,
                finished_at=1_002.0,
            ),
            process_after_interval=CaptureInterval(
                started_at=1_002.0,
                finished_at=1_003.0,
            ),
        )

    @staticmethod
    def _clock(values):
        iterator = iter(values)
        return lambda: next(iterator)

    def test_capture_batch_emits_deterministic_selected_application_evidence(self) -> None:
        events = windows_capture_event_batch(
            self._gemini_capture(),
            source="windows-capture",
            stream_id="capture-001",
            application_names=("Gemini",),
            hash_executables=False,
            clock=self._clock((2_000.0, 2_001.0)),
        )

        self.assertEqual(len(events), 11)
        self.assertEqual(
            tuple(event.event_type for event in events),
            (
                EventType.APPLICATION_DISCOVERY_OBSERVED,
                EventType.PROCESS_OBSERVED,
                EventType.PROCESS_OBSERVED,
                EventType.PROCESS_RELATIONSHIP_OBSERVED,
                EventType.PROCESS_RELATIONSHIP_OBSERVED,
                EventType.FILE_IDENTITY_OBSERVED,
                EventType.FILE_HASH_OBSERVED,
                EventType.FILE_IDENTITY_OBSERVED,
                EventType.FILE_HASH_OBSERVED,
                EventType.TCP_CONNECTION_OBSERVED,
                EventType.TCP_CONNECTION_OBSERVED,
            ),
        )
        self.assertTrue(all(event.stream_id == "capture-001" for event in events))

        discovery = events[0]
        self.assertEqual(discovery.payload["outcome"], "unique")
        self.assertEqual(discovery.payload["candidate_count"], 1)

        process_events = [
            event for event in events
            if event.event_type is EventType.PROCESS_OBSERVED
        ]
        self.assertEqual(
            tuple(event.payload["pid"] for event in process_events),
            (100, 101),
        )
        for event in process_events:
            self.assertNotIn("command_line", event.payload)
            self.assertIn("command_line_sha256", event.payload)
            self.assertEqual(
                event.payload["observation_time_basis"],
                "process_before_inventory_end; stable_across_bracketing_capture",
            )

        relationship_events = [
            event for event in events
            if event.event_type is EventType.PROCESS_RELATIONSHIP_OBSERVED
        ]
        self.assertEqual(
            tuple(event.payload["child"]["pid"] for event in relationship_events),
            (100, 101),
        )
        self.assertEqual(relationship_events[0].payload["parent"]["pid"], 50)
        self.assertEqual(relationship_events[0].payload["parent"]["started_at"], 50.0)
        self.assertEqual(relationship_events[1].payload["parent"]["pid"], 100)
        self.assertEqual(relationship_events[1].payload["parent"]["started_at"], 100.0)

        tcp_events = [
            event for event in events
            if event.event_type is EventType.TCP_CONNECTION_OBSERVED
        ]
        self.assertEqual(
            {event.payload["process"]["pid"] for event in tcp_events},
            {100, 101},
        )
        self.assertNotIn(50, {event.payload["process"]["pid"] for event in tcp_events})
        self.assertNotIn(999, {event.payload["process"]["pid"] for event in tcp_events})
        self.assertTrue(
            all(event.observed_at == 1_002.0 for event in tcp_events)
        )

    def test_file_evidence_uses_explicit_identity_build_window(self) -> None:
        events = windows_capture_event_batch(
            self._gemini_capture(),
            source="windows-capture",
            stream_id="capture-002",
            application_names=("Gemini",),
            hash_executables=False,
            clock=self._clock((2_000.0, 2_005.0)),
        )

        file_events = [
            event for event in events
            if event.event_type in {
                EventType.FILE_IDENTITY_OBSERVED,
                EventType.FILE_HASH_OBSERVED,
            }
        ]
        self.assertEqual(len(file_events), 4)

        for event in file_events:
            self.assertEqual(event.payload["identity_build_window_started_at"], 2_000.0)
            self.assertEqual(event.payload["identity_build_window_finished_at"], 2_005.0)

        identity_events = [
            event for event in file_events
            if event.event_type is EventType.FILE_IDENTITY_OBSERVED
        ]
        self.assertTrue(all(event.observed_at == 2_005.0 for event in identity_events))
        self.assertTrue(
            all(
                event.payload["observation_time_basis"]
                == "identity_build_window_end; exact_per_file_identity_timestamp_unavailable"
                for event in identity_events
            )
        )

        hash_events = [
            event for event in file_events
            if event.event_type is EventType.FILE_HASH_OBSERVED
        ]
        self.assertTrue(all(event.payload["state"] == "not-requested" for event in hash_events))
        self.assertTrue(all(event.payload["observation_time_basis"] == "caller_fallback" for event in hash_events))

    def test_default_batch_records_discovery_for_all_configured_profiles(self) -> None:
        events = windows_capture_event_batch(
            self._gemini_capture(),
            source="windows-capture",
            stream_id="capture-003",
            hash_executables=False,
            clock=self._clock((2_000.0, 2_001.0)),
        )

        discovery_events = [
            event for event in events
            if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED
        ]
        outcomes = {
            event.payload["application"]: event.payload["outcome"]
            for event in discovery_events
        }

        self.assertEqual(outcomes["Gemini"], "unique")
        self.assertEqual(outcomes["Claude"], "absent")
        self.assertEqual(outcomes["Codex"], "absent")
        self.assertEqual(outcomes["Manus"], "absent")
        self.assertEqual(outcomes["Perplexity"], "absent")

    def test_ambiguous_roots_are_preserved_as_discovery_evidence(self) -> None:
        root_a = self._process(
            100,
            50,
            "Gemini.exe",
            100.0,
            executable_path=r"C:\A\Google\Gemini\Gemini.exe",
        )
        root_b = self._process(
            200,
            50,
            "Gemini.exe",
            200.0,
            executable_path=r"C:\B\Google\Gemini\Gemini.exe",
        )
        capture = WindowsCapture(
            processes_before=(root_a, root_b),
            tcp_connections=(),
            processes_after=(root_a, root_b),
            process_before_interval=CaptureInterval(1_000.0, 1_001.0),
            network_interval=CaptureInterval(1_001.0, 1_002.0),
            process_after_interval=CaptureInterval(1_002.0, 1_003.0),
        )

        events = windows_capture_event_batch(
            capture,
            source="windows-capture",
            stream_id="capture-004",
            application_names=("Gemini",),
            hash_executables=False,
            clock=self._clock((2_000.0, 2_001.0)),
        )

        discovery = events[0]
        self.assertEqual(discovery.payload["outcome"], "ambiguous")
        self.assertEqual(discovery.payload["candidate_count"], 2)
        self.assertEqual(
            {candidate["pid"] for candidate in discovery.payload["candidates"]},
            {100, 200},
        )

    def test_append_windows_capture_persists_whole_batch_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = append_windows_capture(
                store,
                self._gemini_capture(),
                source="windows-capture",
                stream_id="capture-005",
                application_names=("Gemini",),
                hash_executables=False,
                clock=self._clock((2_000.0, 2_001.0)),
            )

            readback = store.read_events(stream_id="capture-005")

        self.assertEqual(len(stored), 11)
        self.assertEqual(len(readback), 11)
        self.assertEqual(
            tuple(event.event_id for event in stored),
            tuple(range(1, 12)),
        )
        self.assertEqual(
            tuple(event.event_type for event in readback),
            tuple(event.event_type for event in stored),
        )

    def test_batch_validates_source_stream_and_application_names(self) -> None:
        capture = self._gemini_capture()

        with self.assertRaises(ValueError):
            windows_capture_event_batch(
                capture,
                source="",
                stream_id="capture-006",
                application_names=("Gemini",),
                hash_executables=False,
            )

        with self.assertRaises(ValueError):
            windows_capture_event_batch(
                capture,
                source="windows-capture",
                stream_id="",
                application_names=("Gemini",),
                hash_executables=False,
            )

        with self.assertRaises(ValueError):
            windows_capture_event_batch(
                capture,
                source="windows-capture",
                stream_id="capture-006",
                application_names=(),
                hash_executables=False,
            )


if __name__ == "__main__":
    unittest.main()
