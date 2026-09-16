import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.storage import EventStore, EventType
from tools.eventstore_capture import (
    _application_names,
    _print_summary,
    _stream_id,
    capture_into_store,
    main,
)


class EventStoreCaptureToolTests(unittest.TestCase):
    @staticmethod
    def _capture() -> WindowsCapture:
        root = ProcessSnapshot(
            pid=100,
            ppid=50,
            name="Gemini.exe",
            started_at=1000.0,
            command_line='"C:\\Google\\Gemini\\Gemini.exe"',
            executable_path=r"C:\Google\Gemini\Gemini.exe",
        )
        child = ProcessSnapshot(
            pid=101,
            ppid=100,
            name="Gemini.exe",
            started_at=1001.0,
            command_line='"C:\\Google\\Gemini\\Gemini.exe" --type=renderer',
            executable_path=r"C:\Google\Gemini\Gemini.exe",
        )
        return WindowsCapture(
            processes_before=(root, child),
            tcp_connections=(
                TcpConnection(
                    pid=100,
                    state="Established",
                    local_address="10.0.0.5",
                    local_port=50000,
                    remote_address="203.0.113.10",
                    remote_port=443,
                ),
            ),
            processes_after=(root, child),
            process_before_interval=CaptureInterval(10.0, 11.0),
            network_interval=CaptureInterval(11.0, 12.0),
            process_after_interval=CaptureInterval(12.0, 13.0),
        )

    def test_application_names_accepts_all_or_named_targets(self) -> None:
        self.assertIsNone(_application_names(("all",)))
        self.assertIsNone(_application_names(()))
        self.assertEqual(
            _application_names(("Gemini", "Claude")),
            ("Gemini", "Claude"),
        )

        with self.assertRaises(ValueError):
            _application_names(("all", "Gemini"))

    def test_generated_stream_id_contains_target_and_is_unique(self) -> None:
        first = _stream_id(("Gemini",))
        second = _stream_id(("Gemini",))

        self.assertTrue(first.startswith("windows-capture:gemini:"))
        self.assertNotEqual(first, second)

    def test_capture_into_store_uses_real_batch_and_event_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = capture_into_store(
                store,
                application_names=("Gemini",),
                source="tool-test",
                stream_id="live-001",
                hash_executables=False,
                capture_provider=self._capture,
            )
            readback = store.read_events(stream_id="live-001")

        self.assertEqual(
            tuple(event.event_id for event in stored),
            tuple(event.event_id for event in readback),
        )
        self.assertIn(
            EventType.APPLICATION_DISCOVERY_OBSERVED,
            {event.event_type for event in readback},
        )
        self.assertIn(
            EventType.TCP_CONNECTION_OBSERVED,
            {event.event_type for event in readback},
        )
        discovery = next(
            event
            for event in readback
            if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED
        )
        self.assertEqual(discovery.payload["outcome"], "unique")

    def test_summary_reports_discovery_and_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            events = capture_into_store(
                store,
                application_names=("Gemini",),
                source="tool-test",
                stream_id="live-002",
                hash_executables=False,
                capture_provider=self._capture,
            )

            output = io.StringIO()
            with redirect_stdout(output):
                _print_summary(store, events, stream_id="live-002")

        text = output.getvalue()
        self.assertIn("journal_mode: wal", text)
        self.assertIn("Gemini: unique candidates=1", text)
        self.assertIn("PROCESS_OBSERVED", text)
        self.assertIn("TCP_CONNECTION_OBSERVED", text)

    def test_main_persists_and_reads_back_one_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "events.sqlite3"

            def fake_capture_into_store(
                store,
                *,
                application_names,
                source,
                stream_id,
                hash_executables,
            ):
                return capture_into_store(
                    store,
                    application_names=application_names,
                    source=source,
                    stream_id=stream_id,
                    hash_executables=False,
                    capture_provider=self._capture,
                )

            output = io.StringIO()
            with patch(
                "tools.eventstore_capture.capture_into_store",
                side_effect=fake_capture_into_store,
            ), redirect_stdout(output):
                result = main(
                    [
                        "Gemini",
                        "--db",
                        str(db_path),
                        "--stream-id",
                        "live-main-001",
                        "--timeline",
                    ]
                )

            store = EventStore(db_path)
            persisted = store.read_events(stream_id="live-main-001")

        self.assertEqual(result, 0)
        self.assertTrue(persisted)
        self.assertIn("TIMELINE:", output.getvalue())
        self.assertIn("Gemini: unique candidates=1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
