import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_observatory.storage import EventStore, EventType, ObservationEvent
from tools.eventstore_inspect import main


class EventStoreInspectToolTests(unittest.TestCase):
    @staticmethod
    def _event(stream_id: str, observed_at: float) -> ObservationEvent:
        return ObservationEvent(
            event_type=EventType.PROCESS_OBSERVED,
            observed_at=observed_at,
            source="inspect-test",
            stream_id=stream_id,
            payload={
                "pid": 10,
                "ppid": 1,
                "started_at": 100.0,
                "name": "client.exe",
                "executable_path": r"C:\\App\\client.exe",
                "command_line_sha256": "abc",
            },
        )

    def _store_with_two_streams(self, path: Path) -> EventStore:
        store = EventStore(path)
        store.append(self._event("stream-before", 10.0))
        store.append(self._event("stream-after", 20.0))
        return store

    def test_list_prints_streams_in_append_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            self._store_with_two_streams(path)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "list"])

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("streams: 2", text)
        self.assertLess(text.index("stream-before"), text.index("stream-after"))

    def test_show_without_id_uses_latest_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            self._store_with_two_streams(path)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "show"])

        self.assertEqual(result, 0)
        self.assertIn("stream_id: stream-after", output.getvalue())

    def test_compare_without_ids_uses_latest_two_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            self._store_with_two_streams(path)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "compare"])

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("before: stream-before", text)
        self.assertIn("after:  stream-after", text)
        self.assertIn("result: no semantic changes observed", text)

    def test_missing_database_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "missing.sqlite3"
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(["--db", str(path), "list"])

            self.assertEqual(result, 1)
            self.assertFalse(path.exists())
            self.assertIn("does not exist", error.getvalue())


if __name__ == "__main__":
    unittest.main()
