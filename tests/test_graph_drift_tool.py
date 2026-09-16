import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_observatory.storage import EventStore, EventType, ObservationEvent
from tools.graph_drift import main


class GraphDriftToolTests(unittest.TestCase):
    @staticmethod
    def _event(
        event_type: EventType,
        stream_id: str,
        observed_at: float,
        payload: dict[str, object],
    ) -> ObservationEvent:
        return ObservationEvent(
            event_type=event_type,
            observed_at=observed_at,
            source="graph-drift-tool-test",
            stream_id=stream_id,
            payload=payload,
        )

    def _append_stream(
        self,
        store: EventStore,
        stream_id: str,
        *,
        started_at: float = 1000.0,
        name: str = "Gemini.exe",
        local_port: int = 50000,
    ) -> None:
        process_ref = {"pid": 100, "started_at": started_at}
        store.append_many(
            (
                self._event(
                    EventType.PROCESS_OBSERVED,
                    stream_id,
                    started_at + 1.0,
                    {
                        "pid": 100,
                        "ppid": 50,
                        "started_at": started_at,
                        "name": name,
                        "executable_path": r"C:\\Google\\Gemini\\Gemini.exe",
                        "command_line_sha256": "abc",
                    },
                ),
                self._event(
                    EventType.TCP_CONNECTION_OBSERVED,
                    stream_id,
                    started_at + 2.0,
                    {
                        "process": process_ref,
                        "state": "Established",
                        "local_address": "10.0.0.5",
                        "local_port": local_port,
                        "remote_address": "203.0.113.10",
                        "remote_port": 443,
                        "attribution_basis": "stable_process_instance",
                    },
                ),
                self._event(
                    EventType.FILE_HASH_OBSERVED,
                    stream_id,
                    started_at + 3.0,
                    {
                        "process": process_ref,
                        "path": r"C:\\Google\\Gemini\\Gemini.exe",
                        "file_identity": None,
                        "sha256": "deadbeef",
                        "state": "hashed",
                    },
                ),
            )
        )

    def test_show_defaults_to_latest_two_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_stream(store, "stream-before")
            self._append_stream(store, "stream-after")

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "show"])

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("before: stream-before", text)
        self.assertIn("after:  stream-after", text)
        self.assertIn("same_instance", text)
        self.assertIn("result: no structural changes observed", text)

    def test_explicit_stream_pair_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_stream(store, "stream-one")
            self._append_stream(store, "stream-two")
            self._append_stream(store, "stream-three", name="Changed.exe")

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "--db",
                        str(path),
                        "--before",
                        "stream-one",
                        "--after",
                        "stream-two",
                        "show",
                    ]
                )

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("before: stream-one", text)
        self.assertIn("after:  stream-two", text)
        self.assertIn("result: no structural changes observed", text)

    def test_details_print_changed_node_and_edge_attributes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_stream(store, "stream-before", name="Gemini.exe", local_port=50000)
            self._append_stream(store, "stream-after", name="Gemini Beta.exe", local_port=50001)

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "show", "--details"])

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("~ process:100@1000.0", text)
        self.assertIn("~ OBSERVED_TCP_TO:process:100@1000.0->remote:tcp:[203.0.113.10]:443", text)
        self.assertIn("result: structural changes observed", text)

    def test_json_is_deterministic_and_exposes_continuity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_stream(store, "stream-before")
            self._append_stream(store, "stream-after")

            first = io.StringIO()
            with redirect_stdout(first):
                first_result = main(["--db", str(path), "json"])

            second = io.StringIO()
            with redirect_stdout(second):
                second_result = main(["--db", str(path), "json"])

        self.assertEqual(first_result, 0)
        self.assertEqual(second_result, 0)
        self.assertEqual(first.getvalue(), second.getvalue())

        payload = json.loads(first.getvalue())
        self.assertFalse(payload["has_changes"])
        self.assertEqual(payload["before_stream_id"], "stream-before")
        self.assertEqual(payload["after_stream_id"], "stream-after")
        self.assertEqual(payload["process_continuity"][0]["status"], "same_instance")
        self.assertEqual(payload["projection_notes"]["unchanged_count"], 1)

    def test_json_exposes_pid_reuse_as_replaced_instance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_stream(store, "stream-before", started_at=1000.0)
            self._append_stream(store, "stream-after", started_at=2000.0)

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "json"])

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["has_changes"])
        self.assertEqual(payload["process_continuity"][0]["pid"], 100)
        self.assertEqual(
            payload["process_continuity"][0]["status"],
            "replaced_instance",
        )

    def test_missing_database_and_insufficient_streams_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            missing = Path(temp_dir) / "missing.sqlite3"
            missing_error = io.StringIO()
            with redirect_stderr(missing_error):
                missing_result = main(["--db", str(missing), "show"])

            self.assertEqual(missing_result, 1)
            self.assertFalse(missing.exists())
            self.assertIn("database does not exist", missing_error.getvalue())

            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_stream(store, "only-stream")
            stream_error = io.StringIO()
            with redirect_stderr(stream_error):
                stream_result = main(["--db", str(path), "show"])

        self.assertEqual(stream_result, 1)
        self.assertIn("at least two persisted streams", stream_error.getvalue())


if __name__ == "__main__":
    unittest.main()
