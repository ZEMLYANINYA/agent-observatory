import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_observatory.storage import EventStore, EventType, ObservationEvent
from tools.evidence_graph import main


class EvidenceGraphToolTests(unittest.TestCase):
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
            source="graph-tool-test",
            stream_id=stream_id,
            payload=payload,
        )

    def _store(self, path: Path) -> EventStore:
        store = EventStore(path)
        store.append(
            self._event(
                EventType.PROCESS_OBSERVED,
                "stream-old",
                10.0,
                {
                    "pid": 10,
                    "ppid": 1,
                    "started_at": 100.0,
                    "name": "old.exe",
                    "executable_path": r"C:\\Old\\old.exe",
                    "command_line_sha256": "old",
                },
            )
        )

        stream = "stream-new"
        process_ref = {"pid": 100, "started_at": 1000.0}
        parent_ref = {"pid": 50, "started_at": 900.0}
        events = (
            self._event(
                EventType.APPLICATION_DISCOVERY_OBSERVED,
                stream,
                20.0,
                {
                    "application": "Gemini",
                    "outcome": "unique",
                    "candidate_count": 1,
                    "candidates": [
                        {
                            "pid": 100,
                            "ppid": 50,
                            "started_at": 1000.0,
                            "name": "Gemini.exe",
                            "executable_path": r"C:\\Google\\Gemini\\Gemini.exe",
                        }
                    ],
                },
            ),
            self._event(
                EventType.PROCESS_OBSERVED,
                stream,
                20.1,
                {
                    "pid": 100,
                    "ppid": 50,
                    "started_at": 1000.0,
                    "name": "Gemini.exe",
                    "executable_path": r"C:\\Google\\Gemini\\Gemini.exe",
                    "command_line_sha256": "abc",
                },
            ),
            self._event(
                EventType.PROCESS_RELATIONSHIP_OBSERVED,
                stream,
                20.2,
                {
                    "child": process_ref,
                    "reported_parent_pid": 50,
                    "parent": parent_ref,
                    "state": "valid",
                    "basis": "current_snapshot",
                    "reason": None,
                },
            ),
            self._event(
                EventType.FILE_IDENTITY_OBSERVED,
                stream,
                20.3,
                {
                    "process": process_ref,
                    "path": r"C:\\Google\\Gemini\\Gemini.exe",
                    "state": "observed",
                    "volume_serial": 123,
                    "file_id": 456,
                },
            ),
            self._event(
                EventType.FILE_HASH_OBSERVED,
                stream,
                20.4,
                {
                    "process": process_ref,
                    "path": r"C:\\Google\\Gemini\\Gemini.exe",
                    "file_identity": {"volume_serial": 123, "file_id": 456},
                    "sha256": "deadbeef",
                    "state": "hashed",
                },
            ),
            self._event(
                EventType.TCP_CONNECTION_OBSERVED,
                stream,
                20.5,
                {
                    "process": process_ref,
                    "state": "Established",
                    "local_address": "10.0.0.5",
                    "local_port": 50000,
                    "remote_address": "203.0.113.10",
                    "remote_port": 443,
                    "attribution_basis": "stable_process_instance",
                },
            ),
        )
        store.append_many(events)
        return store

    def test_show_defaults_to_latest_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            self._store(path)
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "show"])

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("stream_id: stream-new", text)
        self.assertIn("nodes: 5", text)
        self.assertIn("edges: 4", text)
        self.assertIn("projection_notes: 1", text)

    def test_nodes_and_edges_print_identity_and_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            self._store(path)

            nodes_output = io.StringIO()
            with redirect_stdout(nodes_output):
                nodes_result = main(
                    ["--db", str(path), "--stream-id", "stream-new", "nodes"]
                )

            edges_output = io.StringIO()
            with redirect_stdout(edges_output):
                edges_result = main(
                    ["--db", str(path), "--stream-id", "stream-new", "edges"]
                )

        self.assertEqual(nodes_result, 0)
        self.assertEqual(edges_result, 0)
        self.assertIn("APPLICATION", nodes_output.getvalue())
        self.assertIn("process:100@1000.0", nodes_output.getvalue())
        self.assertIn("DISCOVERED_AS", edges_output.getvalue())
        self.assertIn("OBSERVED_TCP_TO", edges_output.getvalue())
        self.assertIn("evidence=", edges_output.getvalue())
        self.assertIn("file_hash_not_projected_v1", edges_output.getvalue())

    def test_json_is_deterministic_and_contains_full_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            self._store(path)

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
        self.assertEqual(payload["stream_id"], "stream-new")
        self.assertEqual(len(payload["nodes"]), 5)
        self.assertEqual(len(payload["edges"]), 4)
        self.assertEqual(len(payload["projection_notes"]), 1)
        self.assertTrue(payload["source_event_ids"])
        self.assertIn("event_id", payload["edges"][0]["evidence"][0])
        self.assertIn("observed_at", payload["edges"][0]["evidence"][0])
        self.assertIn("source", payload["edges"][0]["evidence"][0])

    def test_explicit_missing_stream_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            self._store(path)
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(
                    ["--db", str(path), "--stream-id", "missing", "show"]
                )

        self.assertEqual(result, 1)
        self.assertIn("stream not found", error.getvalue())

    def test_missing_database_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "missing.sqlite3"
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(["--db", str(path), "show"])

            self.assertEqual(result, 1)
            self.assertFalse(path.exists())
            self.assertIn("database does not exist", error.getvalue())


if __name__ == "__main__":
    unittest.main()
