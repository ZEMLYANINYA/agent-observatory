import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_observatory.storage import EventStore, EventType, ObservationEvent
from tools.analysis_run import main


class AnalysisRunToolTests(unittest.TestCase):
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
            source="analysis-run-tool-test",
            stream_id=stream_id,
            payload=payload,
        )

    @staticmethod
    def _process_payload(*, name: str = "Gemini.exe") -> dict[str, object]:
        return {
            "pid": 100,
            "ppid": 50,
            "started_at": 1000.0,
            "name": name,
            "executable_path": r"C:\\Google\\Gemini\\Gemini.exe",
            "command_line_sha256": "abc",
        }

    def _append_process(
        self,
        store: EventStore,
        stream_id: str,
        observed_at: float,
        *,
        name: str = "Gemini.exe",
    ) -> None:
        store.append(
            self._event(
                EventType.PROCESS_OBSERVED,
                stream_id,
                observed_at,
                self._process_payload(name=name),
            )
        )

    def test_show_defaults_to_latest_two_streams_and_zero_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_process(store, "before", 1.0)
            self._append_process(store, "after", 2.0)

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "show"])

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("before: before", text)
        self.assertIn("after:  after", text)
        self.assertIn("findings: 0", text)
        self.assertIn("graph-drift-observations v1.0.0 findings=0", text)
        self.assertIn("no severity/confidence/verdict", text)

    def test_json_is_deterministic_and_has_no_evaluative_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_process(store, "before", 1.0)
            self._append_process(store, "after", 2.0)

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
        self.assertEqual(payload["before_stream_id"], "before")
        self.assertEqual(payload["after_stream_id"], "after")
        self.assertEqual(payload["finding_count"], 0)
        self.assertEqual(payload["pass_results"][0]["pass_id"], "graph-drift-observations")
        self.assertEqual(payload["pass_results"][0]["pass_version"], "1.0.0")

        serialized = json.dumps(payload, sort_keys=True)
        for prohibited in ("severity", "confidence", "verdict", "causality", "malicious"):
            self.assertNotIn(f'"{prohibited}"', serialized)

    def test_details_print_nonzero_findings_with_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_process(store, "before", 1.0)
            self._append_process(store, "after", 2.0)
            store.append(
                self._event(
                    EventType.TCP_CONNECTION_OBSERVED,
                    "after",
                    2.1,
                    {
                        "process": {"pid": 100, "started_at": 1000.0},
                        "state": "Established",
                        "local_address": "10.0.0.5",
                        "local_port": 50000,
                        "remote_address": "203.0.113.10",
                        "remote_port": 443,
                        "attribution_basis": "stable_process_instance",
                    },
                )
            )

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["--db", str(path), "show", "--details"])

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("REMOTE_ENDPOINT_APPEARED", text)
        self.assertIn("TCP_RELATION_APPEARED", text)
        self.assertIn("evidence=graph_node:", text)
        self.assertIn("evidence=graph_edge:", text)
        self.assertIn("events=", text)
        self.assertIn("limitation=", text)

    def test_explicit_stream_pair_is_used(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_process(store, "stream-a", 1.0)
            self._append_process(store, "stream-b", 2.0)
            self._append_process(store, "stream-c", 3.0, name="Different.exe")

            output = io.StringIO()
            with redirect_stdout(output):
                result = main(
                    [
                        "--db",
                        str(path),
                        "--before",
                        "stream-a",
                        "--after",
                        "stream-b",
                        "show",
                    ]
                )

        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertIn("before: stream-a", text)
        self.assertIn("after:  stream-b", text)
        self.assertIn("findings: 0", text)

    def test_missing_database_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "missing.sqlite3"
            error = io.StringIO()
            with redirect_stderr(error):
                result = main(["--db", str(path), "show"])

            self.assertEqual(result, 1)
            self.assertFalse(path.exists())
            self.assertIn("database does not exist", error.getvalue())

    def test_insufficient_streams_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_process(store, "only-stream", 1.0)

            error = io.StringIO()
            with redirect_stderr(error):
                result = main(["--db", str(path), "show"])

        self.assertEqual(result, 1)
        self.assertIn("at least two persisted streams", error.getvalue())

    def test_partial_explicit_stream_pair_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            self._append_process(store, "before", 1.0)
            self._append_process(store, "after", 2.0)

            error = io.StringIO()
            with redirect_stderr(error):
                result = main(
                    ["--db", str(path), "--before", "before", "show"]
                )

        self.assertEqual(result, 1)
        self.assertIn("zero stream ids or exactly two", error.getvalue())


if __name__ == "__main__":
    unittest.main()
