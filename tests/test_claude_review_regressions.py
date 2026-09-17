import io
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path

from agent_observatory.analysis import compare_streams
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.evidence import windows_capture_event_batch
from agent_observatory.graph import GraphEdgeType, project_stream
from agent_observatory.storage import EventStore, EventType, ObservationEvent
from tools import evidence_graph as evidence_graph_tool
from tools import eventstore_capture as capture_tool
from tools import service_exposure_capture as service_exposure_tool


class ClaudeReviewRegressionTests(unittest.TestCase):
    @staticmethod
    def _empty_capture() -> WindowsCapture:
        return WindowsCapture(
            processes_before=(),
            tcp_connections=(),
            processes_after=(),
            process_before_interval=CaptureInterval(1.0, 2.0),
            network_interval=CaptureInterval(3.0, 4.0),
            process_after_interval=CaptureInterval(5.0, 6.0),
        )

    @staticmethod
    def _marker(stream_id: str) -> ObservationEvent:
        return ObservationEvent(
            event_type=EventType.OPERATOR_MARKER_OBSERVED,
            observed_at=1.0,
            source="regression-test",
            stream_id=stream_id,
            payload={"marker": "existing", "details": {}},
        )

    def test_evidence_graph_does_not_initialize_foreign_sqlite(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "foreign.sqlite3"
            with closing(sqlite3.connect(db)) as connection:
                connection.execute("CREATE TABLE sentinel(value TEXT)")
                connection.commit()

            before = db.read_bytes()
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = evidence_graph_tool.main(
                    ["--db", str(db), "show"]
                )

            with closing(sqlite3.connect(db)) as connection:
                objects = tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type IN ('table','index','trigger') "
                        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
                    )
                )
            after = db.read_bytes()

        self.assertEqual(code, 1)
        self.assertEqual(objects, ("sentinel",))
        self.assertEqual(before, after)
        self.assertNotIn("event_store_meta", objects)

    def test_read_only_eventstore_reads_but_rejects_append(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "events.sqlite3"
            writable = EventStore(db)
            writable.append(self._marker("stream:1"))

            readonly = EventStore(db, read_only=True)
            self.assertEqual(readonly.count_events(), 1)
            with self.assertRaisesRegex(RuntimeError, "read-only"):
                readonly.append(self._marker("stream:2"))

    def test_graph_rejects_reported_parent_pid_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(
                ObservationEvent(
                    event_type=EventType.PROCESS_RELATIONSHIP_OBSERVED,
                    observed_at=10.0,
                    source="regression-test",
                    stream_id="relationship:mismatch",
                    payload={
                        "child": {"pid": 20, "started_at": 2.0},
                        "reported_parent_pid": 99,
                        "parent": {"pid": 10, "started_at": 1.0},
                        "state": "valid",
                        "basis": "current_snapshot",
                        "reason": "synthetic contradiction",
                    },
                )
            )
            graph = project_stream(store, "relationship:mismatch")

        self.assertFalse(
            any(edge.edge_type is GraphEdgeType.PARENT_OF for edge in graph.edges)
        )
        self.assertIn(
            "relationship_parent_pid_mismatch",
            tuple(note.reason for note in graph.projection_notes),
        )

    def test_windows_capture_rejects_occupied_stream_before_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(self._marker("capture:occupied"))
            called = []

            def provider():
                called.append(True)
                return self._empty_capture()

            with self.assertRaisesRegex(ValueError, "stream already exists"):
                capture_tool.capture_into_store(
                    store,
                    application_names=("Gemini",),
                    source="regression-test",
                    stream_id="capture:occupied",
                    capture_provider=provider,
                )

            self.assertEqual(called, [])
            self.assertEqual(store.count_events(), 1)

    def test_service_exposure_rejects_occupied_stream_before_collection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(self._marker("service-exposure:occupied"))
            called = []

            def provider(*, include_docker):
                called.append(include_docker)
                raise AssertionError("provider must not run")

            with self.assertRaisesRegex(ValueError, "stream already exists"):
                service_exposure_tool.capture_into_store(
                    store,
                    source="regression-test",
                    stream_id="service-exposure:occupied",
                    include_docker=False,
                    capture_provider=provider,
                )

            self.assertEqual(called, [])
            self.assertEqual(store.count_events(), 1)

    def test_unknown_application_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown application target"):
            windows_capture_event_batch(
                self._empty_capture(),
                source="regression-test",
                stream_id="capture:unknown",
                application_names=("Gemnii",),
                hash_executables=False,
            )

    def test_application_target_case_is_canonicalized(self) -> None:
        batch = windows_capture_event_batch(
            self._empty_capture(),
            source="regression-test",
            stream_id="capture:canonical",
            application_names=("gemini",),
            hash_executables=False,
        )

        discovery = tuple(
            event
            for event in batch
            if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED
        )
        self.assertEqual(len(discovery), 1)
        self.assertEqual(discovery[0].payload["application"], "Gemini")
        self.assertEqual(discovery[0].payload["outcome"], "absent")

    def test_event_version_change_is_semantic_change(self) -> None:
        payload = {
            "pid": 10,
            "ppid": 1,
            "started_at": 100.0,
            "name": "client.exe",
            "executable_path": r"C:\\App\\client.exe",
            "command_line_sha256": "abc",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(
                ObservationEvent(
                    event_type=EventType.PROCESS_OBSERVED,
                    event_version=1,
                    observed_at=10.0,
                    source="regression-test",
                    stream_id="before",
                    payload=payload,
                )
            )
            store.append(
                ObservationEvent(
                    event_type=EventType.PROCESS_OBSERVED,
                    event_version=2,
                    observed_at=20.0,
                    source="regression-test",
                    stream_id="after",
                    payload=payload,
                )
            )

            diff = compare_streams(store, "before", "after")

        self.assertTrue(diff.has_changes)
        item = next(
            item
            for item in diff.by_type
            if item.event_type is EventType.PROCESS_OBSERVED
        )
        self.assertEqual(item.unchanged_count, 0)
        self.assertEqual(len(item.changed), 1)
        before_fact = item.changed[0][1]
        after_fact = item.changed[0][2]
        self.assertIn('\"event_version\":1', before_fact)
        self.assertIn('\"event_version\":2', after_fact)


if __name__ == "__main__":
    unittest.main()
