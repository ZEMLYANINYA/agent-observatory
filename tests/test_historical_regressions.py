import io
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr
from pathlib import Path

from agent_observatory.analysis import compare_streams
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.evidence import windows_capture_event_batch
from agent_observatory.graph import GraphEdgeType, project_events
from agent_observatory.storage import EventStore, EventType, ObservationEvent, StoredEvent
from tools import evidence_graph as evidence_graph_tool
from tools.eventstore_capture import capture_into_store


class HistoricalIntegrityRegressionTests(unittest.TestCase):
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

    def test_evidence_graph_does_not_mutate_unrelated_sqlite_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "foreign.sqlite3"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
                connection.execute("INSERT INTO sentinel(value) VALUES ('keep-me')")
                connection.commit()

            with closing(sqlite3.connect(path)) as connection:
                before_objects = tuple(
                    connection.execute(
                        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
                    ).fetchall()
                )
                before_value = connection.execute(
                    "SELECT value FROM sentinel"
                ).fetchone()[0]

            stderr = io.StringIO()
            with redirect_stderr(stderr):
                result = evidence_graph_tool.main(["--db", str(path), "show"])

            with closing(sqlite3.connect(path)) as connection:
                after_objects = tuple(
                    connection.execute(
                        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
                    ).fetchall()
                )
                after_value = connection.execute(
                    "SELECT value FROM sentinel"
                ).fetchone()[0]
                event_store_meta = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='event_store_meta'"
                ).fetchone()

        self.assertEqual(result, 1)
        self.assertEqual(before_objects, after_objects)
        self.assertEqual(before_value, after_value)
        self.assertIsNone(event_store_meta)
        self.assertIn("not an EventStore", stderr.getvalue())

    def test_parent_pid_mismatch_never_becomes_parent_edge(self) -> None:
        event = StoredEvent(
            event_id=1,
            event_type=EventType.PROCESS_RELATIONSHIP_OBSERVED,
            event_version=1,
            observed_at=10.0,
            recorded_at=11.0,
            source="regression-test",
            stream_id="stream-1",
            payload={
                "child": {"pid": 20, "started_at": 200.0},
                "reported_parent_pid": 99,
                "parent": {"pid": 10, "started_at": 100.0},
                "state": "valid",
                "basis": "current_snapshot",
                "reason": None,
            },
        )

        graph = project_events((event,))

        self.assertFalse(
            any(edge.edge_type is GraphEdgeType.PARENT_OF for edge in graph.edges)
        )
        self.assertIn(
            "relationship_parent_pid_mismatch",
            {note.reason for note in graph.projection_notes},
        )

    def test_occupied_stream_is_rejected_before_capture_and_without_new_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(
                ObservationEvent(
                    event_type=EventType.OPERATOR_MARKER_OBSERVED,
                    observed_at=1.0,
                    source="regression-test",
                    stream_id="occupied",
                    payload={"marker": "EXISTING", "details": {}},
                )
            )
            provider_calls = []

            def provider():
                provider_calls.append(True)
                return self._empty_capture()

            before_count = store.count_events()
            with self.assertRaisesRegex(ValueError, "stream already exists"):
                capture_into_store(
                    store,
                    application_names=("Gemini",),
                    source="regression-test",
                    stream_id="occupied",
                    hash_executables=False,
                    capture_provider=provider,
                )
            after_count = store.count_events()

        self.assertEqual(provider_calls, [])
        self.assertEqual(before_count, after_count)

    def test_unknown_target_is_rejected_and_case_variant_is_canonicalized(self) -> None:
        capture = self._empty_capture()

        with self.assertRaisesRegex(ValueError, "unknown application target"):
            windows_capture_event_batch(
                capture,
                source="regression-test",
                stream_id="unknown-target",
                application_names=("Gemnii",),
                hash_executables=False,
                clock=lambda: 10.0,
            )

        batch = windows_capture_event_batch(
            capture,
            source="regression-test",
            stream_id="case-target",
            application_names=("gEmInI",),
            hash_executables=False,
            clock=lambda: 10.0,
        )
        discovery = tuple(
            event
            for event in batch
            if event.event_type is EventType.APPLICATION_DISCOVERY_OBSERVED
        )

        self.assertEqual(len(discovery), 1)
        self.assertEqual(discovery[0].payload["application"], "Gemini")
        self.assertEqual(discovery[0].payload["outcome"], "absent")

    def test_stream_comparison_treats_event_version_change_as_semantic_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            common = {
                "pid": 10,
                "ppid": 1,
                "started_at": 100.0,
                "name": "client.exe",
                "executable_path": r"C:\\App\\client.exe",
                "command_line_sha256": "abc",
            }
            store.append(
                ObservationEvent(
                    event_type=EventType.PROCESS_OBSERVED,
                    event_version=1,
                    observed_at=10.0,
                    source="regression-test",
                    stream_id="before",
                    payload=common,
                )
            )
            store.append(
                ObservationEvent(
                    event_type=EventType.PROCESS_OBSERVED,
                    event_version=2,
                    observed_at=20.0,
                    source="regression-test",
                    stream_id="after",
                    payload=common,
                )
            )

            diff = compare_streams(store, "before", "after")

        self.assertTrue(diff.has_changes)
        item = next(
            entry
            for entry in diff.by_type
            if entry.event_type is EventType.PROCESS_OBSERVED
        )
        self.assertEqual(item.unchanged_count, 0)
        self.assertEqual(len(item.changed), 1)
        self.assertIn('\"event_version\":1', item.changed[0][1])
        self.assertIn('\"event_version\":2', item.changed[0][2])


if __name__ == "__main__":
    unittest.main()
