import tempfile
import unittest
from pathlib import Path

from agent_observatory.analysis import compare_streams, summarize_stream
from agent_observatory.storage import EventStore, EventType, ObservationEvent


class StreamHistoryTests(unittest.TestCase):
    @staticmethod
    def _event(
        event_type: EventType,
        *,
        stream_id: str,
        observed_at: float,
        payload: dict[str, object],
        source: str = "history-test",
    ) -> ObservationEvent:
        return ObservationEvent(
            event_type=event_type,
            observed_at=observed_at,
            source=source,
            stream_id=stream_id,
            payload=payload,
        )

    def test_summarize_stream_reports_ranges_counts_and_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many(
                (
                    self._event(
                        EventType.PROCESS_OBSERVED,
                        stream_id="stream-1",
                        observed_at=10.0,
                        payload={"pid": 1, "started_at": 1.0},
                        source="sensor-a",
                    ),
                    self._event(
                        EventType.TCP_CONNECTION_OBSERVED,
                        stream_id="stream-1",
                        observed_at=12.0,
                        payload={"process": {"pid": 1, "started_at": 1.0}},
                        source="sensor-b",
                    ),
                    self._event(
                        EventType.PROCESS_OBSERVED,
                        stream_id="stream-2",
                        observed_at=20.0,
                        payload={"pid": 2, "started_at": 2.0},
                    ),
                )
            )

            summary = summarize_stream(store, "stream-1")

        self.assertIsNotNone(summary)
        assert summary is not None
        self.assertEqual(summary.event_count, 2)
        self.assertEqual((summary.first_event_id, summary.last_event_id), (1, 2))
        self.assertEqual((summary.observed_start, summary.observed_end), (10.0, 12.0))
        self.assertEqual(summary.sources, ("sensor-a", "sensor-b"))
        self.assertEqual(
            dict(summary.event_counts),
            {
                EventType.PROCESS_OBSERVED: 1,
                EventType.TCP_CONNECTION_OBSERVED: 1,
            },
        )

    def test_compare_ignores_hash_timing_and_provenance_metadata(self) -> None:
        base_payload = {
            "process": {"pid": 10, "started_at": 100.0},
            "path": r"C:\\App\\app.exe",
            "file_identity": {"volume_serial": 1, "file_id": 2},
            "sha256": "abc",
            "state": "hashed",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(
                self._event(
                    EventType.FILE_HASH_OBSERVED,
                    stream_id="before",
                    observed_at=10.0,
                    payload={
                        **base_payload,
                        "hash_gap_ms": 100.0,
                        "observation_time_basis": "first",
                        "identity_build_window_started_at": 9.0,
                        "identity_build_window_finished_at": 10.0,
                    },
                )
            )
            store.append(
                self._event(
                    EventType.FILE_HASH_OBSERVED,
                    stream_id="after",
                    observed_at=20.0,
                    payload={
                        **base_payload,
                        "hash_gap_ms": 900.0,
                        "observation_time_basis": "second",
                        "identity_build_window_started_at": 18.0,
                        "identity_build_window_finished_at": 20.0,
                    },
                )
            )

            diff = compare_streams(store, "before", "after")

        self.assertFalse(diff.has_changes)
        item = diff.by_type[0]
        self.assertEqual(item.unchanged_count, 1)
        self.assertFalse(item.added)
        self.assertFalse(item.removed)
        self.assertFalse(item.changed)

    def test_compare_marks_same_process_instance_payload_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            common = {
                "pid": 10,
                "ppid": 1,
                "started_at": 100.0,
                "name": "client.exe",
                "command_line_sha256": "abc",
            }
            store.append(
                self._event(
                    EventType.PROCESS_OBSERVED,
                    stream_id="before",
                    observed_at=10.0,
                    payload={**common, "executable_path": r"C:\\Old\\client.exe"},
                )
            )
            store.append(
                self._event(
                    EventType.PROCESS_OBSERVED,
                    stream_id="after",
                    observed_at=20.0,
                    payload={**common, "executable_path": r"C:\\New\\client.exe"},
                )
            )

            diff = compare_streams(store, "before", "after")

        self.assertTrue(diff.has_changes)
        item = diff.by_type[0]
        self.assertEqual(len(item.changed), 1)
        self.assertFalse(item.added)
        self.assertFalse(item.removed)

    def test_compare_tcp_facts_as_added_and_removed(self) -> None:
        def tcp(remote: str) -> dict[str, object]:
            return {
                "process": {"pid": 10, "started_at": 100.0},
                "state": "Established",
                "local_address": "10.0.0.5",
                "local_port": 50000,
                "remote_address": remote,
                "remote_port": 443,
                "attribution_basis": "stable_process_instance",
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(
                self._event(
                    EventType.TCP_CONNECTION_OBSERVED,
                    stream_id="before",
                    observed_at=10.0,
                    payload=tcp("203.0.113.10"),
                )
            )
            store.append(
                self._event(
                    EventType.TCP_CONNECTION_OBSERVED,
                    stream_id="after",
                    observed_at=20.0,
                    payload=tcp("203.0.113.20"),
                )
            )

            diff = compare_streams(store, "before", "after")

        self.assertTrue(diff.has_changes)
        item = diff.by_type[0]
        self.assertEqual(len(item.added), 1)
        self.assertEqual(len(item.removed), 1)
        self.assertFalse(item.changed)


if __name__ == "__main__":
    unittest.main()
