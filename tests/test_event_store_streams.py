import tempfile
import unittest
from pathlib import Path

from agent_observatory.storage import EventStore, EventType, ObservationEvent


class EventStoreStreamTests(unittest.TestCase):
    @staticmethod
    def _event(stream_id: str | None) -> ObservationEvent:
        return ObservationEvent(
            event_type=EventType.PROCESS_OBSERVED,
            observed_at=1_700_000_000.0,
            source="stream-test",
            stream_id=stream_id,
            payload={"pid": 1, "started_at": 100.0},
        )

    def test_list_stream_ids_uses_first_append_order_and_excludes_null(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many(
                (
                    self._event("stream-b"),
                    self._event(None),
                    self._event("stream-a"),
                    self._event("stream-b"),
                )
            )

            self.assertEqual(
                store.list_stream_ids(),
                ("stream-b", "stream-a"),
            )

    def test_list_stream_ids_empty_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            self.assertEqual(store.list_stream_ids(), ())


if __name__ == "__main__":
    unittest.main()
