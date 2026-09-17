import tempfile
import threading
import unittest
from pathlib import Path

from agent_observatory.storage import EventStore, EventType, ObservationEvent


class EventStoreStreamClaimTests(unittest.TestCase):
    @staticmethod
    def _event(stream_id: str | None, marker: str) -> ObservationEvent:
        return ObservationEvent(
            event_type=EventType.OPERATOR_MARKER_OBSERVED,
            observed_at=1.0,
            source="stream-claim-test",
            stream_id=stream_id,
            payload={"marker": marker, "details": {}},
        )

    def test_require_new_stream_rejects_occupied_stream_without_partial_append(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            first = store.append_many(
                (
                    self._event("capture:one", "first-a"),
                    self._event("capture:one", "first-b"),
                ),
                require_new_stream=True,
            )

            with self.assertRaisesRegex(ValueError, "stream already exists"):
                store.append_many(
                    (
                        self._event("capture:one", "second-a"),
                        self._event("capture:one", "second-b"),
                    ),
                    require_new_stream=True,
                )

            persisted = store.read_events(stream_id="capture:one")

        self.assertEqual(tuple(event.event_id for event in first), (1, 2))
        self.assertEqual(tuple(event.event_id for event in persisted), (1, 2))
        self.assertEqual(
            tuple(event.payload["marker"] for event in persisted),
            ("first-a", "first-b"),
        )

    def test_require_new_stream_requires_one_shared_non_null_stream_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")

            with self.assertRaisesRegex(ValueError, "one non-null stream_id"):
                store.append_many(
                    (
                        self._event("capture:a", "a"),
                        self._event("capture:b", "b"),
                    ),
                    require_new_stream=True,
                )

            with self.assertRaisesRegex(ValueError, "one non-null stream_id"):
                store.append_many(
                    (self._event(None, "none"),),
                    require_new_stream=True,
                )

            self.assertEqual(store.count_events(), 0)

    def test_competing_new_stream_writers_have_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "events.sqlite3"
            EventStore(db)
            barrier = threading.Barrier(2)
            result_lock = threading.Lock()
            results: list[tuple[str, str]] = []

            def writer(marker: str) -> None:
                store = EventStore(db)
                barrier.wait()
                try:
                    store.append_many(
                        (self._event("capture:race", marker),),
                        require_new_stream=True,
                    )
                except ValueError as exc:
                    outcome = ("rejected", str(exc))
                else:
                    outcome = ("committed", marker)
                with result_lock:
                    results.append(outcome)

            first = threading.Thread(target=writer, args=("first",))
            second = threading.Thread(target=writer, args=("second",))
            first.start()
            second.start()
            first.join(timeout=10.0)
            second.join(timeout=10.0)

            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())

            persisted = EventStore(db).read_events(stream_id="capture:race")

        self.assertEqual(len(results), 2)
        self.assertEqual(sum(result[0] == "committed" for result in results), 1)
        self.assertEqual(sum(result[0] == "rejected" for result in results), 1)
        rejected = next(result for result in results if result[0] == "rejected")
        self.assertIn("stream already exists", rejected[1])
        self.assertEqual(len(persisted), 1)
        self.assertIn(persisted[0].payload["marker"], {"first", "second"})


if __name__ == "__main__":
    unittest.main()
