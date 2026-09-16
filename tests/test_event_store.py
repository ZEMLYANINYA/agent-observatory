import math
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agent_observatory.storage import (
    EVENT_STORE_SCHEMA_VERSION,
    EventStore,
    EventStoreSchemaError,
    EventType,
    ObservationEvent,
)


class EventStoreTests(unittest.TestCase):
    @staticmethod
    def _event(
        event_type: EventType = EventType.PROCESS_OBSERVED,
        *,
        observed_at: float = 1_789_588_800.0,
        source: str = "test-sensor",
        stream_id: str | None = "capture-001",
        payload: dict[str, object] | None = None,
    ) -> ObservationEvent:
        return ObservationEvent(
            event_type=event_type,
            observed_at=observed_at,
            source=source,
            stream_id=stream_id,
            payload=payload or {"pid": 1234, "name": "client.exe"},
        )

    def test_initializes_wal_and_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)

            self.assertEqual(store.journal_mode().casefold(), "wal")

            with sqlite3.connect(path) as connection:
                version = connection.execute(
                    "SELECT value FROM event_store_meta WHERE key = 'schema_version'"
                ).fetchone()[0]

        self.assertEqual(int(version), EVENT_STORE_SCHEMA_VERSION)

    def test_append_round_trip_preserves_unicode_and_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            event = self._event(
                event_type=EventType.FILE_IDENTITY_OBSERVED,
                payload={
                    "path": r"C:\Users\САНТЕР\App.exe",
                    "file_identity": {
                        "volume_serial": 1217733704,
                        "file_id": 844424930368352,
                    },
                },
            )

            appended = store.append(event)
            loaded = store.get_event(appended.event_id)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.event_type, EventType.FILE_IDENTITY_OBSERVED)
        self.assertEqual(loaded.event_version, 1)
        self.assertEqual(loaded.observed_at, event.observed_at)
        self.assertEqual(loaded.source, "test-sensor")
        self.assertEqual(loaded.stream_id, "capture-001")
        self.assertEqual(loaded.payload, dict(event.payload))
        self.assertGreaterEqual(loaded.recorded_at, loaded.observed_at)

    def test_append_many_preserves_duplicate_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            event = self._event()

            stored = store.append_many((event, event))

            self.assertEqual(tuple(item.event_id for item in stored), (1, 2))
            self.assertEqual(store.count_events(), 2)
            self.assertEqual(
                tuple(item.payload for item in store.read_events()),
                (dict(event.payload), dict(event.payload)),
            )

    def test_read_events_filters_by_type_stream_after_id_and_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many(
                (
                    self._event(
                        EventType.PROCESS_OBSERVED,
                        stream_id="capture-a",
                        payload={"pid": 1},
                    ),
                    self._event(
                        EventType.TCP_CONNECTION_OBSERVED,
                        stream_id="capture-a",
                        payload={"pid": 1, "state": "Established"},
                    ),
                    self._event(
                        EventType.PROCESS_OBSERVED,
                        stream_id="capture-b",
                        payload={"pid": 2},
                    ),
                )
            )

            by_type = store.read_events(
                event_types=(EventType.PROCESS_OBSERVED,)
            )
            by_stream = store.read_events(stream_id="capture-a")
            after = store.read_events(after_id=1, limit=1)

        self.assertEqual(tuple(item.event_id for item in by_type), (1, 3))
        self.assertEqual(tuple(item.event_id for item in by_stream), (1, 2))
        self.assertEqual(tuple(item.event_id for item in after), (2,))

    def test_append_many_validates_entire_batch_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            good = self._event(payload={"pid": 1})
            bad = self._event(payload={"not_json": object()})

            with self.assertRaises(TypeError):
                store.append_many((good, bad))

            self.assertEqual(store.count_events(), 0)

    def test_database_triggers_reject_update_and_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            store = EventStore(path)
            stored = store.append(self._event())

            with sqlite3.connect(path) as connection:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "UPDATE events SET source = ? WHERE event_id = ?",
                        ("mutated", stored.event_id),
                    )

            with sqlite3.connect(path) as connection:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(
                        "DELETE FROM events WHERE event_id = ?",
                        (stored.event_id,),
                    )

            self.assertEqual(store.count_events(), 1)
            self.assertEqual(store.get_event(stored.event_id).source, "test-sensor")

    def test_rejects_unsupported_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            EventStore(path)

            with sqlite3.connect(path) as connection:
                connection.execute(
                    "UPDATE event_store_meta SET value = ? WHERE key = 'schema_version'",
                    ("999",),
                )

            with self.assertRaises(EventStoreSchemaError):
                EventStore(path)

    def test_rejects_incomplete_existing_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "events.sqlite3"
            EventStore(path)

            with sqlite3.connect(path) as connection:
                connection.execute("DROP TRIGGER events_reject_delete")

            with self.assertRaises(EventStoreSchemaError):
                EventStore(path)

    def test_rejects_non_finite_observed_at(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")

            for value in (math.nan, math.inf, -math.inf):
                with self.subTest(value=value):
                    with self.assertRaises(ValueError):
                        store.append(self._event(observed_at=value))

            self.assertEqual(store.count_events(), 0)

    def test_empty_append_many_is_noop(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")

            self.assertEqual(store.append_many(()), ())
            self.assertEqual(store.count_events(), 0)


if __name__ == "__main__":
    unittest.main()
