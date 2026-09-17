from __future__ import annotations

import json
import math
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator

from .models import EventType, ObservationEvent, StoredEvent


EVENT_STORE_SCHEMA_VERSION = 1

_META_TABLE = "event_store_meta"
_EVENTS_TABLE = "events"
_UPDATE_TRIGGER = "events_reject_update"
_DELETE_TRIGGER = "events_reject_delete"
_REPLACE_TRIGGER = "events_reject_replace"


class EventStoreSchemaError(RuntimeError):
    """Raised when an existing EventStore has an unsupported or broken schema."""


class EventStore:
    """SQLite/WAL append-only store for source-attributed observation events."""

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        read_only: bool = False,
    ) -> None:
        self.path = Path(path)
        if str(self.path) == ":memory:":
            raise ValueError("EventStore requires a filesystem-backed SQLite path")
        if busy_timeout_ms < 0:
            raise ValueError("busy_timeout_ms must be non-negative")
        if not isinstance(read_only, bool):
            raise TypeError("read_only must be a boolean")

        self.busy_timeout_ms = busy_timeout_ms
        self.read_only = read_only

        if self.read_only:
            if not self.path.is_file():
                raise FileNotFoundError(f"EventStore does not exist: {self.path}")
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)

        self._initialize()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a transactional connection and always close its OS handle."""

        if self.read_only:
            database = f"{self.path.resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(
                database,
                uri=True,
                timeout=max(self.busy_timeout_ms / 1000, 0.001),
            )
        else:
            connection = sqlite3.connect(
                self.path,
                timeout=max(self.busy_timeout_ms / 1000, 0.001),
            )

        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        if not self.read_only:
            connection.execute("PRAGMA synchronous = NORMAL")

        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connect() as connection:
            if self.read_only:
                meta_exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                    (_META_TABLE,),
                ).fetchone()
                if not meta_exists:
                    raise EventStoreSchemaError(
                        "Existing SQLite file is not an EventStore: "
                        "event_store_meta table is missing"
                    )

                self._validate_existing_schema(connection)

                journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
                if str(journal_mode).casefold() != "wal":
                    raise EventStoreSchemaError(
                        "EventStore requires WAL journal mode, got "
                        f"{journal_mode!r}"
                    )
                return

            journal_mode = connection.execute(
                "PRAGMA journal_mode = WAL"
            ).fetchone()[0]
            if str(journal_mode).casefold() != "wal":
                raise RuntimeError(
                    f"EventStore requires WAL journal mode, got {journal_mode!r}"
                )

            meta_exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
                (_META_TABLE,),
            ).fetchone()

            if meta_exists:
                self._validate_existing_schema(connection)
                return

            connection.execute(
                """
                CREATE TABLE event_store_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                ) WITHOUT ROWID
                """
            )
            connection.execute(
                "INSERT INTO event_store_meta(key, value) VALUES (?, ?)",
                ("schema_version", str(EVENT_STORE_SCHEMA_VERSION)),
            )
            connection.execute(
                """
                CREATE TABLE events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    event_version INTEGER NOT NULL CHECK(event_version > 0),
                    observed_at REAL NOT NULL,
                    recorded_at REAL NOT NULL,
                    source TEXT NOT NULL CHECK(length(source) > 0),
                    stream_id TEXT,
                    payload_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX events_type_id_idx ON events(event_type, event_id)"
            )
            connection.execute(
                "CREATE INDEX events_stream_id_idx ON events(stream_id, event_id)"
            )
            connection.execute(
                "CREATE INDEX events_observed_at_idx ON events(observed_at, event_id)"
            )
            connection.execute(
                f"""
                CREATE TRIGGER {_UPDATE_TRIGGER}
                BEFORE UPDATE ON events
                BEGIN
                    SELECT RAISE(ABORT, 'events table is append-only');
                END
                """
            )
            connection.execute(
                f"""
                CREATE TRIGGER {_DELETE_TRIGGER}
                BEFORE DELETE ON events
                BEGIN
                    SELECT RAISE(ABORT, 'events table is append-only');
                END
                """
            )
            connection.execute(
                f"""
                CREATE TRIGGER {_REPLACE_TRIGGER}
                BEFORE INSERT ON events
                WHEN EXISTS (
                    SELECT 1 FROM events WHERE event_id = NEW.event_id
                )
                BEGIN
                    SELECT RAISE(ABORT, 'events table is append-only');
                END
                """
            )

    def _validate_existing_schema(self, connection: sqlite3.Connection) -> None:
        version_row = connection.execute(
            "SELECT value FROM event_store_meta WHERE key = ?",
            ("schema_version",),
        ).fetchone()
        if version_row is None:
            raise EventStoreSchemaError("EventStore schema version metadata is missing")

        try:
            version = int(version_row["value"])
        except (TypeError, ValueError) as exc:
            raise EventStoreSchemaError(
                f"Invalid EventStore schema version: {version_row['value']!r}"
            ) from exc

        if version != EVENT_STORE_SCHEMA_VERSION:
            raise EventStoreSchemaError(
                "Unsupported EventStore schema version: "
                f"{version}; expected {EVENT_STORE_SCHEMA_VERSION}"
            )

        required_objects = {
            (_EVENTS_TABLE, "table"),
            (_UPDATE_TRIGGER, "trigger"),
            (_DELETE_TRIGGER, "trigger"),
            (_REPLACE_TRIGGER, "trigger"),
        }
        rows = connection.execute(
            "SELECT name, type FROM sqlite_master WHERE name IN (?, ?, ?, ?)",
            (
                _EVENTS_TABLE,
                _UPDATE_TRIGGER,
                _DELETE_TRIGGER,
                _REPLACE_TRIGGER,
            ),
        ).fetchall()
        observed_objects = {(row["name"], row["type"]) for row in rows}
        missing = required_objects - observed_objects
        if missing:
            details = ", ".join(
                f"{object_type}:{name}"
                for name, object_type in sorted(missing)
            )
            raise EventStoreSchemaError(
                f"EventStore schema is incomplete; missing {details}"
            )

    @staticmethod
    def _prepare_event(
        event: ObservationEvent,
    ) -> tuple[EventType, int, float, str, str | None, str, dict[str, object]]:
        if not isinstance(event.event_type, EventType):
            raise TypeError("event_type must be an EventType")
        if not isinstance(event.event_version, int) or isinstance(
            event.event_version, bool
        ):
            raise TypeError("event_version must be an integer")
        if event.event_version <= 0:
            raise ValueError("event_version must be a positive integer")
        if (
            not isinstance(event.observed_at, (int, float))
            or isinstance(event.observed_at, bool)
            or not math.isfinite(float(event.observed_at))
        ):
            raise ValueError("observed_at must be a finite Unix timestamp")
        if not isinstance(event.source, str) or not event.source.strip():
            raise ValueError("source must be a non-empty string")
        if event.stream_id is not None and (
            not isinstance(event.stream_id, str) or not event.stream_id.strip()
        ):
            raise ValueError("stream_id must be None or a non-empty string")

        payload = dict(event.payload)
        if any(not isinstance(key, str) for key in payload):
            raise ValueError("payload keys must be strings")

        payload_json = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        persisted_payload = json.loads(payload_json)
        if not isinstance(persisted_payload, dict):
            raise ValueError("payload must serialize to a JSON object")

        return (
            event.event_type,
            event.event_version,
            float(event.observed_at),
            event.source,
            event.stream_id,
            payload_json,
            persisted_payload,
        )

    def append(self, event: ObservationEvent) -> StoredEvent:
        return self.append_many((event,))[0]

    def append_many(
        self,
        events: Iterable[ObservationEvent],
    ) -> tuple[StoredEvent, ...]:
        if self.read_only:
            raise RuntimeError("cannot append to read-only EventStore")

        prepared = tuple(self._prepare_event(event) for event in events)
        if not prepared:
            return ()

        stored: list[StoredEvent] = []
        with self._connect() as connection:
            for (
                event_type,
                event_version,
                observed_at,
                source,
                stream_id,
                payload_json,
                payload,
            ) in prepared:
                recorded_at = time.time()
                cursor = connection.execute(
                    """
                    INSERT INTO events(
                        event_type,
                        event_version,
                        observed_at,
                        recorded_at,
                        source,
                        stream_id,
                        payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_type.value,
                        event_version,
                        observed_at,
                        recorded_at,
                        source,
                        stream_id,
                        payload_json,
                    ),
                )
                event_id = cursor.lastrowid
                if event_id is None:
                    raise RuntimeError("SQLite did not return an event_id")

                stored.append(
                    StoredEvent(
                        event_id=int(event_id),
                        event_type=event_type,
                        event_version=event_version,
                        observed_at=observed_at,
                        recorded_at=recorded_at,
                        source=source,
                        stream_id=stream_id,
                        payload=payload,
                    )
                )

        return tuple(stored)

    def get_event(self, event_id: int) -> StoredEvent | None:
        if event_id <= 0:
            return None

        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE event_id = ?",
                (event_id,),
            ).fetchone()

        return self._row_to_event(row) if row is not None else None

    def read_events(
        self,
        *,
        after_id: int = 0,
        event_types: Iterable[EventType] | None = None,
        stream_id: str | None = None,
        limit: int | None = None,
    ) -> tuple[StoredEvent, ...]:
        if after_id < 0:
            raise ValueError("after_id must be non-negative")
        if limit is not None and limit <= 0:
            raise ValueError("limit must be positive when provided")

        clauses = ["event_id > ?"]
        parameters: list[object] = [after_id]

        if event_types is not None:
            selected_types = tuple(event_types)
            if not selected_types:
                return ()
            if any(not isinstance(item, EventType) for item in selected_types):
                raise TypeError("event_types must contain only EventType values")
            placeholders = ",".join("?" for _ in selected_types)
            clauses.append(f"event_type IN ({placeholders})")
            parameters.extend(item.value for item in selected_types)

        if stream_id is not None:
            if not isinstance(stream_id, str) or not stream_id.strip():
                raise ValueError("stream_id must be a non-empty string")
            clauses.append("stream_id = ?")
            parameters.append(stream_id)

        query = (
            "SELECT * FROM events WHERE "
            + " AND ".join(clauses)
            + " ORDER BY event_id ASC"
        )
        if limit is not None:
            query += " LIMIT ?"
            parameters.append(limit)

        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()

        return tuple(self._row_to_event(row) for row in rows)

    def list_stream_ids(self) -> tuple[str, ...]:
        """Return non-null stream ids in first-append order."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT stream_id, MIN(event_id) AS first_event_id
                FROM events
                WHERE stream_id IS NOT NULL
                GROUP BY stream_id
                ORDER BY first_event_id ASC
                """
            ).fetchall()

        return tuple(str(row["stream_id"]) for row in rows)

    def stream_exists(self, stream_id: str) -> bool:
        if not isinstance(stream_id, str) or not stream_id.strip():
            raise ValueError("stream_id must be a non-empty string")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM events WHERE stream_id = ? LIMIT 1",
                (stream_id,),
            ).fetchone()
        return row is not None

    def count_events(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def journal_mode(self) -> str:
        with self._connect() as connection:
            return str(connection.execute("PRAGMA journal_mode").fetchone()[0])

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> StoredEvent:
        payload = json.loads(row["payload_json"])
        if not isinstance(payload, dict):
            raise EventStoreSchemaError(
                f"Event {row['event_id']} payload is not a JSON object"
            )

        try:
            event_type = EventType(row["event_type"])
        except ValueError as exc:
            raise EventStoreSchemaError(
                f"Event {row['event_id']} has unknown type {row['event_type']!r}"
            ) from exc

        return StoredEvent(
            event_id=int(row["event_id"]),
            event_type=event_type,
            event_version=int(row["event_version"]),
            observed_at=float(row["observed_at"]),
            recorded_at=float(row["recorded_at"]),
            source=str(row["source"]),
            stream_id=(str(row["stream_id"]) if row["stream_id"] is not None else None),
            payload=payload,
        )
