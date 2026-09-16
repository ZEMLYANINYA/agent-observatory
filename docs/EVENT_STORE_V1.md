# EventStore v1

## Purpose

EventStore v1 is the first durable evidence layer for Agent Observatory.

Its job is deliberately narrow:

> persist source-attributed observations in append order without turning them into causal conclusions.

Endpoint collectors, application discovery, network sensors, operator markers, and later service-exposure sensors can emit observations into the same local store. Relationship reconstruction, semantic drift analysis, anomaly detection, and Evidence Graph projections remain derived layers above the evidence log.

## Design rules

EventStore v1 follows these rules:

1. **Append-only observations.** Existing event rows are not mutated through the supported schema.
2. **Facts before interpretation.** The store records what a sensor or operator observed, not a verdict about why it happened.
3. **Source attribution is mandatory.** Every event identifies the source that produced it.
4. **Observation time and storage time are separate.** `observed_at` describes when the source observed the fact; `recorded_at` describes when EventStore persisted it.
5. **Event payloads are versioned.** Each row carries `event_version`, independent of the database schema version.
6. **Capture/session grouping is explicit.** Optional `stream_id` groups related observations without implying causality.
7. **Append order is not observation order.** `event_id` is a durable local append sequence, while `observed_at` carries observation time.
8. **SQLite is local-first.** No remote service is required.
9. **Storage stays semantically simple.** Endpoint-specific interpretation lives in adapters and analysis layers, not in SQLite.

## Storage engine

V1 uses Python's standard-library `sqlite3` module and a filesystem-backed SQLite database.

The store enables:

```text
journal_mode = WAL
synchronous  = NORMAL
foreign_keys = ON
busy_timeout = configurable, default 5000 ms
```

WAL is required because later Observatory components may have one writer while readers inspect already committed evidence.

`EventStore(':memory:')` is intentionally rejected. The implementation opens short-lived SQLite connections per operation and explicitly closes them, including on Windows where an unclosed SQLite handle prevents temporary database deletion.

## Database schema

Schema version is stored in:

```text
event_store_meta
  key   TEXT PRIMARY KEY
  value TEXT NOT NULL
```

Current schema version:

```text
1
```

The append log is:

```text
events
  event_id      INTEGER PRIMARY KEY AUTOINCREMENT
  event_type    TEXT NOT NULL
  event_version INTEGER NOT NULL
  observed_at   REAL NOT NULL
  recorded_at   REAL NOT NULL
  source        TEXT NOT NULL
  stream_id     TEXT NULL
  payload_json  TEXT NOT NULL
```

Indexes exist for:

```text
(event_type, event_id)
(stream_id, event_id)
(observed_at, event_id)
```

## Append-only enforcement

Append-only behavior is enforced in two places.

The Python API exposes append/read operations only. More importantly, the database installs three guards on `events`:

```text
events_reject_update
events_reject_delete
events_reject_replace
```

They reject:

```text
UPDATE
DELETE
INSERT OR REPLACE against an existing event_id
```

with:

```text
events table is append-only
```

The replace guard exists because SQLite replacement semantics can otherwise remove and recreate a row while bypassing the intuitive meaning of append-only history.

These triggers are application-integrity controls. They are not protection against an administrator or attacker who can replace the database file or deliberately modify the SQLite schema.

## Event model

Producers append `ObservationEvent` values:

```text
event_type
observed_at
source
payload
stream_id      optional
event_version  default 1
```

Successful writes return `StoredEvent` values that additionally contain:

```text
event_id
recorded_at
```

Payloads must serialize to a JSON object. Serialization uses:

```text
UTF-8 / ensure_ascii=False
sorted keys
compact separators
NaN / Infinity rejected
```

This is not a content-addressed event log. Canonical serialization primarily makes persisted payloads predictable and prevents accidental non-JSON values.

## Event types

V1 defines:

```text
PROCESS_OBSERVED
PROCESS_RELATIONSHIP_OBSERVED
FILE_IDENTITY_OBSERVED
FILE_HASH_OBSERVED
TCP_CONNECTION_OBSERVED
APPLICATION_DISCOVERY_OBSERVED
OPERATOR_MARKER_OBSERVED
```

These names describe evidence categories, not conclusions.

### PROCESS_OBSERVED

Represents one observed process instance.

The endpoint adapter persists:

```text
pid
ppid
started_at
name
executable_path
command_line_sha256
```

The raw command line is deliberately not persisted in EventStore v1. This reduces the chance of turning the evidence database into a store of accidentally captured tokens or sensitive arguments.

### PROCESS_RELATIONSHIP_OBSERVED

Represents parent/child relationship evidence while preserving:

```text
child process instance
reported parent PID
parent process instance when observed
state
basis
reason
```

The relationship basis remains explicit:

```text
current_snapshot
parent_observed_before_only
reported_ppid_only
```

Temporal or PPID correlation is not silently promoted to causality.

### FILE_IDENTITY_OBSERVED

Represents filesystem object identity observed through a Windows file handle:

```text
volume_serial
file_id
```

`FileIdentity` does not currently carry an independent timestamp, so adapters must provide an explicit observation anchor and `observation_time_basis` rather than manufacturing per-file precision.

### FILE_HASH_OBSERVED

Represents the separate post-capture executable content observation.

It preserves:

```text
sha256
hash state
hash_gap_ms
file identity when available
observation_time_basis
```

The digest does not prove the exact bytes mapped into an already-running process.

### TCP_CONNECTION_OBSERVED

Represents one point-in-time TCP record attributed only after the before/after process capture guard validates the owning process instance.

The event keeps TCP state explicit. For example:

```text
Bound != Established
```

A stable endpoint record does not prove traffic occurred, and a stable count does not imply network inactivity.

### APPLICATION_DISCOVERY_OBSERVED

Preserves application discovery outcomes as data:

```text
absent
unique
ambiguous
```

Launch-time multiple-root ambiguity is therefore evidence, not a generic capture failure.

### OPERATOR_MARKER_OBSERVED

Represents source-attributed human markers such as:

```text
QUERY_SENT
VISIBLE_RESPONSE_COMPLETE
CLIENT_UI_IDLE
```

These markers describe observable UI/operator moments. They do not prove transport idle, server-side completion, or causal relationships.

## `stream_id`

`stream_id` groups observations belonging to one capture, transition session, experiment run, or later monitoring interval.

Live Windows capture currently uses identifiers shaped like:

```text
windows-capture:gemini:20260916T201119Z:e45f91ad
```

Events sharing a stream are related by collection context only. Sharing a stream does not automatically create causal edges between them.

## Batch semantics

`append_many()` validates and serializes the complete input batch before writing.

Consequences:

- an invalid event prevents the batch from being appended;
- valid batches are inserted in supplied order;
- duplicate observations are preserved as separate events with separate `event_id` values;
- one capture can be appended atomically as one event batch.

There is intentionally no deduplication in EventStore v1. Two identical observations at different sampling points remain two observations.

## Windows capture adapter

`windows_capture_event_batch()` converts one bracketed `WindowsCapture` into a deterministic evidence batch.

The current order is:

```text
APPLICATION_DISCOVERY_OBSERVED
PROCESS_OBSERVED
PROCESS_RELATIONSHIP_OBSERVED
FILE_IDENTITY_OBSERVED
FILE_HASH_OBSERVED
TCP_CONNECTION_OBSERVED
```

That order is serialization order only. It is not causal or chronological order.

The adapter:

- retains only selected configured application trees;
- uses only stable process instances for process/TCP attribution;
- includes `started_at` with PIDs to guard against PID reuse;
- preserves external-parent relationship evidence without pulling unrelated processes into the application tree;
- hashes executable files after capture with explicit timing gaps;
- carries observation-time basis metadata for capture-derived timestamps.

## Observation time versus append order

The first live EventStore run immediately demonstrated why these are separate concepts.

One capture observed process inventory first, TCP second, discovery/relationships third, and file evidence last, while EventStore appended the deterministic batch in a different serialization order.

Therefore:

```text
event_id     = append order
observed_at  = observation time
```

The live CLI's `--timeline` output sorts by `observed_at` and still prints `event_id`, so both dimensions remain visible.

## Read semantics

V1 supports ordered reads by append sequence with optional filters for:

```text
after_id
event_type(s)
stream_id
limit
```

Rows from `read_events()` are returned in ascending `event_id` order.

`list_stream_ids()` returns persisted non-null stream identifiers in first-append order.

The storage API does not expose update or delete operations.

## Stream history and semantic comparison

A separate read-only analysis layer provides:

```text
summarize_stream()
compare_streams()
```

and the inspector CLI provides:

```text
eventstore_inspect.py list
eventstore_inspect.py show
eventstore_inspect.py compare
```

If no explicit IDs are supplied, `show` selects the latest stream and `compare` selects the latest two streams.

The inspector refuses a missing database path instead of creating an empty SQLite file by accident.

Semantic comparison is descriptive. It reports:

```text
unchanged
added
removed
changed
```

per evidence type.

Timing/provenance fields such as observation timestamps, storage timestamps, `hash_gap_ms`, and capture timing-basis metadata do not by themselves create semantic drift.

V1 comparison does not label a difference as normal, anomalous, malicious, causal, or important.

## Live capture CLI

`tools/eventstore_capture.py` performs:

```text
WindowsCapture
    -> application/process selection
    -> evidence adapters
    -> one append_many transaction
    -> persisted stream readback
```

It supports named application targets or `all`, optional executable hashing, explicit source/stream IDs, and observed-time timeline output.

Default database path:

```text
.local/agent-observatory.sqlite3
```

Local evidence databases remain outside version control.

## Schema compatibility

Opening an existing EventStore validates:

- EventStore schema version;
- the `events` table;
- `events_reject_update`;
- `events_reject_delete`;
- `events_reject_replace`.

Unsupported or incomplete stores raise `EventStoreSchemaError` instead of being silently modified.

V1 does not implement migrations. A later schema change must add an explicit migration design rather than opportunistically rewriting historical evidence.

## Windows validation

EventStore v1 was validated on the project Windows host with:

```text
126 unittest tests
compileall clean
working tree clean
```

The storage core also passed a direct live SQLite smoke test for:

```text
WAL mode
append/readback
Unicode paths
UPDATE guard
DELETE guard
INSERT OR REPLACE guard
Windows handle release
```

Two consecutive live Gemini captures were then appended to the same database:

```text
stream 1: event_id  1..45
stream 2: event_id 46..90
```

Each stream contained:

```text
10 PROCESS_OBSERVED
10 PROCESS_RELATIONSHIP_OBSERVED
10 FILE_IDENTITY_OBSERVED
10 FILE_HASH_OBSERVED
 4 TCP_CONNECTION_OBSERVED
 1 APPLICATION_DISCOVERY_OBSERVED
```

The second stream did not replace the first. `eventstore_inspect.py compare` reported no semantic changes between the two captured Gemini states.

This validation demonstrates persistence and repeatability for the observed test case. It does not establish that Gemini is always static or that the observed TCP endpoints have any particular purpose.

## What EventStore v1 does not do

V1 intentionally does not:

- infer causality;
- calculate anomaly/risk scores;
- construct Evidence Graph edges;
- automatically classify semantic drift as meaningful or suspicious;
- deduplicate repeated observations;
- capture UDP or QUIC activity;
- measure packet/byte flow;
- encrypt the database;
- provide retention/deletion policy;
- replicate events to another host;
- expose a network API;
- protect evidence against an administrator who can replace the database or schema.

These remain separate layers or later requirements.

## Architectural position

```text
collectors / operator markers
            |
            v
       evidence adapters
            |
            v
  SQLite WAL EventStore
    append-only facts
            |
      +-----+-----+
      |           |
      v           v
stream history  semantic diff
      \           /
       \         /
        v       v
 relationship / drift layer
            |
            v
      Evidence Graph
            |
            v
         analysis
```

The EventStore is the evidence ledger, not the analyst.

## Next layer

EventStore v1 is complete enough to merge independently.

The next architectural layer should build derived structures from persisted events rather than extending storage semantics. Candidate next steps are:

```text
stream drift model
relationship reconstruction from persisted facts
Evidence Graph projections
service-exposure observations
network event/flow telemetry beyond TCP snapshots
```

Those changes should be developed separately so the EventStore remains a small, stable foundation.