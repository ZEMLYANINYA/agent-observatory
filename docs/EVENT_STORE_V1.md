# EventStore v1

## Purpose

EventStore v1 is the first durable evidence layer for Agent Observatory.

Its job is deliberately narrow:

> persist source-attributed observations in append order without turning them into causal conclusions.

Endpoint collectors, application discovery, network sensors, operator markers, and later service-exposure sensors can all emit events into the same local store. Relationship reconstruction, drift analysis, anomaly detection, and Evidence Graph projections are derived layers above this store.

## Design rules

EventStore v1 follows these rules:

1. **Append-only observations.** Existing event rows are never updated or deleted through the supported schema.
2. **Facts before interpretation.** The store records what a sensor or operator observed, not a verdict about why it happened.
3. **Source attribution is mandatory.** Every event identifies the source that produced it.
4. **Observation time and storage time are separate.** `observed_at` describes when the source observed the fact; `recorded_at` describes when EventStore persisted it.
5. **Event payloads are versioned.** Each row carries `event_version`, independent of the database schema version.
6. **Session/capture grouping is explicit.** Optional `stream_id` groups related observations without implying causality.
7. **Ordering is local and durable.** `event_id` is an append sequence for one EventStore database.
8. **SQLite is local-first.** No remote service is required.

## Storage engine

V1 uses Python's standard-library `sqlite3` module and a filesystem-backed SQLite database.

The store enables:

```text
journal_mode = WAL
synchronous  = NORMAL
foreign_keys = ON
busy_timeout = configurable, default 5000 ms
```

WAL is required because later Observatory components may have one writer while analysis/readers inspect already committed evidence.

`EventStore(':memory:')` is intentionally rejected. The implementation opens short-lived SQLite connections per operation, and the project requirement is durable local evidence rather than ephemeral in-memory state.

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

The Python API exposes append/read operations only. More importantly, the database installs `BEFORE UPDATE` and `BEFORE DELETE` triggers on `events` that abort mutation attempts with:

```text
events table is append-only
```

This protects the evidence invariant even if project code accidentally issues an update or delete through a direct SQLite connection.

The triggers are an application-integrity control, not protection against an administrator or attacker who can replace the database file or deliberately alter the SQLite schema.

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

Payloads must serialize to a JSON object. Serialization is deterministic at the top level:

```text
UTF-8 / ensure_ascii=False
sorted keys
compact separators
NaN / Infinity rejected
```

This is not yet a content-addressed event log. Canonical serialization primarily makes stored payloads predictable and prevents accidental non-JSON values.

## Event types

V1 defines the event names required by EXP-002 findings and the next endpoint-persistence step:

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

Intended for one observed process instance and its directly observed identity metadata.

### PROCESS_RELATIONSHIP_OBSERVED

Intended for parent/child relationship evidence including the relationship basis. The event must preserve whether the basis was current-snapshot evidence, historical jointly-observed evidence, or reported-PPID-only uncertainty.

### FILE_IDENTITY_OBSERVED

Intended for filesystem object identity observed through a Windows file handle, such as volume serial and file ID.

### FILE_HASH_OBSERVED

Intended for the separate post-capture content-hash observation, including explicit hash state and timing gap. It must not imply that the digest proves the bytes mapped by a running process.

### TCP_CONNECTION_OBSERVED

Intended for one point-in-time TCP record attributed to a stable process instance. TCP state must remain explicit. A `Bound` record is not an `Established` remote connection.

### APPLICATION_DISCOVERY_OBSERVED

Intended to preserve discovery outcomes such as:

```text
absent
unique root
ambiguous / multiple candidate roots
```

Startup ambiguity is evidence and should not be collapsed into a generic failure.

### OPERATOR_MARKER_OBSERVED

Intended for source-attributed human markers such as:

```text
QUERY_SENT
VISIBLE_RESPONSE_COMPLETE
```

These markers describe operator-observed UI moments. They do not prove transport idle, server-side inference completion, or causality.

## `stream_id`

`stream_id` is an optional grouping key for observations that belong to one capture, transition session, experiment run, or later monitoring interval.

Examples:

```text
capture:20260916T192800Z
exp002:perplexity:20260916T192800Z
endpoint-poll:host-a:000001
```

The store does not attach semantics to the string. Producers own its naming convention.

Events with the same `stream_id` are related by collection context only. Sharing a stream does not automatically create causal edges between them.

## Batch semantics

`append_many()` validates and serializes the complete input batch before opening the write transaction.

Consequences:

- an invalid event prevents the entire batch from being written;
- valid batches are inserted in supplied order;
- duplicate observations are preserved as separate events with separate `event_id` values.

There is intentionally no deduplication in EventStore v1. Two identical observations at different sampling points are still two observations.

## Read semantics

V1 supports ordered reads by local append sequence with optional filters for:

```text
after_id
event_type(s)
stream_id
limit
```

Rows are returned in ascending `event_id` order.

The storage API does not currently expose update or delete operations.

## Schema compatibility

Opening an existing EventStore validates:

- the EventStore schema version;
- the presence of the `events` table;
- the append-only update trigger;
- the append-only delete trigger.

Unsupported or incomplete stores raise `EventStoreSchemaError` instead of being silently modified.

V1 does not yet implement migrations. A later schema change must add an explicit migration design rather than rewriting historical rows opportunistically.

## What EventStore v1 does not do

V1 intentionally does not:

- infer process relationships;
- infer causal relationships;
- calculate anomaly scores;
- construct Evidence Graph edges;
- deduplicate repeated observations;
- capture endpoint/network data itself;
- monitor UDP or QUIC;
- encrypt the database;
- provide retention/deletion policy;
- replicate events to another host;
- expose a network API.

Those are separate layers or later requirements.

## Next integration step

After the storage core passes the local Windows test gate, add adapters that translate already-hardened endpoint evidence into EventStore events.

The first adapter should cover:

```text
ProcessSnapshot / ProcessInstanceIdentity
    -> PROCESS_OBSERVED

ParentRelation + RelationBasis
    -> PROCESS_RELATIONSHIP_OBSERVED

FileIdentity
    -> FILE_IDENTITY_OBSERVED

FileHashObservation
    -> FILE_HASH_OBSERVED

TcpConnection
    -> TCP_CONNECTION_OBSERVED

application discovery result
    -> APPLICATION_DISCOVERY_OBSERVED
```

Adapter code should preserve existing evidence semantics and should not move interpretation into the storage layer.

## Architectural position

```text
collectors / operator markers
            |
            v
       adapters
            |
            v
  SQLite WAL EventStore
    append-only facts
            |
      +-----+-----+
      |           |
      v           v
relationships   drift/diff
      \           /
       \         /
        v       v
      Evidence Graph
            |
            v
         analysis
```

The EventStore is the evidence ledger, not the analyst.
