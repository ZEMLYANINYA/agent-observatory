# Evidence Graph v1

## Purpose

Evidence Graph v1 is a deterministic, read-only projection of one persisted EventStore stream.

Its job is deliberately narrow:

> link already stored observations into identity-bearing nodes and evidence-backed relations without promoting temporal correlation into causality.

EventStore remains the durable source of truth. The graph is derived and can be rebuilt at any time from stored events.

## Architectural rule

Agent Observatory keeps the layers separate:

```text
EventStore
  stores observations
      |
      v
Evidence Graph
  links observations
      |
      v
Analysis
  interprets derived structure
```

The graph does not replace or rewrite EventStore evidence.

## Projection scope

Evidence Graph v1 projects exactly one `stream_id` at a time.

Mixed streams are rejected. Events without an explicit stream id are also rejected because the projection must have a clear collection boundary.

Projection order is deterministic and based on persisted `event_id` ordering, but event order is not treated as causal order.

## Node types

V1 defines four node types.

### APPLICATION

Represents an application profile name observed through `APPLICATION_DISCOVERY_OBSERVED`.

Node identity:

```text
application:<casefolded-name>
```

Example:

```text
application:gemini
```

### PROCESS_INSTANCE

Represents one process instance, never PID alone.

Identity is:

```text
pid + started_at
```

Node id:

```text
process:<pid>@<started_at>
```

This preserves the process-instance rule already established in the endpoint layer and avoids collapsing PID reuse into one entity.

A process node can be created from process evidence, discovery evidence, relationship evidence, file evidence, or TCP evidence when that event carries a valid process-instance reference.

Therefore the number of process nodes can exceed the number of `PROCESS_OBSERVED` events. For example, an observed external parent may appear only through relationship evidence.

### FILE_IDENTITY

Represents a Windows filesystem object identity observed through a file handle.

Identity is:

```text
volume_serial + file_id
```

Node id:

```text
file:<volume_serial>:<file_id>
```

A path is not the node identity. Paths remain edge/evidence attributes because the same path can refer to a different filesystem object after replacement.

### REMOTE_ENDPOINT

Represents an observed remote endpoint.

Identity is currently:

```text
protocol + address + port
```

Node id:

```text
remote:<protocol>:[<address>]:<port>
```

V1 only projects TCP remote endpoints because EventStore v1 currently receives TCP records from the Windows capture path.

## Edge types

V1 defines four edge types.

### DISCOVERED_AS

```text
APPLICATION -> PROCESS_INSTANCE
```

Created from `APPLICATION_DISCOVERY_OBSERVED` candidate evidence.

For an ambiguous discovery result, v1 preserves every valid candidate. It does not choose one candidate heuristically.

### PARENT_OF

```text
PROCESS_INSTANCE -> PROCESS_INSTANCE
```

Created only when `PROCESS_RELATIONSHIP_OBSERVED.state == "valid"` and both process identities are available.

The edge preserves relationship metadata including:

```text
basis
state
reported_parent_pid
reason
```

Unknown or invalid relationship observations remain in EventStore and become projection notes instead of graph edges.

### EXECUTED_FROM

```text
PROCESS_INSTANCE -> FILE_IDENTITY
```

Created from `FILE_IDENTITY_OBSERVED` only when the file identity state is `observed` and both `volume_serial` and `file_id` are present.

The edge preserves the observed path and file-identity timestamp basis.

An unavailable file identity never creates a placeholder file node.

### OBSERVED_TCP_TO

```text
PROCESS_INSTANCE -> REMOTE_ENDPOINT
```

Created from `TCP_CONNECTION_OBSERVED` when a meaningful remote endpoint exists.

The edge preserves:

```text
state
local_address
local_port
attribution_basis
```

Records such as a Windows `Bound` entry with remote `0.0.0.0:0` do not become remote endpoint nodes. They remain represented through projection notes.

The edge name is deliberately `OBSERVED_TCP_TO`, not `CONNECTED_TO`, `SENT_TO`, or `USED_FOR`. A point-in-time TCP record does not prove traffic volume, purpose, or causality.

## Provenance

Every derived node and edge carries one or more `EvidenceRef` values back to persisted EventStore rows:

```text
event_id
event_type
observed_at
source
stream_id
```

This is a hard design rule. A graph object should remain inspectable back to the exact stored observation that justified it.

Graph edges are evidence-backed relations, not unsupported inferred links.

## Projection notes

Evidence Graph v1 does not silently discard event semantics it cannot safely express.

Instead it emits `GraphProjectionNote` values with:

```text
event_id
event_type
reason
```

Examples include:

```text
file_hash_not_projected_v1
operator_marker_not_projected_v1
tcp_remote_endpoint_unavailable
file_identity_unavailable
relationship_not_valid
node_attribute_conflict:...
```

This keeps omitted semantics visible and prevents the graph from pretending to be a complete replacement for EventStore.

## Why file hashes are not nodes in v1

`FILE_HASH_OBSERVED` is intentionally not projected yet.

The current executable hash is a post-capture content observation with explicit timing semantics. Treating the digest immediately as an eternal property of a `FILE_IDENTITY` node could overstate continuity between process execution time and later hash time.

Until the desired graph semantics are specified, file-hash events remain available in EventStore and appear as explicit projection notes.

## Why operator markers are not edges in v1

`OPERATOR_MARKER_OBSERVED` is also intentionally not projected yet.

Markers such as:

```text
QUERY_SENT
VISIBLE_RESPONSE_COMPLETE
```

are observations of operator-visible moments. Connecting them directly to process or network activity with causal-looking edges would exceed the evidence.

They remain persisted and explicitly noted as not projected in v1.

## Determinism

For the same stream contents, projection is deterministic.

Input event iteration order does not change the final node and edge ordering because events are normalized by `event_id`, nodes are sorted by type/id, and edges by their deterministic edge ids.

The graph is therefore suitable for repeatable export, testing, later visualization, and graph-level comparison.

## Attribute conflicts

A node can receive evidence from multiple events.

When a later event supplies a different non-null value for an already established node attribute, v1 does not silently overwrite the existing value. The conflict is preserved as a projection note.

This prevents a derived projection from erasing disagreement between source observations.

## Read-only CLI

`tools/evidence_graph.py` provides a read-only view over an existing EventStore database.

Commands:

```text
show
nodes
edges
json
```

If `--stream-id` is omitted, the latest persisted stream is selected.

The inspector rejects a missing database path rather than creating an empty database accidentally.

### `show`

Prints compact counts by node and edge type, the number of projection notes, and source-event coverage.

### `nodes`

Prints every projected node with attributes and source event ids.

### `edges`

Prints every edge with source/target ids, attributes, evidence ids, and projection notes.

### `json`

Prints a deterministic machine-readable representation containing:

```text
stream_id
nodes
edges
projection_notes
source_event_ids
```

The JSON output is a derived projection, not a second authoritative evidence store.

## Live Windows validation

Evidence Graph v1 was validated against the existing live EventStore database produced by two consecutive Gemini captures.

Windows unit gate before live projection:

```text
Ran 142 tests
OK
working tree clean
```

The latest Gemini stream contained EventStore ids `46..90`, or 45 source events.

The live projection produced:

```text
nodes: 15
  APPLICATION              1
  FILE_IDENTITY            1
  PROCESS_INSTANCE         11
  REMOTE_ENDPOINT          2

edges: 23
  DISCOVERED_AS            1
  PARENT_OF               10
  EXECUTED_FROM           10
  OBSERVED_TCP_TO          2

projection_notes: 12
source_events:     45
```

All 45 source events were accounted for through node evidence, edge evidence, or projection notes.

### Process topology observed in that stream

The application discovery root was one Gemini process instance. Nine additional Gemini process instances were linked through valid current-snapshot parent relationships.

The graph also contained one external parent process instance that was present through relationship evidence but not through `PROCESS_OBSERVED` application-tree evidence. This is expected and demonstrates why graph-node count must not be equated with application process count.

### Executable identity observed in that stream

All ten Gemini application process instances linked through `EXECUTED_FROM` to the same observed filesystem identity:

```text
volume_serial = 1217733704
file_id       = 71494644085169296
```

This means the capture observed those ten process instances referencing the same filesystem object identity. It does not by itself establish when bytes were loaded into each running process.

### TCP projection observed in that stream

One Gemini process instance carried four TCP records in the source stream.

Two records had usable established remote endpoints and produced graph edges to two TCP/443 endpoint nodes.

Two `Bound` records used `0.0.0.0:0` as the remote endpoint and therefore produced:

```text
tcp_remote_endpoint_unavailable
```

projection notes rather than remote nodes.

No purpose, service role, packet flow, byte count, or request causality was inferred from those endpoint observations.

### File-hash notes in that stream

All ten `FILE_HASH_OBSERVED` events remained visible as:

```text
file_hash_not_projected_v1
```

This is intentional, not dropped evidence.

## What Evidence Graph v1 does not do

V1 intentionally does not:

- persist a second graph database;
- mutate EventStore;
- infer causality from time proximity;
- choose a root from ambiguous discovery evidence;
- create relationships from invalid parent evidence;
- treat PID alone as process identity;
- treat executable path alone as file identity;
- turn `Bound 0.0.0.0:0` into a remote service;
- infer network traffic volume or purpose;
- project executable hashes as timeless file properties;
- project operator markers as causal edges;
- merge multiple streams into one graph;
- calculate anomaly or risk scores;
- perform graph-level drift analysis;
- render a graphical UI.

Those are later layers or separate design decisions.

## Architectural position

```text
Windows collectors
      |
      v
Evidence adapters
      |
      v
SQLite/WAL EventStore
  append-only observations
      |
      v
Evidence Graph v1
  deterministic projection
  nodes + evidence-backed edges
      |
      +------------------+
      |                  |
      v                  v
 graph diff/drift     visual projections
      |                  |
      +--------+---------+
               |
               v
            analysis
```

The graph is derived structure with provenance. EventStore remains the evidence ledger.
