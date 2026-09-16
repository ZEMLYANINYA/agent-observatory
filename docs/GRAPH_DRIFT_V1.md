# Graph Drift v1

Graph Drift v1 is the first structural comparison layer built on top of persisted EventStore streams and Evidence Graph v1 projections.

It compares two independently projected evidence graphs and reports what changed in graph structure without assigning importance, anomaly, intent, causality, or maliciousness.

The design rule is:

```text
EventStore stores observations.
Evidence Graph links observations into identity-bearing structure.
Graph Drift compares two derived structures.
Analysis may interpret the result later.
```

## Scope

Graph Drift v1 compares exactly two `EvidenceGraph` objects or two persisted EventStore streams that can be projected into Evidence Graph v1.

It reports four independent dimensions:

```text
node drift
edge drift
process identity continuity
projection-note drift
```

No automatic scoring, anomaly classification, baseline verdict, or causal inference is performed in v1.

## Inputs

The persisted-stream entry point is:

```python
compare_graph_streams(store, before_stream_id, after_stream_id)
```

Internally this performs:

```text
EventStore stream A
        |
        v
Evidence Graph A

EventStore stream B
        |
        v
Evidence Graph B

        |
        v
compare_graphs(A, B)
```

The EventStore remains the durable source of truth. Both Evidence Graph and Graph Drift are derived, read-only layers.

## Provenance is not structural identity

Graph Drift deliberately excludes EventStore provenance identifiers and observation timestamps from structural equality.

For example, these differences alone do not create drift:

```text
event_id
edge_id
recorded_at
observed_at
source-event ordering
```

Two separately captured observations may have different provenance while describing the same graph structure.

This behavior was live-validated using two independently appended Gemini streams where event ids differed but the derived structures matched exactly.

## Node drift

Node identity is inherited from Evidence Graph v1.

Current node identities are:

```text
APPLICATION      application:<casefolded-name>
PROCESS_INSTANCE process:<pid>@<started_at>
FILE_IDENTITY    file:<volume_serial>:<file_id>
REMOTE_ENDPOINT  remote:<protocol>:[<address>]:<port>
```

For each node type Graph Drift reports:

```text
added
removed
changed
unchanged
```

A node is `changed` only when the same `node_id` exists in both graphs but its semantic attributes differ.

If the same node id maps to different node types across graphs, comparison fails instead of silently reconciling the conflict.

## Edge drift

Current Evidence Graph v1 edge types are:

```text
DISCOVERED_AS
PARENT_OF
EXECUTED_FROM
OBSERVED_TCP_TO
```

For each edge type Graph Drift reports:

```text
added
removed
changed
unchanged_count
ambiguous_keys
```

### Edge identity for comparison

Graph Drift groups edges by:

```text
edge_type
source_node_id
target_node_id
```

Exact matching semantic attributes are counted as unchanged.

If one unmatched edge exists before and one unmatched edge exists after for the same endpoint pair, the pair may be represented as one `changed` edge.

If multiple unmatched candidates remain on both sides, Graph Drift does not guess pairings. The endpoint key is recorded in `ambiguous_keys`, while unmatched facts remain explicit as added and removed entries.

This prevents arbitrary correspondence from being invented when the evidence is not sufficient to identify one-to-one edge continuity.

## Process identity continuity

PID is not process identity.

Graph Drift therefore treats process continuity as a separate observation over PID slots.

For PIDs present in both graphs, the corresponding `PROCESS_INSTANCE` node ids are compared.

Statuses are:

```text
same_instance
replaced_instance
mixed
```

### same_instance

The PID maps to the same process instance set in both graphs.

For the common single-instance case:

```text
same PID
+
same started_at
=
same process instance
```

### replaced_instance

The PID exists in both graphs but the before and after process-instance sets do not overlap.

For the common single-instance case:

```text
same PID
+
different started_at
=
replaced process instance
```

This exposes PID reuse rather than silently treating the later process as the same entity.

### mixed

The before and after PID slots share at least one process instance but are not identical sets.

Graph Drift preserves this ambiguity instead of choosing one instance as authoritative.

## Projection-note drift

Evidence Graph v1 intentionally leaves some EventStore semantics unprojected and records explicit `projection_notes`.

Graph Drift compares note counts by:

```text
event_type
reason
```

Event ids are not part of note equality.

The result contains:

```text
added
removed
unchanged_count
```

This is important because projection limitations themselves can change between captures even when graph nodes and edges do not.

## Read-only CLI

`tools/graph_drift.py` provides a read-only operator interface.

### Compare the latest two streams

```powershell
python .\tools\graph_drift.py `
  --db .local\eventstore-v1-live.sqlite3 `
  show
```

### Detailed report

```powershell
python .\tools\graph_drift.py `
  --db .local\eventstore-v1-live.sqlite3 `
  show --details
```

### Machine-readable output

```powershell
python .\tools\graph_drift.py `
  --db .local\eventstore-v1-live.sqlite3 `
  json
```

### Explicit streams

Two specific persisted stream ids can be supplied instead of using the latest two.

The tool does not write to EventStore and rejects a missing database rather than creating an empty one by accident.

## Live validation

Graph Drift v1 was validated on two real Gemini Windows capture streams already stored in the same EventStore database.

Before:

```text
windows-capture:gemini:20260916T200836Z:d2840730
```

After:

```text
windows-capture:gemini:20260916T201119Z:e45f91ad
```

The independently persisted streams had different EventStore ids but projected to the same observed structure.

### Node drift

```text
APPLICATION        unchanged=1    added=0 removed=0 changed=0
PROCESS_INSTANCE   unchanged=11   added=0 removed=0 changed=0
FILE_IDENTITY      unchanged=1    added=0 removed=0 changed=0
REMOTE_ENDPOINT    unchanged=2    added=0 removed=0 changed=0
```

### Edge drift

```text
DISCOVERED_AS      unchanged=1    added=0 removed=0 changed=0 ambiguous=0
PARENT_OF          unchanged=10   added=0 removed=0 changed=0 ambiguous=0
EXECUTED_FROM      unchanged=10   added=0 removed=0 changed=0 ambiguous=0
OBSERVED_TCP_TO    unchanged=2    added=0 removed=0 changed=0 ambiguous=0
```

### Process continuity

```text
compared_pid_slots=11
same_instance=11
replaced_instance=0
mixed=0
```

The 11 stable PID slots include the 10 Gemini process instances plus the externally observed parent process represented by relationship evidence in both graph projections.

### Projection-note drift

```text
unchanged=12
added=0
removed=0
```

The unchanged notes consisted of the intentionally unprojected file-hash observations and Bound-style TCP records whose remote endpoint could not be represented as a meaningful remote node.

### Result

```text
result: no structural changes observed
```

This validates the intended distinction between provenance change and structural change:

```text
capture A event ids != capture B event ids

but

graph structure A == graph structure B
```

## What Graph Drift v1 does not claim

A structural change is not automatically:

```text
an anomaly
malicious behavior
causal behavior
important behavior
unexpected behavior
```

Likewise, no structural change does not prove that nothing happened between observations.

The underlying Windows capture remains point-in-time evidence with known limits. Short-lived processes or connections may be missed, TCP topology is not byte-level traffic, UDP/QUIC are outside the current capture path, and observation windows do not imply causality.

## Current boundaries

Graph Drift v1 does not yet provide:

```text
cross-application graph normalization
graph-level anomaly scoring
multi-stream trend analysis
longitudinal baseline learning
path/subgraph matching
causal inference
visual graph rendering
FILE_HASH graph-property drift
operator-marker graph semantics
```

Those can be layered later without weakening the current evidence model.

## Architectural position

```text
collectors
   |
   v
EventStore
append-only observations
   |
   v
Evidence Graph
read-only structure
   |
   v
Graph Drift
read-only structural comparison
   |
   v
future analysis / review
```

The direction remains one-way: higher layers derive from lower layers. Derived interpretation never rewrites the evidence ledger.
