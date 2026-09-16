# Analysis Pass v1

Analysis Pass v1 defines the first deterministic interpretation contract above Graph Drift and includes the first production pass built on that contract.

It does **not** introduce anomaly detection, severity, confidence, causal claims, maliciousness judgments, importance scoring, or automatic blocking.

The architectural rule remains:

```text
EventStore stores observations.
Evidence Graph links observations into identity-bearing structure.
Graph Drift compares two derived structures.
Analysis Passes emit bounded descriptive findings.
Humans or later explicitly designed layers may interpret those findings.
```

## Scope

Analysis Pass v1 provides:

```text
AnalysisContext
AnalysisPass
AnalysisPassMetadata
PassVersion
ReasonCode
AnalysisEvidenceRef
AnalysisFinding
AnalysisPassResult
AnalysisResult
run_analysis_passes(...)
build_analysis_context(...)
```

The first production pass is:

```text
graph-drift-observations v1.0.0
```

Its job is only to translate already-computed Graph Drift into deterministic reviewable findings with complete evidence references.

## Position in the pipeline

```text
Windows capture
      |
      v
EventStore
      |
      v
Evidence Graph A / B
      |
      v
Graph Drift
      |
      v
AnalysisContext
      |
      v
Analysis Passes
      |
      v
AnalysisFinding
```

The data flow is one-way. Analysis never rewrites Graph Drift, Evidence Graph, or EventStore.

## AnalysisContext

`AnalysisContext` contains exactly the evidence needed by v1 passes:

```text
before_graph
after_graph
graph_drift
```

The context validates that:

```text
graph_drift.before_stream_id == before_graph.stream_id
graph_drift.after_stream_id  == after_graph.stream_id
```

This prevents a drift result from being accidentally combined with unrelated graph projections.

The persisted entry point is:

```python
build_analysis_context(store, before_stream_id, after_stream_id)
```

It projects each stream once, computes Graph Drift from those projections, and returns one bounded context.

## AnalysisPass

A pass implements the protocol:

```python
metadata: AnalysisPassMetadata

run(context: AnalysisContext) -> tuple[AnalysisFinding, ...]
```

The return type is intentionally a tuple rather than an arbitrary iterable. This makes pass output explicit and discourages hidden lazy state or order-dependent generators.

### Pass metadata

Each pass has:

```text
pass_id
version
description
```

`pass_id` is stable lowercase kebab-case, for example:

```text
graph-drift-observations
service-exposure-observations
process-lifecycle-observations
```

The ID identifies the analysis algorithm family, not a specific run.

## PassVersion

Pass behavior is explicitly versioned:

```text
major.minor.patch
```

Example:

```text
1.0.0
```

Versions contain three non-negative integers.

A finding must carry the exact version of the pass that emitted it. The runner rejects a finding whose `pass_id` or `pass_version` disagrees with pass metadata.

This matters because derived findings may later be recomputed after an algorithm changes. The stored or exported result must make clear which deterministic logic produced it.

## ReasonCode

`ReasonCode` is a stable machine-readable description of why a finding exists.

Format:

```text
UPPER_SNAKE_CASE
```

The first production pass emits reason-code families such as:

```text
PROCESS_INSTANCE_APPEARED
PROCESS_INSTANCE_DISAPPEARED
PROCESS_IDENTITY_REPLACED
REMOTE_ENDPOINT_APPEARED
REMOTE_ENDPOINT_DISAPPEARED
FILE_IDENTITY_APPEARED
FILE_IDENTITY_DISAPPEARED
PARENT_RELATION_APPEARED
PARENT_RELATION_DISAPPEARED
PARENT_RELATION_ATTRIBUTES_CHANGED
TCP_RELATION_APPEARED
TCP_RELATION_DISAPPEARED
EDGE_CORRESPONDENCE_AMBIGUOUS
PROJECTION_NOTE_COUNT_INCREASED
PROJECTION_NOTE_COUNT_DECREASED
```

A reason code is **not** a severity or verdict.

For example:

```text
REMOTE_ENDPOINT_APPEARED
```

means only that the compared evidence contains a remote endpoint that was not represented in the earlier graph.

It does not mean:

```text
suspicious network activity
malware
exfiltration
unexpected traffic
important event
```

Those are separate interpretations requiring additional evidence and policy.

## AnalysisFinding

A v1 finding contains:

```text
finding_id
pass_id
pass_version
reason_code
summary
evidence
limitations
attributes
```

### Intentionally absent fields

The v1 contract deliberately has no fields named:

```text
severity
confidence
verdict
causality
malicious
```

A regression test locks this surface.

This is not an omission waiting to be casually filled. Those concepts require their own definitions, evidence model, calibration, and review policy.

## Finding identity

`finding_id` must be deterministic and non-empty.

The runner enforces global uniqueness within one analysis run.

The first production pass derives finding IDs from canonical semantic finding content:

```text
pass_id
reason_code
subject attributes
```

It hashes that canonical JSON description and does not use random UUIDs, wall-clock timestamps, or EventStore append IDs as finding identity.

Current shape:

```text
graph-drift-observations:<reason-code-lowercase>:<sha256-prefix>
```

The source `event_id` values remain evidence provenance, not finding identity.

## Evidence references

Every finding must contain at least one `AnalysisEvidenceRef`.

Supported v1 layers are:

```text
EVENT
GRAPH_NODE
GRAPH_EDGE
```

Each evidence reference carries:

```text
layer
reference_id
stream_id
event_ids
```

`event_ids` are sorted, unique, positive EventStore event IDs.

### Evidence-bounded validation

The runner validates every emitted evidence reference against `AnalysisContext`.

A finding cannot reference:

```text
a stream outside before/after context
an EventStore event id not covered by that graph
a graph node that does not exist in the referenced graph
a graph edge that does not exist in the referenced graph
an event id outside the referenced node/edge provenance
```

For `EVENT` references, the canonical reference ID must be:

```text
event:<event_id>
```

This prevents an analysis pass from inventing evidence provenance.

## Evidence helper functions

The framework provides:

```python
node_evidence_ref(graph, node)
edge_evidence_ref(graph, edge)
event_evidence_ref(stream_id=..., event_id=...)
```

Node and edge helpers automatically carry the source EventStore IDs already preserved by Evidence Graph.

This maintains the chain:

```text
AnalysisFinding
      |
      v
AnalysisEvidenceRef
      |
      v
Graph node / edge
      |
      v
EvidenceRef
      |
      v
EventStore event_id
```

## Limitations

`limitations` is an explicit tuple of human-readable constraints on the finding.

A pass should use it when a finding can be described accurately only with an important evidence boundary attached.

Examples include:

```text
Observed only in the later compared graph; this does not establish first occurrence.
Point-in-time absence does not establish termination or continuous absence.
Remote endpoint identity is only a protocol/address/port tuple.
Service identity and transferred data are not inferred from endpoint topology.
```

Limitations are part of the finding contract, not decorative logging.

## Attributes

`attributes` contains structured descriptive metadata relevant to the finding.

The mapping must:

```text
use string keys
contain finite JSON-compatible values
```

NaN and other non-JSON values are rejected.

The framework copies the mapping into the immutable finding object so later mutation of the caller's dictionary does not silently alter the finding.

## Deterministic runner

`run_analysis_passes(context, passes)` applies the following rules:

1. Pass IDs must be unique.
2. Passes are executed in sorted `pass_id` order.
3. Each pass must return a tuple.
4. Every emitted value must be an `AnalysisFinding`.
5. Finding `pass_id` must match the executing pass.
6. Finding `pass_version` must match the executing pass.
7. Evidence must validate against the supplied context.
8. Finding IDs must be globally unique in the run.
9. Findings from each pass are sorted by `finding_id`.

Therefore registration order does not affect final result ordering.

The same context and same pass versions should produce the same semantic result.

## AnalysisResult

The aggregate result contains:

```text
before_stream_id
after_stream_id
pass_results
```

Each `AnalysisPassResult` contains:

```text
pass_id
pass_version
findings
```

The aggregate also exposes flattened `findings` and `finding_count` convenience properties.

No persistence format is defined in v1. EventStore remains the only durable evidence ledger.

If analysis results are persisted later, they must remain derived artifacts that can be recomputed and must never overwrite source observations.

# graph-drift-observations v1.0.0

`GraphDriftObservationsPass` is the first production implementation of the framework.

It consumes the already-computed `GraphDrift` inside `AnalysisContext`. It does not reclassify Graph Drift and does not decide whether any change is good, bad, expected, or important.

The pass covers all four current Graph Drift dimensions:

```text
node drift
edge drift
process identity continuity
projection-note drift
```

## Node findings

For each current `GraphNodeType`, the pass can emit added, removed, and attribute-changed findings.

Examples:

```text
APPLICATION_APPEARED
PROCESS_INSTANCE_DISAPPEARED
FILE_IDENTITY_APPEARED
REMOTE_ENDPOINT_ATTRIBUTES_CHANGED
```

An appearance means only that the node is represented in the later graph but not the earlier graph.

A disappearance means only that the node is represented in the earlier graph but not the later graph.

## Edge findings

Current edge families are translated into relation-specific reason codes.

Examples:

```text
APPLICATION_DISCOVERY_RELATION_APPEARED
PARENT_RELATION_DISAPPEARED
EXECUTED_FROM_RELATION_ATTRIBUTES_CHANGED
TCP_RELATION_APPEARED
```

If duplicate structurally identical edges exist, Graph Drift can identify multiplicity change without identifying which provenance instance constitutes the delta. Findings therefore carry that limitation explicitly.

When multiple unmatched edge candidates share one endpoint key, the pass also emits:

```text
EDGE_CORRESPONDENCE_AMBIGUOUS
```

It does not invent one-to-one correspondence.

## Process identity continuity findings

`same_instance` continuity emits no finding because it is unchanged structure.

Current change findings are:

```text
PROCESS_IDENTITY_REPLACED
PROCESS_IDENTITY_CONTINUITY_MIXED
```

`PROCESS_IDENTITY_REPLACED` means the same PID slot maps to non-overlapping `PID + started_at` process identities across the compared graphs.

It does not explain why the process identity changed.

## Projection-note drift findings

Evidence Graph intentionally leaves some semantics unprojected. Changes in those note counts remain reviewable through:

```text
PROJECTION_NOTE_COUNT_INCREASED
PROJECTION_NOTE_COUNT_DECREASED
```

These findings link directly to the source EventStore event IDs represented by the projection notes.

A change in projection-note count is not automatically a change in underlying system behavior. It may instead describe a change in evidence that Evidence Graph v1 intentionally does not model as nodes or edges.

## Current non-goals

Analysis Pass v1 does not provide:

```text
severity
confidence scoring
confidence calibration
anomaly classification
baseline learning
causal inference
maliciousness classification
automatic response or blocking
finding persistence
finding suppression
policy engines
LLM interpretation
```

The first production pass also does not perform cross-capture scoring, behavioral baselining, service attribution, packet interpretation, or threat classification.

## Design principle

The top-level rule for this layer is:

```text
A finding may summarize evidence.
A finding may not outrun evidence.
```

If an analysis pass cannot point back to concrete evidence contained in its `AnalysisContext`, the runner rejects the finding.
