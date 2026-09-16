# Analysis Pass v1

Analysis Pass v1 defines the first deterministic interpretation contract above Graph Drift.

It does **not** introduce anomaly detection, severity, confidence, causal claims, maliciousness judgments, or automatic blocking.

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

No production detector pass is included in this initial contract layer.

That separation is deliberate. The framework is frozen and tested before concrete finding logic is added.

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

Examples planned for future passes:

```text
PROCESS_INSTANCE_APPEARED
REMOTE_ENDPOINT_APPEARED
PROCESS_IDENTITY_REPLACED
EXECUTABLE_IDENTITY_CHANGED
PARENT_RELATION_CHANGED
APPLICATION_ROOT_BECAME_AMBIGUOUS
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

Concrete passes should derive finding IDs from stable semantic identity rather than timestamps, random UUIDs, or EventStore append IDs where possible.

For example a future pass might use a shape such as:

```text
graph-drift-observations:remote-endpoint-appeared:tcp:203.0.113.10:443
```

The exact production convention will be defined with the first concrete pass.

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

Examples could include:

```text
Point-in-time TCP topology only; byte-level traffic was not observed.
UDP/QUIC is outside the current capture path.
The observation establishes temporal presence, not causality.
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

No persistence format is defined in this first contract step. EventStore remains the only durable evidence ledger.

If analysis results are persisted later, they must remain derived artifacts that can be recomputed and must never overwrite source observations.

## Current non-goals

Analysis Pass v1 does not yet provide:

```text
production detector passes
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

These are future layers, not implicit behavior of the pass contract.

## Planned first production pass

After the contract is validated, the first concrete pass should consume Graph Drift and emit descriptive observations such as:

```text
PROCESS_INSTANCE_APPEARED
PROCESS_INSTANCE_DISAPPEARED
REMOTE_ENDPOINT_APPEARED
REMOTE_ENDPOINT_DISAPPEARED
PROCESS_IDENTITY_REPLACED
```

That pass should not call any of these changes anomalous or suspicious.

Its job is only to translate deterministic graph structure into stable reviewable findings with complete evidence references.

## Design principle

The top-level rule for this layer is:

```text
A finding may summarize evidence.
A finding may not outrun evidence.
```

If an analysis pass cannot point back to concrete evidence contained in its `AnalysisContext`, the runner rejects the finding.
