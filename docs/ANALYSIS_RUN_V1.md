# Analysis Run v1

`tools/analysis_run.py` is the read-only operator interface for the first production Analysis Pass pipeline.

It executes the existing deterministic layers in order:

```text
EventStore streams
      |
      v
AnalysisContext
      |
      +--> Evidence Graph A
      +--> Evidence Graph B
      +--> Graph Drift
      |
      v
Analysis Pass runner
      |
      v
graph-drift-observations v1.0.0
      |
      v
AnalysisResult
```

The CLI does not write findings back to EventStore. EventStore remains the durable evidence ledger and analysis output remains a derived artifact.

## Commands

Compare the latest two persisted streams:

```powershell
python .\tools\analysis_run.py `
  --db .local\eventstore-v1-live.sqlite3 `
  show
```

Detailed human-readable output:

```powershell
python .\tools\analysis_run.py `
  --db .local\eventstore-v1-live.sqlite3 `
  show --details
```

Machine-readable output:

```powershell
python .\tools\analysis_run.py `
  --db .local\eventstore-v1-live.sqlite3 `
  json
```

The CLI can also compare an explicit before/after stream pair instead of defaulting to the latest two persisted streams.

## Output semantics

The operator output states explicitly:

```text
deterministic descriptive findings only; no severity/confidence/verdict
```

That sentence is part of the interface contract, not presentation decoration.

`AnalysisFinding` v1 intentionally contains no evaluative fields for severity, confidence, anomaly verdict, causality, maliciousness, or importance.

## Live validation

Analysis Run v1 was validated on the two existing real Gemini Windows capture streams already stored in the same EventStore database.

Before:

```text
windows-capture:gemini:20260916T200836Z:d2840730
```

After:

```text
windows-capture:gemini:20260916T201119Z:e45f91ad
```

The upstream Graph Drift comparison for these streams had already established no structural drift across the currently projected dimensions.

Running the first production pass produced:

```text
ANALYSIS RUN:
  deterministic descriptive findings only; no severity/confidence/verdict
findings: 0
  graph-drift-observations v1.0.0 findings=0
```

The machine-readable result was:

```json
{
  "after_stream_id": "windows-capture:gemini:20260916T201119Z:e45f91ad",
  "before_stream_id": "windows-capture:gemini:20260916T200836Z:d2840730",
  "finding_count": 0,
  "pass_results": [
    {
      "finding_count": 0,
      "findings": [],
      "pass_id": "graph-drift-observations",
      "pass_version": "1.0.0"
    }
  ]
}
```

## What zero findings means

For this comparison, zero findings means:

```text
graph-drift-observations v1.0.0
received a valid AnalysisContext
and found no Graph Drift changes that its current reason-code contract translates into findings
```

It does not mean:

```text
nothing happened between captures
no process executed between captures
no network traffic occurred between captures
no short-lived connection occurred
no UDP/QUIC activity occurred
no behavior outside current collectors changed
system state is safe
system state is normal
```

The underlying evidence remains point-in-time Windows observation with the existing capture limitations.

## Why zero findings is important

The first production pass must be able to emit findings when structural evidence changes, but it must also remain silent when the compared evidence does not support a descriptive change.

The live Gemini validation demonstrates the second half of that requirement:

```text
capture
  -> EventStore
  -> Evidence Graph
  -> Graph Drift
  -> production Analysis Pass
  -> zero fabricated findings
```

Synthetic tests separately cover non-zero cases including PID reuse, remote-endpoint appearance, parent-relation appearance, edge-attribute change, ambiguous edge correspondence, and projection-note count drift.

## Architectural boundary

Analysis Run v1 is a review surface over deterministic derived artifacts.

It is not:

```text
anomaly detection
threat classification
policy enforcement
automatic response
causal inference
LLM interpretation
```

Those require separately designed layers and must not be inferred from the presence or absence of v1 findings.
