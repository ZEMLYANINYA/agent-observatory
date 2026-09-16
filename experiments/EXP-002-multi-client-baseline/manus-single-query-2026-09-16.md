# Manus Single-Query Transition — 2026-09-16

## Purpose

Record the controlled single-query Manus transition run for EXP-002.

This run is kept separate from the earlier Manus multi-query stress pass. The operator sent exactly one benign text query during this session.

## Artifact

```text
.local/exp002/20260916T190327Z-manus-transition-query.json
```

Session result:

```text
observations=14
ok=14
non_ok=0
```

## Pre-query idle

```text
processes=7
tcp=14
unknown=2
non_hashed=0
guard_rejected=0
capture_duration_ms=1234
```

## Query window

Successful query-window observations were captured at:

```text
+0s
+2s
+4s
+6s
+8s
+10s
+12s
+14s
+16s
```

Every query-window observation reported:

```text
processes=7
tcp=14
unknown=2
non_hashed=0
guard_rejected=0
```

Capture durations ranged from approximately 1.16s to 1.78s. The capture-aware scheduler therefore skipped missed 1-second slots and retained the target timing grid without adding an extra interval after each capture.

## Post-response observations

```text
+20s  POST_RESPONSE  processes=7 tcp=14 unknown=2 non_hashed=0 guard_rejected=0
+23s  POST_RESPONSE  processes=7 tcp=14 unknown=2 non_hashed=0 guard_rejected=0
+33s  POST_RESPONSE  processes=7 tcp=14 unknown=2 non_hashed=0 guard_rejected=0
+78s  IDLE_LONG      processes=7 tcp=14 unknown=2 non_hashed=0 guard_rejected=0
```

All scheduled post-response observations reported zero schedule lag at console precision.

## Narrow observation

Across this single-query run, the validated Manus application tree remained stable at seven processes. The role classifier retained two unknown/helper processes throughout. All executable evidence remained hashable and the PID-stability attribution guard rejected no TCP records.

The point-in-time TCP record count remained at 14 for the entire pre-query, query, post-response, and long-idle sequence.

This does **not** establish that no network traffic changed during the query. EXP-002 currently records socket topology/state snapshots rather than bytes or packets transferred within an already-established connection, and UDP traffic is outside the current sensor scope.

## Relation to the multi-query stress pass

The earlier Manus stress run contained three user queries and showed a TCP-record count transition from 22 to 20 to 18 while process topology remained stable at seven processes. That run is useful as a multi-query interaction/stress artifact but must not be used as the single-query comparative baseline.

This artifact is the preferred controlled Manus single-query transition for cross-client comparison in EXP-002.
