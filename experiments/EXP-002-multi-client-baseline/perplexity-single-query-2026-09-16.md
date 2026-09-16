# Perplexity Controlled Single-Query Transition — 2026-09-16

## Status

Controlled single-query transition suitable for EXP-002 comparison.

This run followed an earlier Perplexity multi-turn/UI-completion ambiguity case. In this run, the operator sent one query only and no second follow-up query was required.

## Artifact

```text
.local/exp002/20260916T192800Z-perplexity-transition-query.json
```

Session result:

```text
observations=12
ok=12
non_ok=0
```

## Stable process evidence

Across pre-query, query-window, post-response, and long-idle observations:

```text
processes=10
unknown=2
non_hashed=0
guard_rejected=0
```

No process-tree churn, executable-hash gap, or PID-stability attribution rejection was reported by the capture summary.

## TCP snapshot sequence

Pre-query idle:

```text
tcp=5
```

Query window:

```text
+0.000s   tcp=7
+2.000s   tcp=7
+4.000s   tcp=7
+6.000s   tcp=6
+8.000s   tcp=5
+10.000s  tcp=5
+12.000s  tcp=7
```

The operator marked the visible answer complete after the +12s observation.

Post-response:

```text
+16.000s  tcp=9
+19.000s  tcp=5
+29.000s  tcp=5
+74.000s  tcp=5
```

The observed TCP-record count therefore changed after the visible response-complete marker, briefly rising from 7 at the final query-window sample to 9 at the first post-response sample before returning to the pre-query value of 5.

## Narrow observation

This run supports the observation that the validated Perplexity process topology remained stable while point-in-time TCP state changed during and immediately after one ordinary text query.

The post-response TCP change is especially important methodologically: a user-visible answer-complete marker does not establish that network activity has stopped or that the client has reached a transport-level idle state.

The raw EXP-002 counter includes TCP records in all returned states. It does not represent bytes transferred, packet counts, or complete flow lifetimes, and the current sensor does not observe UDP. No claim is made that the additional records were caused by a specific internal action or that they represented newly established remote connections without inspecting their individual states.

## Timing

The capture-aware scheduler behaved as expected. Query-window observations followed the achievable two-second grid because individual captures took approximately 1.2–1.6 seconds. Missed one-second slots were skipped rather than introducing an additional full interval after capture completion.

## Comparison note

Unlike the earlier Perplexity multi-turn case, this run contained one operator query only. Use this artifact for the controlled single-query cross-client comparison. Retain the earlier run separately as a multi-turn/UI-completion ambiguity case.
