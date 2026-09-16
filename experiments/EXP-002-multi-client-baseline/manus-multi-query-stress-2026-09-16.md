# Manus Multi-Query Stress Run — 2026-09-16

## Status

This sequence is retained as a controlled multi-query stress/interaction run and must not be treated as the single-query comparative baseline.

The operator sent three user requests during the transition session. Because EXP-002's comparative protocol is defined around one benign query, a later one-query Manus transition should be used for direct comparison with Gemini and Perplexity.

## Artifacts

```text
.local/exp002/20260916T185518Z-manus-startup.json
.local/exp002/20260916T185831Z-manus-idle.json
.local/exp002/20260916T185908Z-manus-transition-query.json
```

## STARTUP

```text
processes=7
tcp_total=20
unknown=2
non_hashed=0
guard_rejected=0
```

## IDLE

```text
processes=7
tcp_total=16
unknown=2
non_hashed=0
guard_rejected=0
```

## Pre-query idle

```text
processes=7
tcp_total=20
unknown=2
non_hashed=0
guard_rejected=0
capture_duration_ms=1406
```

## Multi-query window

The session used the capture-aware scheduler with a target one-second start-to-start cadence. Capture duration was consistently greater than one second, so missed one-second slots were skipped and successful observations started on the two-second grid.

Observed TCP totals:

```text
+0s   22
+2s   22
+4s   20
+6s   18
+8s   18
...
+62s  18
```

Across the complete query window:

```text
processes=7 stable
unknown=2 stable
non_hashed=0
guard_rejected=0
```

## Post-response

```text
+65.204s   POST_RESPONSE  tcp_total=18
+68.204s   POST_RESPONSE  tcp_total=18
+78.204s   POST_RESPONSE  tcp_total=18
+123.219s  IDLE_LONG      tcp_total=18
```

Session result:

```text
observations=37
ok=37
non_ok=0
```

## Narrow observation

The validated Manus process topology remained stable at seven observed processes with two unknown-role helpers throughout startup, idle, the multi-query interaction window, and post-response sampling. Executable hash evidence remained complete and the PID-stability attribution guard rejected no TCP ownership.

The point-in-time TCP record total changed from 20 at pre-query idle to 22 immediately after interaction, then declined to 20 and 18, where it remained through the rest of the sampled window and long-idle observation.

This is not sufficient to claim query-caused connection creation or closure. EXP-002 records point-in-time TCP state, and the `tcp_total` value mixes TCP states unless explicitly broken down. Socket ownership and state should be inspected before interpreting the count.

## Comparative-use limitation

Because three user requests were sent during this run, it should not be compared directly to a one-query Gemini or Perplexity transition as if the interaction load were identical. Preserve it as a stress/interaction run and collect a separate one-query Manus baseline for the final comparative table.
