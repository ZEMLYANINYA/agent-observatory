# Gemini Controlled Query Transition — 2026-09-16

## Purpose

Record the first controlled Gemini query-transition run captured with EXP-002 evidence schema v2 after executable FileIdentity/hash timing validation.

This note preserves observed facts separately from interpretation. TCP counts are point-in-time socket snapshots, not complete connection-lifecycle measurements.

## Artifact

```text
.local/exp002/20260916T182911Z-gemini-transition-query.json
```

Session result:

```text
observations=19
ok=19
non_ok=0
```

## Pre-query idle

```text
processes=10
tcp=11
unknown=0
non_hashed=0
guard_rejected=0
```

## Query window

The operator marked `QUERY_SENT`, after which 14 successful query-window observations were captured at the following actual start offsets:

```text
+0.000s
+2.422s
+4.813s
+7.203s
+9.609s
+11.875s
+14.313s
+16.688s
+19.031s
+21.266s
+23.578s
+25.953s
+28.234s
+30.594s
```

Every query-window observation reported:

```text
processes=10
tcp=11
unknown=0
non_hashed=0
guard_rejected=0
```

The operator then marked the visible response as complete.

## Post-response observations

```text
+35.047s  POST_RESPONSE  processes=10 tcp=11 unknown=0 non_hashed=0 guard_rejected=0
+38.047s  POST_RESPONSE  processes=10 tcp=11 unknown=0 non_hashed=0 guard_rejected=0
+48.047s  POST_RESPONSE  processes=10 tcp=11 unknown=0 non_hashed=0 guard_rejected=0
+93.047s  IDLE_LONG      processes=10 tcp=11 unknown=0 non_hashed=0 guard_rejected=0
```

## Narrow observation

Across this controlled run, the validated Gemini application tree remained at 10 observed processes and the point-in-time TCP count remained at 11. No unknown-role process, executable hash gap, or PID-stability attribution rejection was reported by the capture summary.

This does **not** establish that no network activity changed during the query. The current collector records point-in-time TCP state and can miss connections that open and close between snapshots. It also does not establish causality between the user query and any specific process or socket.

## Scheduler limitation found during this run

The transition command requested a 1-second burst interval, but actual query-window starts were roughly 2.2–2.4 seconds apart.

The cause was in the scheduler semantics: after a capture overran its next requested slot, the old loop scheduled another full interval from the current time. This effectively produced approximately:

```text
capture duration + requested interval
```

rather than a target start-to-start cadence.

The run remains usable because each observation stores its actual monotonic timestamp. It should not, however, be described as a strict 1 Hz capture series.

The scheduler was subsequently changed so that:

- `--interval` is a target start-to-start cadence;
- missed schedule slots are skipped instead of adding an extra full interval after capture completion;
- each observation records scheduled time, schedule lag, and capture duration;
- capture-limited cadence is explicit rather than hidden.

Relevant follow-up commits:

```text
afe291c  fix(exp002): make transition cadence capture-aware
7111cd7  test(exp002): cover capture-aware schedule slots
```

## Status

Use this run as a valid controlled Gemini transition observation with actual timestamps preserved.

For strict cross-client timing comparison, collect a second Gemini transition with the capture-aware scheduler and use the same scheduler version for Manus and Perplexity.
