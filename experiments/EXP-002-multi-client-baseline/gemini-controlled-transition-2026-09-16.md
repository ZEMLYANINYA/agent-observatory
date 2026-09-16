# Gemini Controlled Query Transition — 2026-09-16

## Purpose

Record the controlled Gemini query-transition runs captured with EXP-002 evidence schema v2 after executable FileIdentity/hash timing validation.

This note preserves observed facts separately from interpretation. Raw TCP records are point-in-time endpoint snapshots, not complete connection-lifecycle or traffic-volume measurements.

## First controlled transition

Artifact:

```text
.local/exp002/20260916T182911Z-gemini-transition-query.json
```

Session result:

```text
observations=19
ok=19
non_ok=0
```

### Pre-query idle

```text
processes=10
tcp_total=11
unknown=0
non_hashed=0
guard_rejected=0
```

### Query window

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
tcp_total=11
unknown=0
non_hashed=0
guard_rejected=0
```

The operator then marked the visible response as complete.

### Post-response observations

```text
+35.047s  POST_RESPONSE  processes=10 tcp_total=11 unknown=0 non_hashed=0 guard_rejected=0
+38.047s  POST_RESPONSE  processes=10 tcp_total=11 unknown=0 non_hashed=0 guard_rejected=0
+48.047s  POST_RESPONSE  processes=10 tcp_total=11 unknown=0 non_hashed=0 guard_rejected=0
+93.047s  IDLE_LONG      processes=10 tcp_total=11 unknown=0 non_hashed=0 guard_rejected=0
```

### TCP state inspection

A later state-level inspection of the first successful observation showed that the `tcp_total=11` value consisted entirely of `Bound` records:

```text
Bound        11
Established   0
```

All 11 records belonged to one Gemini process. Each had a wildcard remote endpoint (`0.0.0.0:0`) and a locally bound ephemeral port.

Therefore the original console value `tcp=11` must not be read as 11 active remote TCP sessions.

## Scheduler limitation found during first run

The first transition requested a 1-second burst interval, but actual query-window starts were roughly 2.2–2.4 seconds apart.

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

## Clean-restart startup captures

After a clean Gemini restart, two consecutive STARTUP captures produced the same summary:

```text
processes=10
tcp_total=2
unknown=0
non_hashed=0
guard_rejected=0
```

Artifacts:

```text
.local/exp002/20260916T183913Z-gemini-startup.json
.local/exp002/20260916T183920Z-gemini-startup.json
```

The repeated result supports that the two-record snapshot was reproducible within this launch session.

## Second controlled transition

Artifact:

```text
.local/exp002/20260916T184227Z-gemini-transition-query.json
```

Session result:

```text
observations=24
ok=24
non_ok=0
```

The capture-aware scheduler was active. Individual observations required roughly 1.2–1.45 seconds, so the requested 1-second target cadence produced starts on schedule slots `0, 2, 4, ...` seconds. Missed one-second slots were skipped rather than silently adding another interval.

Across pre-query, query-window, post-response, and long-idle observations:

```text
processes=10
tcp_total=2
unknown=0
non_hashed=0
guard_rejected=0
```

### TCP state inspection

A state-level inspection of the first successful observation showed:

```text
Bound        1
Established  1
```

Both records were owned by the same Gemini process. The established record was:

```text
local  = 10.87.23.44:61224
remote = 142.250.109.95:443
state  = Established
```

A `Bound` record was simultaneously present on local port `61224` with wildcard remote endpoint.

## Narrow observations

1. Gemini's validated process topology remained stable at 10 processes across both controlled transitions and the clean-start captures.
2. No unknown-role processes, executable hash failures, or PID-stability attribution rejections were observed.
3. Raw TCP record count varied materially between launch sessions (`11` versus `2`) while the observed process topology remained constant.
4. The 11-record session consisted of `Bound` records and contained no `Established` record in the inspected snapshot.
5. The clean-restart controlled session contained one `Established` port-443 record plus one `Bound` record.
6. Stable TCP record count during a query does not imply lack of traffic. Payload may traverse an already-established connection without changing the endpoint inventory.
7. The current EXP-002 sensor observes TCP snapshots only. UDP/QUIC and traffic-volume information are outside this evidence stream.

## Experimental consequence

The console label `tcp=` is too ambiguous for analysis. Future summaries should distinguish at least:

```text
tcp_total
tcp_established
tcp_bound
tcp_other
```

Raw per-process TCP records remain the authoritative evidence, and existing JSON artifacts should not be rewritten merely to normalize their display summaries.

For later Agent Observatory network work, endpoint snapshots alone are insufficient for action-level activity attribution. A future sensor should evaluate event/flow or byte-level telemetry and UDP coverage while preserving the project's conservative attribution rules.

## Non-conclusions

This evidence does not establish:

- which application-layer request used the observed established TCP connection;
- whether Gemini used TCP, UDP/QUIC, or a mixture for the controlled query;
- the purpose of the remote endpoint;
- exact connection lifetimes between snapshots;
- traffic volume on an established connection;
- causality between the operator query and any individual network endpoint.

## Status

The second transition is the preferred controlled Gemini timing run for cross-client comparison because it uses the capture-aware scheduler.

The first run remains valid timestamped evidence and is retained because it exposed both the scheduler limitation and the need to distinguish TCP connection states in summaries.
