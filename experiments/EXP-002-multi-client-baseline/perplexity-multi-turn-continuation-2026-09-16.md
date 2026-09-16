# Perplexity Multi-Turn Continuation / UI Completion Ambiguity — 2026-09-16

## Status

This run is retained as a controlled multi-turn interaction case and must not be treated as the single-query Perplexity baseline.

The operator submitted the standard DNS prompt. The first answer became visibly readable, but the Perplexity conversation/history item remained in an animated active state. The operator then selected the suggested follow-up:

```text
What role do TTL values play in DNS caching duration
```

Perplexity produced a second answer. Only after that second response did the UI activity indicator stop animating.

Because the second interaction occurred inside the same EXP-002 transition session and the capture tool recorded only the initial `QUERY_SENT` and final `RESPONSE_COMPLETE` operator markers, the network observations cannot be partitioned cleanly between the first and second requests.

## Artifact

```text
.local/exp002/20260916T191913Z-perplexity-transition-query.json
```

Session result:

```text
observations=47
ok=47
non_ok=0
```

## Stable process evidence

Across the full observation window:

```text
processes=10
unknown=2
non_hashed=0
guard_rejected=0
```

No process-tree churn, executable hash gap, or PID-stability attribution rejection was reported by the capture summary.

## Point-in-time TCP record counts

Pre-query idle:

```text
tcp=12
```

The query-window snapshots then varied materially:

```text
+0s   14
+2s   14
+4s   18
+6s   26
+8s   26
+10s  18
+12s  18
+14s  18
+16s  22
+18s  22
+20s  18
+22s  18
+24s  18
+26s  22
+28s  22
+30s  18
+32s  18
+34s  18
+36s  22
+38s  22
+40s  22
+42s  18
+44s  18
+46s  18
+48s  22
+50s  22
+52s  18
+54s  18
+56s  18
+58s  20
+60s  20
+62s  20
+64s  18
+66s  18
+68s  20
+70s  20
+72s  18
+74s  18
+76s  18
+78s  20
+80s  20
+82s  20
```

Post-response snapshots:

```text
+85.266s   18
+88.266s   18
+98.266s   18
+143.266s  22  (IDLE_LONG)
```

These are counts of observed TCP records, not byte/packet activity and not necessarily counts of `ESTABLISHED` connections. Raw per-record TCP state remains preserved in the JSON evidence.

## Narrow observations

- The validated Perplexity process topology remained stable at ten processes throughout the multi-turn interaction.
- Two processes remained role `unknown` throughout the run.
- The point-in-time TCP record count was substantially more dynamic than in the controlled Gemini and Manus single-query runs, ranging from 14 to 26 during the query window after a pre-query value of 12.
- The TCP record count continued to vary after visible answer generation and was 22 at the long-idle observation.
- Because two user requests occurred inside one session, these changes cannot be attributed to either request individually.

## UI completion ambiguity

The run exposed a methodological distinction that EXP-002 currently represents with only one operator marker:

```text
visible answer text complete
!=
client UI/activity indicator idle
```

The operator observed that the first answer appeared complete while the conversation/history item still showed an animated active state. A second suggested follow-up was then submitted. The indicator stopped only after the second answer completed.

This does not establish what internal work Perplexity was performing while the indicator remained active. It records only the observed UI state and corresponding endpoint/network evidence.

## Experimental consequence

A clean Perplexity single-query baseline should be repeated with exactly one prompt. For comparability with the other EXP-002 clients, `RESPONSE_COMPLETE` should be marked when the first visible answer stops changing, even if Perplexity's separate UI activity indicator remains animated. No follow-up should be clicked during the scheduled post-response window.

The operator should note whether and approximately when the UI activity indicator stops on its own during the post-response/IDLE_LONG period.

A later protocol may benefit from separate operator markers for `ANSWER_VISIBLE_COMPLETE` and `CLIENT_UI_IDLE`, but this should not be retrofitted into the current cross-client baseline without documenting the schema/protocol change.
