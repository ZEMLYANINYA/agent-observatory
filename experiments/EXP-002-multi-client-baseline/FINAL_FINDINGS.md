# EXP-002 Final Comparative Findings

## Status

EXP-002 is complete as a first comparative desktop-client baseline.

The experiment produced controlled and supporting observations for:

- Claude;
- Codex;
- Gemini;
- Manus;
- Perplexity;
- five-client co-residency.

This document is the final comparison layer. The chronological capture notes and
client-specific case files remain the evidence trail and should be consulted for
exact timestamps, operator annotations, and artifact names.

## Scope of conclusions

EXP-002 is an endpoint and point-in-time network observation experiment. It is
not a benchmark of model quality, application quality, privacy, security, or
vendor behavior.

The evidence can support statements about what Agent Observatory observed on the
instrumented Windows workstation during the recorded runs. It cannot, by itself,
prove why an application created a process, why a socket changed state, which
server-side operation occurred, or whether an unobserved transport carried
traffic between snapshots.

The strongest directly comparable timed-query subset is Gemini, Manus, and
Perplexity, which were captured with the later transition protocol and hardened
executable-evidence semantics. Claude and Codex remain useful comparative cases,
but their controlled sequences predate part of that protocol. The Codex active
sequence also contains artifacts whose stored state label is `IDLE`; phase names
for those artifacts come from contemporaneous operator notes.

## Cross-client summary

| Client | Controlled process topology | Unknown-role count | Point-in-time TCP behavior | Notable observation |
| --- | --- | ---: | --- | --- |
| Claude | Stable at 8 processes in controlled sequence | 0 | Snapshot count varied while process tree remained stable | Stable observed topology despite changing TCP snapshot count |
| Codex | Dynamic, including 10 -> 21 -> 33 -> 30 in one isolated sequence | Dynamic, including 3 -> 10 -> 22 -> 19 | Snapshot count changed substantially | Native/tooling descendants appeared and disappeared during the observed lifecycle |
| Gemini | Stable at 10 in clean controlled runs | 0 | Final single-query run remained at 2 TCP records | TCP total alone was shown to be ambiguous because `Bound` and `Established` were previously combined |
| Manus | Stable at 7 in controlled single-query run | 2 | Single-query run remained at 14 TCP records; multi-query stress run changed | Process topology remained stable while TCP snapshot count could change across a longer multi-query interaction |
| Perplexity | Stable at 10 in controlled single-query run | 2 | Single-query run changed during query and after visible answer completion | First post-response sample rose above the final query-window count before returning to baseline |

The table is descriptive. TCP values in older artifacts are totals across all
states returned by the Windows TCP inventory, not counts of established remote
connections.

## 1. Co-residency validation succeeded

After the endpoint identity hardening work, all five configured desktop clients
were observed simultaneously:

```text
Claude       processes=8
Codex        processes=16
Gemini       processes=10
Manus        processes=7
Perplexity   processes=10
```

Global result:

```text
applications             5
AI processes            51
processes with hash evidence 51
non-HASHED states        0
guard-rejected TCP       0
```

The application discovery layer separated the five co-resident trees without
cross-identifying Codex as ChatGPT despite the shared `ChatGPT.exe` name.

This validates the multi-signal discovery approach for the observed installed
versions and demonstrates that the PID-stability TCP attribution guard can
operate under simultaneous client load.

It does not establish that every future application version will retain the same
path/name evidence or tree shape.

## 2. Process topology and network topology are different evidence dimensions

Several clients demonstrated that process count can remain unchanged while the
point-in-time TCP inventory changes.

### Claude

The controlled Claude sequence remained at eight observed processes with zero
unknown-role processes and zero attribution-guard rejections. TCP snapshot totals
changed across startup, idle, active, and post-action observations.

The narrow result is that the observed application process topology remained
stable while the socket snapshot was dynamic.

### Gemini

The clean later Gemini runs remained at ten processes with zero unknown-role
processes and zero attribution-guard rejections. The final controlled single-query
transition remained at two TCP records throughout the sampled query and
post-response window.

An earlier controlled run reported eleven TCP records. Inspection of the first
sample from that artifact showed:

```text
11 Bound
0 Established
```

Inspection of the first sample from the later clean run showed:

```text
1 Bound
1 Established
```

Therefore a raw `tcp=11` summary was not equivalent to eleven active remote
connections. The evidence representation was correct because socket state was
preserved per record, but the console summary was too ambiguous. EXP-002 cleanup
now reports total, established, bound, and other state counts separately.

### Manus

The controlled single-query run remained at seven processes, two unknown-role
processes, zero non-hashed executable observations, and zero attribution-guard
rejections. Its TCP total remained stable during that run.

A separate multi-query stress pass kept the same process topology while the TCP
snapshot total changed from the low twenties toward eighteen. Because that pass
contained three operator queries, it is retained as a stress artifact and is not
used as the single-query comparison baseline.

### Perplexity

The clean single-query transition remained at ten processes and two unknown-role
processes. Its TCP total changed during the query and briefly rose after the
operator marked the visible answer complete before returning to the pre-query
level.

The process tree therefore remained stable while the socket snapshot changed.

## 3. Codex was the clear topology-dynamic case in the observed runs

Codex differed from the stable-topology controlled cases above.

One isolated startup series showed:

```text
10 processes
21 processes
16 processes
```

followed by a repeated observed plateau at sixteen processes during that startup
sequence.

A second isolated state-by-state sequence showed substantial descendant growth:

```text
STARTUP              10 processes, 3 unknown
IDLE                 21 processes, 10 unknown
ACTIVE observation   up to 33 processes, 22 unknown
POST observation     30 processes, 19 unknown
```

Observed descendants included native/tooling processes such as `codex.exe`,
`codex-computer-use-swift.exe`, `conhost.exe`, `cmd.exe`, `git.exe`,
`node_repl.exe`, and `node.exe` in the recorded runs.

These facts support only the observation that the validated Codex descendant
tree was more dynamic in these runs. They do not establish the purpose of each
helper, whether repository indexing occurred, or which user-visible operation
caused a specific child process.

## 4. Visible answer completion is not a network-idle boundary

Perplexity supplied the clearest controlled example.

Its clean single-query transition recorded:

```text
PRE_QUERY     tcp_total=5
QUERY         7 -> 7 -> 7 -> 6 -> 5 -> 5 -> 7
operator RESPONSE_COMPLETE marker
POST          9 -> 5 -> 5 -> 5
```

The first post-response observation therefore contained more TCP records than
the final query-window observation even though the visible answer had already
been marked complete.

A separate Perplexity multi-turn case also exposed UI-completion ambiguity: the
first visible answer was present while the conversation/history indicator still
appeared active. A suggested follow-up was then selected, causing a second turn.
That artifact is intentionally not used as the clean single-query baseline.

The methodology consequence is important:

`RESPONSE_COMPLETE` is an operator-observed UI marker. It is not proof that the
application, network stack, remote service, or background work has reached an
idle state.

The EventStore should preserve such markers as evidence events rather than turn
them into causal or lifecycle truth.

## 5. Startup discovery has observable ambiguity windows

Two launch-time edge cases were observed during EXP-002.

### Codex

An attempted very-early capture did not yet discover Codex. Later captures in the
same launch lifecycle succeeded.

### Perplexity

One STARTUP attempt failed with:

```text
application 'Perplexity' matched multiple roots; capture separately
```

A retry after the launch tree settled succeeded with one selected root and ten
validated application processes.

The failed Perplexity attempt did not write a normal evidence artifact, so the
exact root-candidate PIDs from that historical attempt are not available in the
saved JSON. EXP-002 cleanup now includes candidate PID, PPID, start time, and path
in future multiple-root diagnostics.

The narrow conclusion is that point-in-time application discovery can be
ambiguous during startup transitions. `not discovered`, `one root`, and
`multiple candidate roots` should remain distinguishable states in future
persistence rather than being collapsed into one generic failure.

## 6. The capture cadence is sensor-limited and is now explicit

The first timed Gemini transition requested a one-second interval but actual
observation starts were roughly 2.2 to 2.4 seconds apart. The original scheduler
added another full interval after a capture overran its next slot.

The scheduler was corrected so that `--interval` means target start-to-start
cadence. Missed slots are skipped, and each observation now records:

```text
schedule_slot
scheduled_t_relative_ms
schedule_lag_ms
capture_duration_ms
```

On the workstation, a full observation commonly took roughly 1.2 to 1.8 seconds.
As a result, the achievable timed-query grid was usually approximately two
seconds even when the requested target cadence was one second.

This is not hidden measurement error anymore. The artifact records the actual
start time, requested schedule point, lag, and capture duration.

## 7. Executable evidence semantics held under live use

The hardened evidence model survived live multi-client and timed-query runs:

- paths with non-ASCII Windows profile components remained intact;
- FileIdentity was available for observed executables in the validated runs;
- executable hashes remained separate post-capture observations;
- the co-residency gate obtained hash evidence for all 51 observed AI processes;
- later controlled transitions reported zero non-hashed process evidence;
- hash timing remained explicit rather than being treated as contemporaneous
  process memory identity.

A package/executable identity change for Claude was also observed between runs.
That is exactly the kind of drift a future append-only EventStore should retain
as a sequence of observations rather than overwrite in place.

## 8. Current network evidence is topology evidence, not traffic evidence

EXP-002 currently observes point-in-time TCP records attributed to stable process
instances.

It does not yet measure:

- bytes sent or received on an existing connection;
- packet counts;
- complete connect/close lifecycle between snapshots;
- UDP endpoints or UDP flow activity;
- QUIC/HTTP/3 specifically;
- TLS contents;
- server-side request boundaries.

Therefore a stable TCP-record count does not imply that no network traffic
occurred. A request and response may traverse an already-established connection
without changing the number of socket records.

Likewise, a missing TCP record does not prove that no network communication
occurred. Short-lived TCP activity may fall between snapshots, and non-TCP
transport is outside the current sensor.

No EXP-002 observation is used to claim that a client did or did not use QUIC,
HTTP/3, or any specific unobserved transport.

## 9. Evidence-model changes justified by EXP-002

The experiment directly motivated or validated the following rules:

1. Keep application discovery outcomes explicit: absent, unique, or ambiguous.
2. Keep process topology independent from network topology.
3. Preserve TCP state per record and do not label total socket records as
   established connections.
4. Keep operator UI events distinct from inferred application/network state.
5. Preserve actual sensor timing and capture duration.
6. Keep executable path, filesystem identity, and content hash as separate
   evidence concepts.
7. Prefer `unknown` helper roles over unsupported semantic guesses.
8. Treat point-in-time network evidence as incomplete flow coverage.

## 10. EventStore requirements carried forward

EXP-002 is sufficient to proceed to SQLite + WAL append-only EventStore v1.

The first storage layer should persist observations rather than derived verdicts.
At minimum the model should be able to represent:

```text
PROCESS_OBSERVED
PROCESS_RELATIONSHIP_OBSERVED
FILE_IDENTITY_OBSERVED
FILE_HASH_OBSERVED
TCP_CONNECTION_OBSERVED
APPLICATION_DISCOVERY_OBSERVED
OPERATOR_MARKER_OBSERVED
```

`TCP_CONNECTION_OBSERVED` should preserve state explicitly. A later network
sensor can add UDP and richer flow/activity observations without redefining the
meaning of existing TCP snapshot evidence.

Discovery ambiguity should be representable rather than discarded as an error.
Operator markers such as query sent or visible response complete should remain
source-attributed observations and must not automatically create causal edges.

## 11. Follow-up sensor work

The experiment identifies several useful later extensions, but they are not
required to close EXP-002:

- UDP endpoint observation;
- connection/flow lifecycle events rather than snapshots only;
- byte/packet counters where reliable attribution is available;
- richer native/helper role taxonomy backed by evidence;
- startup discovery transition capture;
- repeatable session diff/drift reports over stored evidence.

These belong after the first durable EventStore rather than being folded into the
baseline experiment.

## Final experiment conclusion

EXP-002 achieved its primary purpose: the current Agent Observatory endpoint
layer can distinguish the five observed desktop AI clients, maintain guarded
process/TCP attribution, preserve hardened executable identity evidence, and
capture meaningful behavioral differences without converting temporal
co-occurrence into causality.

The experiment also found weaknesses in the measurement surface itself:
ambiguous aggregate TCP presentation, capture-limited cadence, startup discovery
ambiguity, UI-completion ambiguity, and incomplete network-flow coverage. Those
limitations are now explicit evidence-model requirements rather than hidden
assumptions.

EXP-002 should be treated as closed after the final test gate for the cleanup
commits. The next architecture milestone is append-only EventStore v1.
