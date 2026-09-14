# EXP-002 Observations

## Environment

Record before the controlled run:

```text
Windows build:
Agent Observatory commit:
Network interfaces in use:
VPN / tunnel state:
Capture time zone:
```

## Preliminary Multi-Client Validation

A pre-experiment smoke test with multiple clients running simultaneously showed:

```text
Claude      discovered
Codex       discovered from ChatGPT.exe + OpenAI.Codex_ path evidence
Gemini      discovered
Manus       discovered
Perplexity  discovered
```

Observed examples from that uncontrolled smoke test included:

- Codex Electron network service owning multiple established TCP connections;
- `codex.exe` owning an additional established TCP connection;
- `manus-computer-operator.exe` owning an established TCP connection;
- Manus Electron network service owning established TCP connections;
- `perplexity-rpc-server.exe` owning an established TCP connection.

A later co-residency capture with all five clients running simultaneously produced:

```text
Claude       processes=8   tcp=4   unknown=0   guard_rejected=0
Codex        processes=16  tcp=14  unknown=6   guard_rejected=0
Gemini       processes=11  tcp=0   unknown=0   guard_rejected=0
Manus        processes=8   tcp=6   unknown=2   guard_rejected=0
Perplexity   processes=10  tcp=3   unknown=2   guard_rejected=0
```

Capture artifact:

```text
.local/exp002/20260914T072142Z-all-coresidency.json
```

These observations are retained as reproduction targets for the controlled
experiment. TCP counts are point-in-time snapshots, not complete flow-lifecycle
measurements.

## Claude

A first rapid-sequence pilot was captured before the controlled timing protocol
was followed. All four rapid samples reported `processes=8`, `tcp=2`,
`unknown=0`, and `guard_rejected=0`. Those pilot artifacts are retained but are
not used as the controlled state baseline.

### STARTUP

```text
Capture: .local/exp002/20260914T072616Z-claude-startup.json
Process count: 8
TCP snapshot count: 4
Unknown/helper processes: 0
Attribution guard rejected: 0
Notes: captured after a clean Claude restart and shortly after the window appeared
```

### IDLE

```text
Capture: .local/exp002/20260914T072721Z-claude-idle.json
Process count: 8
TCP snapshot count: 8
Unknown/helper processes: 0
Attribution guard rejected: 0
Notes: captured after approximately 60 seconds without user interaction
```

### ACTIVE_QUERY

The active phase was sampled repeatedly across the request/response lifecycle,
covering the period before generation, generation start, generation in progress,
completion, and the immediate period after completion.

```text
20260914T072842Z  processes=8  tcp=6   unknown=0  guard_rejected=0
20260914T072858Z  processes=8  tcp=12  unknown=0  guard_rejected=0
20260914T072909Z  processes=8  tcp=12  unknown=0  guard_rejected=0
20260914T072923Z  processes=8  tcp=12  unknown=0  guard_rejected=0
20260914T072938Z  processes=8  tcp=12  unknown=0  guard_rejected=0
20260914T073048Z  processes=8  tcp=10  unknown=0  guard_rejected=0
```

Observed process topology remained stable at eight processes throughout the
sampled active period. TCP snapshot counts changed materially during the same
period. These captures do not establish that a specific number of connections
was opened by the query because connections may be created or closed between
point-in-time snapshots.

### POST_ACTION_IDLE

```text
Capture: .local/exp002/20260914T073352Z-claude-post-action-idle.json
Process count: 8
TCP snapshot count: 8
Unknown/helper processes: 0
Attribution guard rejected: 0
Notes: captured after the response completed and a subsequent idle interval
```

### Claude preliminary finding

Across the controlled sequence, Claude kept the same observed eight-process
application topology and produced no unknown-role processes or rejected TCP
attributions. TCP snapshot counts changed from 4 at startup to 8 at idle,
varied between 6 and 12 during the sampled active period, and returned to 8 in
the post-action idle capture.

This supports a narrow observation that, for this run, application process
topology remained stable while observed TCP state was dynamic. It does not yet
support claims about exact connection lifetimes, request-specific destinations,
or causality between one user action and any individual TCP connection.

## Codex

The first Codex sequence was captured while Gemini, Manus, and Perplexity were
still running. It is therefore retained as a co-resident preliminary sequence,
not the isolated controlled Codex baseline.

An attempted very-early STARTUP capture did not discover Codex yet and reported
only Gemini, Manus, and Perplexity. A subsequent capture succeeded after the
Codex application root became observable. This is retained as evidence that the
current point-in-time discovery can miss Codex during an early launch window.

### Preliminary STARTUP

```text
Capture: .local/exp002/20260914T073917Z-codex-startup.json
Root PID: 25056
Process count: 13
TCP snapshot count: 26
Unknown/helper processes: 6
Attribution guard rejected: 0
```

Observed name/role composition:

```text
ChatGPT.exe                  main       1   TCP=0
ChatGPT.exe                  network    1   TCP=22
ChatGPT.exe                  renderer   3   TCP=0
ChatGPT.exe                  gpu        1   TCP=0
ChatGPT.exe                  crashpad   1   TCP=0
ChatGPT.exe                  unknown    1   TCP=0
codex.exe                    unknown    1   TCP=4
codex-computer-use-swift.exe unknown    1   TCP=0
conhost.exe                  unknown    2   TCP=0
node_repl.exe                unknown    1   TCP=0
```

All observed TCP was owned by two stable process instances in this snapshot:
`ChatGPT.exe` with role `network` (PID 3032, 22 TCP) and `codex.exe`
(PID 25112, 4 TCP).

### Preliminary IDLE

```text
Capture: .local/exp002/20260914T074030Z-codex-idle.json
Root PID: 25056
Process count: 33
TCP snapshot count: 70
Unknown/helper processes: 23
Attribution guard rejected: 0
```

Observed name/role composition:

```text
ChatGPT.exe                  main       1   TCP=0
ChatGPT.exe                  network    1   TCP=56
ChatGPT.exe                  renderer   6   TCP=0
ChatGPT.exe                  gpu        1   TCP=0
ChatGPT.exe                  crashpad   1   TCP=0
ChatGPT.exe                  unknown    1   TCP=0
codex.exe                    unknown    1   TCP=14
codex-computer-use-swift.exe unknown    1   TCP=0
cmd.exe                      unknown    2   TCP=0
conhost.exe                  unknown    4   TCP=0
git.exe                      unknown    4   TCP=0
node_repl.exe                unknown    5   TCP=0
node.exe                     unknown    5   TCP=0
```

The root PID remained 25056 between the two successful captures. The observed
`ChatGPT.exe` network owner remained PID 3032 and `codex.exe` remained PID
25112. TCP snapshot counts for those two owners increased from 22 to 56 and
from 4 to 14 respectively.

Between preliminary STARTUP and IDLE, the validated Codex descendant tree grew
from 13 to 33 processes. The additional observed composition included three
more renderers, two additional `conhost.exe` instances, and newly observed
`cmd.exe`, `git.exe`, `node.exe`, and additional `node_repl.exe` instances.

This supports only the observation that additional helper/tooling processes
appeared in the validated Codex descendant tree during the idle interval. It
does not establish the purpose of those processes, whether they were performing
repository indexing, or what caused their creation.

### Controlled isolated STARTUP time series

After other configured desktop AI clients had been closed, Codex was started in
isolation and sampled repeatedly during startup. The first attempted capture did
not discover any configured application. Successful captures then showed a
rapidly changing process tree followed by a stable observed plateau:

```text
20260914T074746Z  processes=10  tcp=12  unknown=3   guard_rejected=0
20260914T074758Z  processes=21  tcp=28  unknown=10  guard_rejected=0
20260914T074852Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T074855Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T074857Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T074859Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T074901Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T074906Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T074912Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T075018Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T075026Z  processes=16  tcp=32  unknown=5   guard_rejected=0
20260914T075031Z  processes=16  tcp=32  unknown=5   guard_rejected=0
```

The isolated startup sequence shows an observed transition from 10 to 21 to 16
processes, with TCP snapshot counts rising from 12 to 28 to 32 and the
unknown-role count changing from 3 to 10 to 5. The `16 / 32 / 5` state was then
observed repeatedly for more than one minute with no attribution-guard
rejections.

After Codex was intentionally closed by the operator, two subsequent capture
attempts reported `application 'Codex' not discovered; discovered: none`.
Those post-close attempts are expected shutdown validation and are not part of
the startup time series or evidence of a discovery failure. A later direct
`Win32_Process` check for Codex package paths and `codex*` process names also
returned no processes.

### Controlled isolated STARTUP

A second isolated run was started for the state-by-state baseline:

```text
Capture: .local/exp002/20260914T080040Z-codex-startup.json
Process count: 10
TCP snapshot count: 10
Unknown/helper processes: 3
Attribution guard rejected: 0
```

### Controlled isolated IDLE

After approximately 60 seconds without the controlled query:

```text
Capture: .local/exp002/20260914T080147Z-codex-idle.json
Process count: 21
TCP snapshot count: 50
Unknown/helper processes: 10
Attribution guard rejected: 0
```

This second run independently reproduced substantial post-launch growth in the
validated Codex process tree before the controlled query was sent.

### ACTIVE_QUERY

The operator then sent the controlled query and sampled Codex repeatedly through
the response lifecycle. These captures were accidentally invoked with the
`IDLE` state argument, so the JSON metadata and filenames retain `idle`; the
phase labels below come from the operator's contemporaneous notes and are not
inferred from the capture metadata.

```text
20260914T080444Z  processes=33  tcp=44  unknown=22  guard_rejected=0
20260914T080458Z  processes=31  tcp=48  unknown=20  guard_rejected=0
20260914T080503Z  processes=31  tcp=46  unknown=20  guard_rejected=0
20260914T080511Z  processes=31  tcp=44  unknown=20  guard_rejected=0
20260914T080515Z  processes=31  tcp=44  unknown=20  guard_rejected=0
```

The observed process count reached 33 during the active sequence and then
settled at 31 across four consecutive samples. TCP snapshot counts varied from
44 to 48 and back to 44 during the same period. No attribution-guard rejection
was observed.

### POST_ACTION_IDLE

The operator recorded the following capture after the conversation had ended.
It was also invoked with the `IDLE` state argument and therefore retains that
label in the artifact metadata:

```text
Capture: .local/exp002/20260914T080623Z-codex-idle.json
Process count: 30
TCP snapshot count: 40
Unknown/helper processes: 19
Attribution guard rejected: 0
```

### Codex preliminary finding

Unlike the Claude run, Codex did not maintain a fixed observed process topology.
In the second isolated run, the validated application tree grew from 10
processes at startup to 21 after approximately one idle minute and reached 33
around the controlled active phase before declining to 30 in the post-action
capture. Unknown-role counts changed in parallel from 3 to 10 to 22 and then
19. TCP snapshot counts were also dynamic but did not move monotonically with
process count: 10 at startup, 50 at the first idle capture, 44-48 during the
sampled active phase, and 40 afterward.

Across all successful captures in this sequence, `guard_rejected=0`. This
supports the narrow observation that Codex exhibited a substantially more
dynamic validated descendant tree than Claude in these runs. It does not yet
establish the purpose of the added helper processes, exact process lifetimes,
or a causal relationship between the controlled query and any individual
process or connection. The ACTIVE/POST_ACTION phase assignment for the
mislabeled artifacts relies on the operator's contemporaneous annotations.

## Gemini

### STARTUP

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### IDLE

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### ACTIVE_QUERY

```text
Query:
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### POST_ACTION_IDLE

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

## Manus

### STARTUP

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### IDLE

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### ACTIVE_QUERY

```text
Query:
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### POST_ACTION_IDLE

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

## Perplexity

### STARTUP

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### IDLE

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### ACTIVE_QUERY

```text
Query:
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

### POST_ACTION_IDLE

```text
Capture:
Process count:
Executable identities:
TCP owners:
Unknown/helper processes:
Attribution guard:
Notes:
```

## Co-Residency Pass

```text
Applications running: Claude, Codex, Gemini, Manus, Perplexity
Discovery result: all five discovered under their expected profiles
Cross-identification observed: none
TCP attribution anomalies: none observed in capture summary
Attribution guard output: guard_rejected=0 for all five applications
Capture: .local/exp002/20260914T072142Z-all-coresidency.json
```

## Findings

Do not treat preliminary per-client results as cross-client conclusions until
the remaining controlled client captures are complete.

Separate:

- reproducible observations;
- tentative interpretations;
- unresolved unknowns.
