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

Do not treat the preliminary Claude result as a cross-client conclusion until
the remaining controlled client captures are complete.

Separate:

- reproducible observations;
- tentative interpretations;
- unresolved unknowns.
