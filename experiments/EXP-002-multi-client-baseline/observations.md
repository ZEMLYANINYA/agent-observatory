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

These observations are retained only as reproduction targets for the controlled
experiment.

## Claude

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
Applications running:
Discovery result:
Cross-identification observed:
TCP attribution anomalies:
Attribution guard output:
Notes:
```

## Findings

Do not populate this section until the controlled state captures are complete.

Separate:

- reproducible observations;
- tentative interpretations;
- unresolved unknowns.
