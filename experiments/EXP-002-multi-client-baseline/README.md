# EXP-002 — Multi-Client Desktop Baseline

## Objective

Establish a comparative behavioral baseline for multiple desktop AI clients on
a live Windows workstation using Agent Observatory's current process identity,
application discovery, process-tree, and TCP attribution layers.

The experiment is intended to answer four questions:

1. Which process instances and executable identities are stable for each client?
2. Which process roles appear only during startup, active use, or post-action idle?
3. Which process instances actually own observed TCP connections?
4. Which native/helper processes participate in behavior outside the Electron
   network service?

## Applications

The first controlled pass covers clients already observed on the workstation:

- Claude
- Codex
- Gemini
- Manus
- Perplexity

A current ChatGPT Desktop profile should be added only after its installed
application identity has been observed directly. The legacy ChatGPT Classic
profile remains a compatibility case and is not the subject of this experiment.

## Evidence Model

For each application state, record:

- application profile and root PID;
- process tree and inferred process roles;
- PID, PPID, process start time, executable name, and executable path;
- Windows filesystem object identity where available:
  - volume serial number;
  - file ID;
- executable hash observation as a separate evidence object:
  - SHA-256 where available;
  - explicit hash state;
  - hash observation timestamp;
  - process-observation-to-hash timing gap;
- exact command-line identity hash;
- established TCP ownership by process instance;
- local and remote socket endpoints;
- helper/native processes that remain role `unknown`;
- capture timing and attribution-guard output.

Executable path is metadata, not executable identity. File identity is based on
the Windows filesystem object observed through a file handle. SHA-256 is a
separate post-capture observation of that filesystem object.

For evidence schema version 2, `hash_gap_ms` is anchored to the end of the
pre-network process inventory (`capture.process_before.finished_at`). Windows CIM
does not provide an exact observation timestamp for each returned process row,
so this value must not be interpreted as an exact per-process sampling delay.
The exported evidence includes this timing basis explicitly.

When multiple applications are captured together, executable identities are
built once across the full selected process set. Hash reuse is therefore keyed
by `FileIdentity` across the complete capture rather than independently inside
each application tree.

Observed facts must remain separate from interpretation. An `unknown` role is
preferred over a guessed role.

## Evidence Schema

Single-capture evidence currently uses `schema_version: 2`.

The executable object has the following shape:

```json
{
  "path": "C:\\Program Files\\Example\\App.exe",
  "file_identity": {
    "volume_serial": 1217733704,
    "file_id": 8162774325295280
  },
  "hash_observation": {
    "sha256": "...",
    "state": "hashed",
    "observed_at": "2026-09-16T18:00:00+00:00",
    "hash_gap_ms": 753.258
  }
}
```

`file_identity` may be `null` when Windows file identity cannot be observed.
Hash states remain explicit rather than inferring success from the presence or
absence of a digest.

Transition-query sessions use `schema_version: 3` and declare
`embedded_evidence_schema_version: 2` because every timed observation embeds a
single-capture evidence document.

## States

Each client is observed in the following controlled states:

1. **STARTUP** — capture shortly after a clean launch.
2. **IDLE** — application open and left untouched long enough for startup churn
   to settle.
3. **ACTIVE_QUERY** — capture immediately after sending one benign text query.
4. **POST_ACTION_IDLE** — capture after the query has completed and the client
   has returned to an idle state.

The primary per-client pass should run with only the target client intentionally
active where practical. A final co-residency pass may run all observed clients
simultaneously to verify discovery separation and process/TCP attribution under
contention.

## Method

For each client:

1. close the target application and confirm its process tree has terminated;
2. launch the application normally;
3. capture STARTUP evidence;
4. wait for the application to become idle and capture IDLE evidence;
5. submit one benign query that does not invoke external tools or file access;
6. capture ACTIVE_QUERY evidence while the request is active or immediately
   after transmission;
7. after completion and a short quiet period, capture POST_ACTION_IDLE evidence;
8. preserve the raw observation output before drawing conclusions.

The same capture commands and observation format should be used across clients.

## Preliminary Validation

Before the controlled experiment, a live multi-client smoke test successfully
identified Claude, Codex, Gemini, Manus, and Perplexity at the same time.

A later co-residency validation after executable-identity hardening observed 51
AI processes across those five applications. All 51 received executable hash
evidence, with zero non-hashed states and zero TCP connections rejected by the
PID-stability attribution guard.

That validation also exposed and fixed a PowerShell stdout encoding issue that
corrupted non-ASCII paths under a Windows user profile. Evidence transport now
forces UTF-8 and preserves paths such as `C:\Users\САНТЕР\...` without silent
replacement characters.

The smoke tests also showed that network ownership is not limited to Chromium's
`network.mojom.NetworkService`. Native/helper processes such as `codex.exe`,
`manus-computer-operator.exe`, and `perplexity-rpc-server.exe` were observed as
separate process-tree members, with some owning established TCP connections.

These preliminary observations are hypotheses to reproduce under controlled
states, not final experiment conclusions.

## Expected Result

Agent Observatory should:

- distinguish all configured applications without cross-identifying Codex as
  ChatGPT despite the shared `ChatGPT.exe` executable name;
- maintain stable process-instance attribution across the bracketing capture;
- preserve one executable identity for processes launched from the same binary
  while distinguishing concrete process instances by launch identity;
- keep executable path, filesystem identity, and hash observation as distinct
  evidence concepts;
- expose the timing gap between process capture and executable hashing;
- attribute established TCP connections only to validated process instances;
- expose helper/native processes without guessing unsupported semantic roles.

## Safety

The experiment is observational and local-first.

Queries used during ACTIVE_QUERY should be benign and should not request file
modification, shell execution, credential access, network scanning, exploitation,
or other privileged actions.

No TLS interception, credential capture, security-control bypass, or application
modification is required.
