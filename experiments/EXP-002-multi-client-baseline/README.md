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
- executable SHA-256 where available;
- exact command-line identity hash;
- established TCP ownership by process instance;
- local and remote socket endpoints;
- helper/native processes that remain role `unknown`;
- capture timing and attribution-guard output.

Observed facts must remain separate from interpretation. An `unknown` role is
preferred over a guessed role.

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

That smoke test also showed that network ownership is not limited to Chromium's
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
- attribute established TCP connections only to validated process instances;
- expose helper/native processes without guessing unsupported semantic roles.

## Safety

The experiment is observational and local-first.

Queries used during ACTIVE_QUERY should be benign and should not request file
modification, shell execution, credential access, network scanning, exploitation,
or other privileged actions.

No TLS interception, credential capture, security-control bypass, or application
modification is required.
