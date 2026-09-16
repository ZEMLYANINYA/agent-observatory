# EXP-002 — Multi-Client Desktop Baseline

## Status

**Controlled baseline complete.**

The experiment now contains controlled or supporting observations for Claude,
Codex, Gemini, Manus, Perplexity, and five-client co-residency.

The final comparative interpretation is in [`FINAL_FINDINGS.md`](FINAL_FINDINGS.md).
Chronological notes and special-case runs remain in this experiment directory as
the supporting evidence trail.

## Objective

Establish a comparative behavioral baseline for multiple desktop AI clients on
a live Windows workstation using Agent Observatory's current process identity,
application discovery, process-tree, and TCP attribution layers.

The experiment asks four questions:

1. Which process instances and executable identities are stable for each client?
2. Which process roles appear during startup, active use, or post-action idle?
3. Which process instances own observed TCP records and what states are those
   records in?
4. Which native/helper processes participate outside the ordinary Electron role
   taxonomy?

## Applications

The controlled pass covers clients directly observed on the workstation:

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
- TCP ownership by validated process instance;
- TCP state for every returned record;
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

Single-capture evidence uses `schema_version: 2`.

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

Transition-query sessions use `schema_version: 4` and declare
`embedded_evidence_schema_version: 2` because every timed observation embeds a
single-capture evidence document.

Transition observations also record scheduler evidence:

```text
schedule_slot
scheduled_t_relative_ms
schedule_lag_ms
capture_duration_ms
```

The requested `--interval` is a target start-to-start cadence. If a capture takes
longer than the requested interval, missed schedule slots are skipped rather than
silently adding another full interval after capture completion.

## TCP summary semantics

Raw evidence preserves every returned TCP record and its state.

The cleanup console summary reports:

```text
tcp_total
established
bound
other
```

`tcp_total` is the total number of attributed TCP records in the snapshot. It is
**not** the number of established remote connections. The legacy
`summary["tcp_count"]` field remains in transition JSON as a backward-compatible
total while explicit state-count fields are added alongside it.

A stable TCP-record count does not imply no network traffic. Existing connections
can carry traffic without changing the number of observed socket records.

The current EXP-002 sensor does not observe UDP or complete flow lifetimes.

## States

Each client is observed where practical in the following controlled states:

1. **STARTUP** — capture shortly after a clean launch.
2. **IDLE** — application open and left untouched long enough for startup churn
   to settle.
3. **ACTIVE_QUERY** — timed observations after one benign text query.
4. **POST_ACTION_IDLE** — observations after the visible response completes.

The primary per-client pass runs with only the target client intentionally active
where practical. A co-residency pass runs all observed clients simultaneously to
verify discovery separation and process/TCP attribution under contention.

`RESPONSE_COMPLETE` in the transition protocol is an operator-observed UI marker.
It is not proof that the application, network stack, or remote service has become
idle.

## Method

For each client:

1. close the target application and confirm its process tree has terminated;
2. launch the application normally;
3. capture STARTUP evidence;
4. wait for startup churn to settle and capture IDLE evidence;
5. submit one benign query that does not invoke external tools or file access;
6. run the timed transition capture while the answer is produced;
7. mark visible response completion without inferring transport-level idle;
8. allow the scheduled post-response observations to complete;
9. preserve the raw observation output before drawing conclusions.

Special cases such as multi-query stress runs, network-interface transitions, or
UI-completion ambiguity are retained separately and are not silently merged into
the clean single-query baseline.

## Validation

A hardened live co-residency validation observed all five configured desktop AI
clients simultaneously:

```text
Claude       8 processes
Codex       16 processes
Gemini      10 processes
Manus        7 processes
Perplexity  10 processes
```

Global result:

```text
AI applications       5
AI processes          51
hash evidence         51 / 51
non-HASHED states     0
guard-rejected TCP    0
```

This validation also exposed and fixed a PowerShell stdout encoding issue that
corrupted non-ASCII paths under a Windows user profile. Evidence transport now
forces UTF-8 and preserves paths such as `C:\Users\САНТЕР\...` without silent
replacement characters.

The experiment additionally exposed:

- capture-limited scheduler cadence;
- ambiguous aggregate TCP presentation;
- launch-time discovery ambiguity;
- UI-visible completion that does not necessarily coincide with network idle;
- the need to preserve network state as evidence rather than collapse it into a
  single count.

These findings are documented in `FINAL_FINDINGS.md`.

## Discovery ambiguity

Application discovery is point-in-time evidence.

During EXP-002, very-early startup produced both `not discovered` and
`multiple candidate roots` edge cases on different clients. Future multiple-root
errors include candidate PID, PPID, start time, and executable path so the
ambiguity can be inspected instead of reduced to a generic failure.

Future persistence should preserve absent, unique, and ambiguous discovery
outcomes as distinct observations.

## Safety

The experiment is observational and local-first.

Queries used during ACTIVE_QUERY are benign and do not request file
modification, shell execution, credential access, network scanning, exploitation,
or other privileged actions.

No TLS interception, credential capture, security-control bypass, or application
modification is required.

## Next milestone

After the final cleanup test gate, EXP-002 is closed.

The next architecture milestone is SQLite + WAL append-only EventStore v1. The
EventStore should preserve observations first and leave relationships, drift,
Evidence Graph projections, and analysis as derived layers.
