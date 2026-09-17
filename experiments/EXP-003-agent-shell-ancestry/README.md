# EXP-003 — Agent → PowerShell → child ancestry fixture

## Purpose

Validate one narrow ancestry invariant in a real Windows process capture:

```text
AI desktop agent
    ↓
powershell.exe          observed in processes_before, gone in processes_after
    ↓
harmless Python child   same process instance in before and after
```

The expected relationship for the surviving child is:

```text
state = valid
basis = parent_observed_before_only
```

This experiment exists to prove the production evidence path preserves historical parent evidence when an intermediate process exits between bracketed process snapshots.

It does **not** prove causality beyond the observed process ancestry, maliciousness, intent, network reachability, or exploitability.

## Fixture design

The observer is `tools/fixture_c_ancestry.py`.

The target AI agent must execute the exact command printed by the observer. That command launches `tools/fixture_c_intermediate.ps1` as a descendant of the target agent.

The PowerShell intermediary:

1. launches `tools/fixture_c_child.py` as a harmless long-lived child;
2. writes `ready.json` with its PID and the child PID;
3. waits for the observer's `release.signal`;
4. exits deliberately while the child remains alive.

The observer synchronizes the capture instead of relying on timing luck:

1. wait until PowerShell and child are both visible inside the requested agent's pre-capture application tree;
2. capture `processes_before`;
3. create `release.signal`;
4. wait until PowerShell is gone while both the requested agent root and child remain the same process instances;
5. capture `processes_after`;
6. construct a `WindowsCapture` with no TCP evidence by design;
7. validate `build_capture_parent_relations()`;
8. pass the capture through `windows_capture_event_batch()`;
9. validate the production adapter batch before persistence;
10. atomically persist the validated batch to a dedicated EventStore stream;
11. verify the stored child relationship remains `valid / parent_observed_before_only`.

The observer always creates `child-stop.signal` during cleanup so the harmless child exits without requiring a force kill.

## Safety / scope

The fixture intentionally performs no network request, privilege elevation, persistence, credential access, file modification outside its `.local/fixture-c/` session directory, or destructive action.

Raw command lines are not persisted in EventStore. The normal process event adapter stores only the command-line SHA-256 digest.

## Run

From a normal PowerShell terminal outside the target AI agent:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python .\tools\fixture_c_ancestry.py --agent Codex
```

Valid configured targets are the application profiles already known to Agent Observatory, currently:

```text
ChatGPT
Claude
Codex
Gemini
Manus
Perplexity
```

The observer prints one exact `powershell.exe ... fixture_c_intermediate.ps1 ...` command.

Ask the selected AI desktop agent to execute that command unchanged. Do not run the printed command manually from the observer terminal, because then PowerShell will not be evidence of agent ancestry.

## PASS criteria

All of the following must be true:

1. the requested AI application root is discovered in `processes_before` and remains the same stable process instance in `processes_after`;
2. the PowerShell intermediary and harmless child both belong to that pre-capture application tree;
3. the child's observed PPID equals the PowerShell PID;
4. PowerShell is absent from `processes_after`;
5. the child remains the same stable process instance across the capture;
6. `build_capture_parent_relations()` returns `VALID / PARENT_OBSERVED_BEFORE_ONLY` for the child;
7. `windows_capture_event_batch()` contains exactly one matching relationship event with the same state/basis before anything is committed;
8. the EventStore append succeeds as a new stream and preserves that relationship event.

A PASS means only that the ancestry evidence survived an exited intermediary correctly.

## Outputs

Default session directory:

```text
.local/fixture-c/<timestamp>-<agent>-<id>/
```

Session artifacts:

```text
ready.json
release.signal
child-stop.signal
result.json
```

Default fixture EventStore:

```text
.local/fixture-c.sqlite3
```

A successful `result.json` records the selected agent root PID, PowerShell PID, child PID, relationship state/basis, stream ID, and persisted relationship event ID.

## Failure semantics

The fixture fails instead of guessing when any required observation is missing or ambiguous, including:

- PowerShell or child absent from the before snapshot;
- intermediary PID does not identify `powershell.exe`;
- child PPID does not equal PowerShell PID;
- fixture processes are not in the requested agent tree;
- more than one target-agent root contains the fixture processes;
- target agent root disappears or changes process identity;
- PowerShell remains present after release;
- child disappears or its PID is reused;
- relationship state/basis is not the expected historical-parent evidence;
- production adapter batch does not contain the expected relationship before persistence;
- persisted EventStore relationship does not match the validated batch.

Ctrl+C records the local fixture result as `interrupted` and still signals both release and child cleanup.

## Regression coverage

`tests/test_fixture_c_ancestry.py` covers:

- expected historical-parent relation;
- parent still alive after release;
- child PID reuse;
- target agent root PID reuse;
- fixture processes outside the requested agent tree.
