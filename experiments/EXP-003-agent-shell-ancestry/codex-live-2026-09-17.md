# EXP-003 Codex live run — 2026-09-17

## Result

**PASS**

The controlled live fixture successfully observed an agent-triggered process chain with an exited PowerShell intermediary and a surviving stable child process.

Observed chain:

```text
Codex root PID 4004
    ↓
PowerShell PID 26376        observed in processes_before, absent in processes_after
    ↓
Python child PID 19484      same process instance in processes_before/processes_after
```

Observed relationship evidence for the surviving child:

```text
state = valid
basis = parent_observed_before_only
```

Persisted EventStore evidence:

```text
stream_id = fixture-c:codex:20260917T132136Z:13f47986
relationship_event_id = 50
```

Successful observer session:

```text
C:\Users\САНТЕР\AppData\Local\Temp\agent-observatory-fixture-c\20260917T132048Z-codex-4d8d2d87
```

## What this proves

This run demonstrates, on a live Codex execution path, that the current capture/evidence pipeline can preserve historical ancestry when:

1. the application root remains the same stable process instance;
2. an intermediate `powershell.exe` process is present in the pre-capture application tree;
3. the PowerShell intermediary exits before the post-capture snapshot;
4. its child remains the same stable process instance across the bracketed capture;
5. the relationship is emitted through the production `windows_capture_event_batch()` path and persisted to EventStore.

The observed result is therefore consistent with the intended ancestry contract fixed after review: application membership comes from the full pre-capture tree, while emitted stable process evidence is filtered by process-instance stability.

## What this does not prove

The run does not establish maliciousness, user intent, semantic causality beyond observed parent/child ancestry, network reachability, exploitability, or effective policy disposition.

## Orchestration findings from failed attempts

Two earlier attempts failed before the ancestry contract was exercised and produced useful environment findings.

### Attempt 1 — relative shared path

The observer originally passed a relative `SessionDir`. Codex executed the PowerShell fixture from a different working directory, so the intermediary created its handshake files in a different location from the observer.

Result: transport/orchestration failure, not ancestry failure.

Fix: use an absolute shared session path.

### Attempt 2 — repository-local shared path

With an absolute repository-local path, Codex successfully launched PowerShell, but the agent-launched PowerShell received access denied while trying to write:

```text
D:\_ATEST\agent-observatory\.local\fixture-c\...\ready.json
```

This indicates the Codex execution environment can read/execute the fixture code from the repository but cannot write the repository-local `.local` handshake directory under the observed runner policy.

Result: execution-boundary observation, not ancestry failure.

Working configuration moved the handshake session to the user's temporary directory:

```text
%TEMP%\agent-observatory-fixture-c
```

The EventStore remained repository-local because persistence is performed by the external observer, not by the Codex-launched PowerShell intermediary.

## Command transport

The final successful run used an encoded PowerShell command:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand <base64>
```

This avoided path corruption caused by escaping of underscores during command transfer through the conversational interface.

## Live console result

```text
Fixture C: PASS
  agent=Codex root_pid=4004
  powershell_pid=26376 (before only)
  child_pid=19484 (stable across capture)
  relation=valid/parent_observed_before_only
  stream_id=fixture-c:codex:20260917T132136Z:13f47986
  relationship_event_id=50
```

## Follow-up

Before merging the EXP-003 branch:

- make the shared session root default to a cross-runner writable location rather than repository `.local`;
- run focused Fixture C regressions;
- run the full test suite;
- perform another external correctness review focused on orchestration boundaries and false-positive PASS conditions.
