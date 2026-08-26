# EXP-000 Observations

## Experiment

Initial environment and AI desktop client inventory.

## Status

Completed.

## Windows endpoint

The monitored workstation runs a 64-bit Windows environment with Python 3.12.

Two native AI desktop clients were present during the experiment:

| Application | Installation | Observed architecture |
|---|---|---|
| ChatGPT Desktop | Windows packaged application | Multi-process Electron/Chromium-style runtime |
| Claude Desktop | Windows packaged application | Multi-process Electron/Chromium-style runtime |

Exact host identifiers, usernames, addresses, and other environment-specific
values are intentionally omitted from public observations.

## Process discovery

Both applications expose a visible root process and multiple child processes.

Observed ChatGPT process roles included:

- main
- renderer
- network service
- GPU process
- crash handler

Observed Claude process roles included:

- main
- renderer
- network service
- GPU process
- audio service
- video capture service
- crash handler

Process names alone are therefore insufficient for complete application
attribution.

## Network attribution

Active TCP connections were observed from processes belonging to both
application trees.

Network activity was not necessarily owned by the visible root process.

For example, dedicated Chromium NetworkService processes owned active
outbound TCP connections.

This establishes an initial requirement:

> Network activity must be attributed to the complete validated application
> process tree rather than only to the visible root process.

No attempt was made during EXP-000 to classify remote endpoints as benign or
suspicious.

## Capability versus activity

Desktop runtime metadata exposed multiple application capabilities and feature
flags.

The presence of a capability or feature flag is not evidence that the
capability was exercised during the observation period.

Agent Observatory therefore distinguishes:

    capability != observed activity

Alerts must be based on observed behavior rather than feature availability
alone.

## PID reuse finding

During initial recursive process-tree reconstruction, an existing `adb.exe`
process appeared to be a descendant of a ChatGPT renderer.

The apparent relationship was:

    ChatGPT
      -> renderer
           -> adb.exe

This relationship was false.

Timestamp comparison showed that `adb.exe` had started almost two days before
the ChatGPT renderer currently occupying the reported parent PID.

The parent PID had been reused by Windows.

Therefore a PPID-only reconstruction produced a false attribution.

### Resulting rule

A parent-child relationship must be temporally valid.

At minimum:

    child_start_time >= parent_start_time

If the supposed child predates the current process occupying its reported
parent PID, the relationship must be rejected.

Possible classification:

    relationship.state  = invalid
    relationship.reason = parent_pid_reused

## Privacy observation

Raw system inventory may contain information unnecessary for public research,
including:

- usernames
- hostnames
- machine identifiers
- boot identifiers
- MAC addresses
- SSIDs
- local addressing
- user-specific filesystem paths

Raw evidence should remain local.

Public evidence should pass through a deterministic sanitization layer.

## Requirements derived from EXP-000

The endpoint collector should:

1. discover AI application root processes dynamically;
2. recursively discover descendants;
3. identify known process roles from runtime metadata;
4. preserve unknown process roles rather than guessing;
5. validate parent-child relationships using process creation times;
6. tolerate PID reuse;
7. attribute sockets to validated process identities;
8. distinguish internal application components from external tools;
9. distinguish capabilities from observed behavior;
10. collect only telemetry necessary for the research objective;
11. sanitize evidence before public export.

## Conclusion

EXP-000 demonstrated that naive process-name and PPID-based monitoring is not
sufficient for reliable AI application attribution.

The most significant finding was a real false-positive process relationship
caused by Windows PID reuse.

This finding directly changes the design of the first endpoint collector.