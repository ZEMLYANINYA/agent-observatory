# EXP-001 — Process Baseline and First-Seen Detection

## Objective

Verify that Agent Observatory can establish a process baseline for a live
Windows workstation and distinguish a newly launched process from processes
already represented by the baseline.

The experiment specifically evaluates the normalized process fingerprint
model introduced after EXP-000.

## Method

A live Windows process inventory was collected and converted into normalized
process fingerprints.

The resulting fingerprint set was persisted as a local JSON baseline.

Two comparison passes were then performed:

1. a control comparison without intentionally changing the process state;
2. a comparison after intentionally launching Windows Notepad.

The local baseline artifact was not intended for publication or version
control.

## Expected Result

The control comparison should report no first-seen processes.

After launching a process not represented by the learned baseline, the
comparison should report that process as `FIRST_SEEN`.

## Safety

The experiment used read-only process observation except for intentionally
launching Notepad as the controlled test process.

No system configuration, application configuration, security policy, or
network configuration was modified.