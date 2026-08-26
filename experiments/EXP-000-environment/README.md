# EXP-000 — Environment Inventory

## Objective

Establish the initial operating-system, network, runtime, and AI-client
environment used by Agent Observatory.

The experiment also evaluates what information is required to identify AI
desktop application processes reliably.

## Method

Read-only observation was performed using native operating-system facilities.

The experiment inspected:

- operating-system and runtime information;
- network topology relevant to the laboratory;
- installed AI desktop packages;
- running AI application processes;
- parent and child process relationships;
- process creation times;
- runtime process roles;
- active TCP socket ownership.

No application configuration was changed.

No traffic was intercepted or modified.

No AI client was instrumented internally.

## Key finding

A naive PPID-based process tree falsely attributed a long-running `adb.exe`
process to ChatGPT.

Creation timestamps demonstrated that the supposed child process existed
before the current process occupying its reported parent PID.

The observation demonstrated PID reuse and established temporal validation as
a requirement for process attribution.

See [observations.md](observations.md) for the complete findings.

## Result

EXP-000 is complete.

Its findings define requirements for the first Agent Observatory endpoint
collector.