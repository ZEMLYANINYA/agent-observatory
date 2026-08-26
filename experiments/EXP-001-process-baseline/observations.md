# EXP-001 Observations

## Baseline Capture

The initial live snapshot contained:

- observed processes: 277
- unique normalized process fingerprints: 126

The difference between the two counts is expected because multiple process
instances may share the same normalized fingerprint.

## Control Comparison

Immediately after baseline creation, a comparison was performed without
intentionally launching another application.

Result:

```text
FIRST_SEEN: 0