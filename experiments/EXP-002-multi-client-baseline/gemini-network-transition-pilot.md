# EXP-002 Gemini Network-Transition Pilot

## Status

This sequence is retained as a pilot and must not be treated as the controlled
Gemini baseline.

During the run, the operator switched the workstation from the primary Wi-Fi
connection to mobile internet while waiting for Gemini to answer. The response
did not begin immediately after the interface change. Because network transport
changed during the observation window, the run is intentionally separated from
the controlled STARTUP / IDLE / ACTIVE_QUERY / POST_ACTION_IDLE sequence.

Several captures were also invoked with state labels that do not match the
actual operator-observed phase. Artifact metadata is preserved as originally
written; the timeline below records the chronology without rewriting the local
JSON evidence.

## Timeline

The first attempted ACTIVE_QUERY capture did not discover Gemini or any other
configured application. A subsequent capture succeeded:

```text
20260914T080849Z  label=ACTIVE_QUERY  processes=11  tcp=2  unknown=0  guard_rejected=0
20260914T080854Z  label=STARTUP       processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T080955Z  label=IDLE          processes=10  tcp=6  unknown=0  guard_rejected=0
20260914T081402Z  label=IDLE          processes=10  tcp=6  unknown=0  guard_rejected=0
20260914T081427Z  label=IDLE          processes=10  tcp=3  unknown=0  guard_rejected=0
20260914T081430Z  label=IDLE          processes=10  tcp=3  unknown=0  guard_rejected=0
20260914T081433Z  label=IDLE          processes=10  tcp=3  unknown=0  guard_rejected=0
20260914T081436Z  label=IDLE          processes=10  tcp=3  unknown=0  guard_rejected=0
20260914T081439Z  label=IDLE          processes=10  tcp=3  unknown=0  guard_rejected=0
20260914T081443Z  label=IDLE          processes=10  tcp=3  unknown=0  guard_rejected=0
20260914T081447Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081449Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081452Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081455Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081501Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081505Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081511Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081523Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081536Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081600Z  label=IDLE          processes=10  tcp=2  unknown=0  guard_rejected=0
20260914T081648Z  label=IDLE          processes=10  tcp=0  unknown=0  guard_rejected=0
20260914T081735Z  label=IDLE          processes=10  tcp=0  unknown=0  guard_rejected=0
20260914T081804Z  label=IDLE          processes=10  tcp=0  unknown=0  guard_rejected=0
20260914T081808Z  label=IDLE          processes=10  tcp=0  unknown=0  guard_rejected=0
```

According to the operator's contemporaneous note, Gemini finally produced the
response during the final two captures (`081804Z` and `081808Z`). Before that,
the workstation had already been switched from the primary Wi-Fi connection to
mobile internet, but Gemini did not respond immediately after the switch.

## Narrow observations

The observed Gemini process topology was notably stable after the early launch
sample: 10 processes, zero unknown-role processes, and zero attribution-guard
rejections across the long sampled interval.

Observed TCP snapshot counts declined from 6 to 3 to 2 and eventually to 0.
The final two captures coincided with the operator-observed response while the
EXP-002 TCP snapshot count remained 0.

This does **not** establish that Gemini used UDP, QUIC, HTTP/3, or any other
specific transport. The current EXP-002 network evidence is point-in-time TCP
only. A response coinciding with `tcp=0` therefore supports only the narrower
conclusion that this TCP snapshot stream was insufficient to explain the full
network activity of this episode. Plausible unresolved explanations include
short-lived TCP activity between captures, non-TCP transport, effects of the
interface transition, or a combination of those factors.

## Experimental consequence

A new controlled Gemini baseline should be repeated with one network interface
held stable for the entire run. This pilot should remain available as a separate
network-transition case rather than being merged into the controlled baseline.

The episode also exposes a sensor-coverage question for later work: whether the
Windows network sensor should eventually observe UDP alongside TCP. That is a
follow-up requirement, not a conclusion about the transport used in this run.
