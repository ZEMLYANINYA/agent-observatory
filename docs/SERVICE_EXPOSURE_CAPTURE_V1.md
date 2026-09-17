# Service Exposure Capture v1

Service Exposure Capture v1 is the live collector layer for service-exposure evidence.

It persists point-in-time Windows listener, process-principal, Windows service, firewall context/rule, and Docker publication evidence in one append-only EventStore stream together with explicit collector-completeness metadata.

The governing rule remains:

```text
listening != reachable
published != reachable
reachable != unauthenticated
reachable != exploitable
```

## Current live collectors

The production CLI currently requests:

```text
windows_tcp_listeners
windows_listener_process_principals
windows_listener_services
windows_firewall_context
windows_firewall_rules
docker_published_ports
```

Docker can be explicitly skipped.

Process-principal collection is limited to listener processes that were already attributed to a stable process instance by the bracketed Windows capture.

## Capture manifest

Every live capture that reaches EventStore persistence ends with exactly one:

```text
SERVICE_EXPOSURE_CAPTURE_MANIFEST
```

The manifest distinguishes:

```text
succeeded
failed
skipped
```

A succeeded collector has an integer `record_count`, including zero.

A failed or skipped collector has:

```text
record_count = null
```

Failed collectors also preserve:

```text
error_type
error_message
```

`partial=true` means at least one requested collector failed. It does not invalidate facts collected successfully by other collectors.

## Principal completeness contract

`WINDOWS_PROCESS_PRINCIPAL_OBSERVED` is optional source evidence, but when principal facts are persisted their manifest report must agree with them.

Persistence rejects a capture when:

```text
principal facts exist without windows_listener_process_principals report
principal report count differs from persisted principal observations
failed/skipped principal report carries principal facts
collector report names are duplicated
```

This prevents missing principal evidence from being represented as a successful empty collection.

A principal resolution failure is itself preserved as evidence. For example:

```text
resolution_state = unresolved
get_owner_sid_return_value = 2
resolution_reason = access_denied
```

No SID is guessed for protected system processes.

## Listener attribution

The production live capture uses the existing Windows process/TCP/process bracket.

When the same process instance is present across the bracket, listener evidence contains:

```text
owner_identity_basis = stable_process_instance
process = { pid, started_at }
process_name
executable_path, when available
```

If stable process attribution cannot be established, the listener remains unresolved instead of being upgraded from PID alone.

The lower-level `service_exposure_event_batch(...)` helper still supports explicit unbracketed TCP inventories and therefore preserves PID-only semantics there.

## Process principal evidence

For bracket-stable listener processes, the optional principal collector invokes:

```text
Win32_Process.GetOwnerSid
```

and performs another process snapshot after the SID query.

The SID is attached only when the same `(pid, started_at)` process instance remains stable across the query.

This evidence is later used by firewall candidate correlation for the firewall rule `Owner` condition.

## Windows service evidence

Running `Win32_Service` records are collected for listener process IDs and then verified against a fresh process snapshot.

A service event tied to the same process instance means only that the service is hosted in that observed process instance.

It does not prove that a particular service owns a particular socket, especially for shared service-host processes.

## Windows Firewall evidence

The capture persists two independent firewall evidence surfaces:

```text
WINDOWS_FIREWALL_PROFILE_OBSERVED
WINDOWS_NETWORK_PROFILE_OBSERVED
WINDOWS_FIREWALL_RULE_OBSERVED
```

Firewall profile defaults are context only.

Firewall rule evidence v2 preserves the expanded ActiveStore condition surface, including owner, status, mapping flags, dynamic target, security-filter principals, authentication/encryption fields, addresses, ports, program, package, service, and interface filters.

These are source facts. The capture layer does not decide whether a listener is allowed or blocked.

## Candidate correlation is a separate analysis layer

`analysis.firewall_rule_candidates` correlates listener evidence with firewall rule evidence conservatively.

Its statuses are:

```text
CANDIDATE_MATCH
NO_CANDIDATE
AMBIGUOUS
```

These statuses describe source compatibility only.

They are not effective Windows Firewall verdicts and do not establish reachability.

A v1 firewall rule event remains readable, but because it predates the expanded rule condition surface it retains:

```text
RULE_CONDITION_SURFACE = unknown
```

and cannot become a fully known candidate match merely because newer principal evidence exists in the same stream.

## Observation times

Collectors are not treated as simultaneous.

The live capture keeps separate observation anchors for listener, principal, service, firewall source inventory, Docker, and the final manifest where the underlying collector provides an appropriate capture interval or point-in-time anchor.

No per-record precision is invented when the source cannot provide it.

## Live CLI

Operator entry point:

```text
tools/service_exposure_capture.py
```

Example:

```powershell
python .\tools\service_exposure_capture.py `
  --db .\.local\service-exposure-live.sqlite3 `
  --details
```

Docker can be skipped explicitly:

```powershell
python .\tools\service_exposure_capture.py `
  --db .\.local\service-exposure-live.sqlite3 `
  --skip-docker `
  --details
```

## Exit codes

```text
0  requested collectors succeeded, or an optional collector was explicitly skipped
1  fatal capture or EventStore error prevented normal persistence
2  partial capture was persisted because at least one requested collector failed
3  persisted-stream verification failed
```

## Event ordering

The live batch is persisted deterministically as:

```text
TCP_LISTENER_OBSERVED
WINDOWS_PROCESS_PRINCIPAL_OBSERVED
WINDOWS_SERVICE_OBSERVED
WINDOWS_FIREWALL_PROFILE_OBSERVED
WINDOWS_NETWORK_PROFILE_OBSERVED
WINDOWS_FIREWALL_RULE_OBSERVED
DOCKER_PORT_PUBLISHED
SERVICE_EXPOSURE_CAPTURE_MANIFEST
```

Groups with zero observations are simply absent. The manifest remains present.

## Non-goals

Service Exposure Capture v1 does not perform:

```text
port-number service identification
remote probing
HTTP/API interrogation
authentication checks
vulnerability checks
exploit attempts
effective Windows Firewall disposition
reachability verdicts
severity scoring
anomaly classification
automatic blocking
```

## Design principle

```text
Record what was collected.
Record whether collection succeeded.
Tie identity to stable process instances.
Never turn missing evidence into a negative fact.
```
