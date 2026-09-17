# Service Exposure Evidence v1

Service Exposure Evidence v1 records source observations needed to reason about locally exposed and published services without turning address/port topology into a vulnerability verdict.

The governing rule is:

```text
listening != reachable
published != reachable
reachable != unauthenticated
reachable != exploitable
```

## Architectural position

```text
source collection
    |
    +-- Windows TCP listeners
    +-- stable process identity
    +-- process principal SID
    +-- Windows services
    +-- Windows Firewall profile/network context
    +-- Windows Firewall rule inventory
    +-- Docker published ports
    |
    v
append-only EventStore
    |
    v
derived relationship / candidate analysis
    |
    v
future effective policy / reachability analysis
```

Facts, relationships, and conclusions remain separate.

## Durable observation types

The current service-exposure evidence surface includes:

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

A proposed `SERVICE_BINDING_OBSERVED` source event remains intentionally absent. A binding between listener, process, container, service, and policy evidence is derived relationship logic, not another raw source fact.

## TCP listener evidence

The live Windows path reuses the bracketed process/TCP/process capture.

For a stable listener process instance, the event can contain:

```text
owner_pid
owner_identity_basis = stable_process_instance
process = { pid, started_at }
process_name
executable_path
local_address
local_port
bind_scope
```

If process stability cannot be established, attribution remains unresolved.

The lower-level unbracketed helper still represents owner identity as PID-only snapshot evidence.

## Bind scope

Bind addresses use:

```text
loopback
wildcard
specific
unknown
```

`wildcard` describes socket address topology only. It does not mean LAN or Internet reachability.

## Process principal evidence

`WINDOWS_PROCESS_PRINCIPAL_OBSERVED` records the result of `Win32_Process.GetOwnerSid` for bracket-stable listener processes.

The process is verified again after the SID query, so a resolved SID is tied to the same `(pid, started_at)` process instance.

Possible evidence includes both successful and unsuccessful resolution:

```text
resolved + owner_sid + return_value=0
unresolved + return_value/reason
```

Access-denied results remain unresolved. The implementation does not infer a SYSTEM SID from process name or PID.

## Windows service evidence

`WINDOWS_SERVICE_OBSERVED` records running `Win32_Service` facts associated with listener process IDs and preserves stable process-instance attribution when verified.

A service sharing a process with a listener does not by itself prove that service owns the socket. This matters for shared host processes.

## Windows Firewall context

`WINDOWS_FIREWALL_PROFILE_OBSERVED` records ActiveStore profile context such as enabled state and default inbound/outbound actions.

`WINDOWS_NETWORK_PROFILE_OBSERVED` records interface profile assignment such as Public, Private, or Domain.

These facts are context. A default inbound action is not a per-listener verdict.

## Windows Firewall rule evidence v2

`WINDOWS_FIREWALL_RULE_OBSERVED` event version 2 records the expanded inbound ActiveStore rule condition surface, including:

```text
enabled / direction / action / profile
protocol
local and remote ports
local and remote addresses
program
package
service
interface type and alias
owner
primary/status metadata
loose/local-only mapping flags
ICMP type
dynamic target
authentication
encryption
override block rules
local user
remote user
remote machine
```

The rule name or display name is descriptive source metadata and is not parsed to invent missing package, application, or principal identity.

Event version 1 remains readable. Because it predates several condition fields, analysis must retain `RULE_CONDITION_SURFACE` as unknown for v1 rules.

## Firewall candidate correlation

`agent_observatory.analysis.correlate_firewall_rule_candidates(...)` is a derived analysis layer over source events.

It compares known listener context against enabled inbound firewall rules across dimensions such as:

```text
profile
protocol
local port/address
program
service
owner SID
remote constraints
interface constraints
security-filter conditions
dynamic target
rule status
```

A known incompatibility eliminates a rule.

An unresolved restrictive condition preserves the rule as a candidate with an unknown dimension.

Statuses are:

```text
CANDIDATE_MATCH
NO_CANDIDATE
AMBIGUOUS
```

`CANDIDATE_MATCH` means one source-compatible candidate remains with no unresolved dimensions. It is not an effective Windows Firewall allow/block verdict.

`AMBIGUOUS` can mean either multiple fully known compatible rules or one/more rules with unresolved dimensions.

`NO_CANDIDATE` means no collected rule survived the current compatibility checks. It does not prove remote unreachability.

Rule action is retained as source data but is not used to implement effective allow/block precedence in this layer.

## Stable identity joins

Where process identity is available, relationships use:

```text
(pid, started_at)
```

rather than PID alone.

This applies to principal evidence and service-name correlation. PID reuse must not transfer evidence between different process instances.

## Docker publication evidence

Docker host-port mappings come from structured `docker inspect` data for running containers.

A `DOCKER_PORT_PUBLISHED` event says Docker reported a host publication. It does not prove that another host can reach it or that the application behind it is unauthenticated.

## Capture completeness

`SERVICE_EXPOSURE_CAPTURE_MANIFEST` records each requested collector as succeeded, failed, or skipped.

A failed collector is not converted into a successful zero-record observation.

For process-principal evidence, persistence additionally validates that principal facts and the principal collector report agree on presence and record count.

## EventStore

The SQLite physical schema remains EventStore schema v1. New observation types and firewall event versions do not require a new table layout.

The durable ledger remains append-only.

## Current graph behavior

Evidence Graph v1 does not yet project these service-exposure facts into a dedicated service-exposure graph model.

Until an explicit projection is designed, source events remain ledger evidence and candidate correlation remains an analysis result rather than a persisted source fact.

## Current non-goals

This layer does not provide:

```text
service identity from port number alone
remote reachability proof
authentication testing
HTTP/API interrogation
vulnerability scanning
exploit checks
effective Windows Firewall precedence/disposition
exposure severity scoring
automatic blocking
```

Future layers may add controlled reachability evidence or effective policy evaluation, but those conclusions must remain traceable to explicit source facts.

## Design principle

```text
Observe the source fact.
Bind identity only when stable.
Preserve uncertainty explicitly.
Correlate without promoting correlation into a verdict.
```
