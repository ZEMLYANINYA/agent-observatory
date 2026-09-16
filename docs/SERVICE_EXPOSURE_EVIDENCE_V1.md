# Service Exposure Evidence v1

Service Exposure Evidence v1 adds source observations needed to reason about locally exposed and published services later, without turning address/port topology into a vulnerability verdict.

The governing rule is:

```text
listening != reachable
published != reachable
reachable != unauthenticated
reachable != exploitable
```

This layer records evidence only.

## Architectural position

```text
Windows TCP inventory                 Docker inspect
        |                                  |
        v                                  v
HostTcpListener                     DockerPublishedPort
        |                                  |
        v                                  v
TCP_LISTENER_OBSERVED               DOCKER_PORT_PUBLISHED
        \                                  /
         \                                /
          +---------- EventStore --------+
                         |
                         v
              future relationship /
              exposure analysis layer
```

No firewall verdict, service fingerprint, authentication check, remote probe, vulnerability classification, or exploitability conclusion is performed in v1.

## Event types

v1 adds exactly two durable observation types:

```text
TCP_LISTENER_OBSERVED
DOCKER_PORT_PUBLISHED
```

A proposed `SERVICE_BINDING_OBSERVED` event is intentionally not added.

The listener and Docker publication are source observations. A normalized service binding would be a relationship derived from those observations and other identity evidence. Persisting it as another source event would duplicate semantics and blur the boundary between evidence and projection.

## TCP listener observations

The existing Windows collector already uses:

```powershell
Get-NetTCPConnection
```

and retains every TCP state. Service Exposure Evidence therefore projects `Listen` / `Listening` records from the existing `TcpConnection` inventory rather than introducing a second Windows TCP collector.

`HostTcpListener` contains:

```text
owner_pid
local_address
local_port
state
owner_identity_basis
```

The protocol is currently `tcp`.

### PID is not process identity

The raw Windows TCP snapshot exposes an owning PID, but this first global listener projection does not have the bracketed process-instance validation used by the application capture path.

Therefore v1 explicitly records:

```text
owner_identity_basis = pid_only_snapshot
```

and does **not** serialize a `process: {pid, started_at}` reference.

A later bracketed global collector may strengthen listener attribution to process-instance identity. Until then, `owner_pid` remains a point-in-time owner field rather than durable process identity.

## Bind scope

Bind addresses are classified into a small topological vocabulary:

```text
loopback
wildcard
specific
unknown
```

Examples:

```text
127.0.0.1  -> loopback
::1        -> loopback
0.0.0.0    -> wildcard
::         -> wildcard
10.0.0.5   -> specific
```

`wildcard` means only that the socket/publication uses an unspecified-address bind.

It does **not** mean:

```text
Internet reachable
LAN reachable
firewall permitted
NAT forwarded
unauthenticated
vulnerable
exploitable
```

Those require independent evidence.

## TCP_LISTENER_OBSERVED payload

Current payload shape:

```json
{
  "protocol": "tcp",
  "owner_pid": 1234,
  "owner_identity_basis": "pid_only_snapshot",
  "state": "Listen",
  "local_address": "0.0.0.0",
  "local_port": 11434,
  "bind_scope": "wildcard",
  "observation_basis": "windows_get_nettcpconnection_snapshot"
}
```

No `reachable`, `exploitable`, `vulnerable`, service-name, or authentication field exists in this event.

## Docker publication observations

Docker host-port mappings are collected from structured `docker inspect` JSON for currently running containers.

The collector first obtains the exact running container IDs with:

```text
docker ps -q --no-trunc
```

and then inspects those IDs.

It does not parse the human-oriented `PORTS` display column from `docker ps`.

`DockerPublishedPort` contains:

```text
container_id
container_name
image
protocol
container_port
host_address
host_port
observation_basis
```

One object is created for each host binding returned by Docker. Dual-stack publications can therefore produce separate IPv4 and IPv6 observations.

Docker ports whose inspect value is `null` are container-exposed ports without a host publication and do not produce `DOCKER_PORT_PUBLISHED` events.

## DOCKER_PORT_PUBLISHED payload

Current payload shape:

```json
{
  "container": {
    "id": "...",
    "name": "ollama",
    "image": "ollama/ollama:latest"
  },
  "protocol": "tcp",
  "container_port": 11434,
  "host_address": "0.0.0.0",
  "host_port": 11434,
  "bind_scope": "wildcard",
  "observation_basis": "docker_inspect_running_container"
}
```

The event states that Docker reported a host publication. It does not establish successful reachability from any other network location.

## Docker collection failure semantics

The low-level Docker collector raises `DockerCollectionError` when:

```text
docker executable is unavailable
a Docker command times out
a Docker command returns a non-zero exit code
docker inspect JSON is invalid or structurally incomplete
```

It does not silently convert collection failure into an empty publication set.

An empty result from `collect_docker_published_ports()` means the successful `docker ps` query returned no running container IDs, or successful inspect evidence contained no published host bindings.

A higher-level live capture tool should preserve whether Docker collection was required, skipped, successful, or failed. That capture-manifest concern is intentionally separate from these source observation models.

## Deterministic evidence batch

`service_exposure_event_batch(...)` accepts explicit:

```text
TCP inventory
Docker published-port inventory
TCP observation timestamp
Docker observation timestamp
source
stream_id
```

The two collector timestamps remain separate. v1 does not manufacture simultaneity between Windows TCP collection and Docker inspection.

Serialization order is deterministic:

```text
1. TCP_LISTENER_OBSERVED events
2. DOCKER_PORT_PUBLISHED events
```

Within each group, facts are sorted by stable descriptive fields rather than caller iteration order.

`append_service_exposure_batch(...)` appends the complete constructed batch through the existing EventStore `append_many()` transaction.

## EventStore and schema

The SQLite storage schema remains EventStore schema v1. Adding new `EventType` enum values does not change the physical SQLite table layout.

The durable evidence ledger remains append-only.

## Current Graph behavior

Evidence Graph v1 does not yet project the new exposure events into service/listener nodes or relationships.

Until an explicit graph design is added, these events remain source-accounted by the projection fallback note:

```text
event_type_not_projected_v1
```

This is preferable to silently inventing a service identity or binding relationship.

The future graph layer should decide, explicitly, how to represent concepts such as:

```text
local listener endpoint
container identity
host publication
process-instance attribution
publication-to-listener correlation
```

without treating temporal or port-number correlation as causality.

## Future reachability evidence

A later layer may add evidence from sources such as:

```text
Windows Firewall configuration
Docker networking configuration
host interface inventory
controlled LAN probes
explicit loopback probes
service-specific safe metadata requests
```

Those observations must remain distinct from the listener/publication facts recorded here.

For example:

```text
0.0.0.0:11434 observed listening
```

is a valid v1 fact.

This is not a valid v1 conclusion:

```text
Ollama is remotely reachable and unauthenticated
```

That conclusion requires additional evidence for service identity, network path, response behavior, and authentication semantics.

## Current non-goals

Service Exposure Evidence v1 does not provide:

```text
service identification by port number
Redis detection
Ollama detection
firewall evaluation
remote reachability probes
authentication checks
HTTP/API interrogation
vulnerability scanning
exploit checks
exposure severity
anomaly scoring
automatic blocking
```

Those belong to later evidence collectors and deterministic analysis passes.

## Design principle

```text
Observe the bind.
Observe the publication.
Preserve the source.
Do not invent the path.
```
