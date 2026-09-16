# Service Exposure Capture v1

Service Exposure Capture v1 is the live collector layer built on top of `SERVICE_EXPOSURE_EVIDENCE_V1`.

Its purpose is to persist point-in-time Windows TCP listener evidence, Docker host-port publication evidence, and explicit collector-completeness metadata in one append-only EventStore stream.

The governing rule remains:

```text
listening != reachable
published != reachable
reachable != unauthenticated
reachable != exploitable
```

## Why a capture manifest exists

An empty evidence set is ambiguous unless collection completeness is recorded.

These two situations are not equivalent:

```text
Docker collection succeeded and observed 0 published ports
Docker collection failed before publication evidence could be observed
```

Without a manifest both cases would produce zero `DOCKER_PORT_PUBLISHED` events.

Service Exposure Capture v1 therefore persists exactly one:

```text
SERVICE_EXPOSURE_CAPTURE_MANIFEST
```

for every live capture stream that reaches EventStore append.

## Collector statuses

Current collectors are:

```text
windows_tcp_listeners
docker_published_ports
```

Each collector report uses one status:

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

This prevents a collection failure from masquerading as a successful zero observation.

Failed collectors also preserve:

```text
error_type
error_message
```

Explicit Docker skipping is represented as `skipped`, not `failed`.

## Manifest payload

Current shape:

```json
{
  "capture_kind": "service_exposure",
  "partial": false,
  "collectors": [
    {
      "collector": "windows_tcp_listeners",
      "status": "succeeded",
      "record_count": 18,
      "observation_basis": "windows_get_nettcpconnection_snapshot",
      "error_type": null,
      "error_message": null
    },
    {
      "collector": "docker_published_ports",
      "status": "succeeded",
      "record_count": 3,
      "observation_basis": "docker_inspect_running_container",
      "error_type": null,
      "error_message": null
    }
  ]
}
```

`partial=true` means at least one requested collector failed.

It does not mean the surviving evidence is invalid. It means the stream is incomplete with respect to the requested collection set.

## Best-effort collection, atomic persistence

Collectors run independently.

For example, if Docker collection fails but Windows listener collection succeeds:

```text
Windows listener facts are preserved
Docker facts are absent
manifest records Docker failure
partial = true
```

The resulting facts and manifest are appended together through one EventStore `append_many()` transaction.

This separates two concerns:

```text
collector execution can be partial
EventStore persistence is atomic
```

## Observation times

Windows listener collection and Docker inspection are not simultaneous.

Successful collector outputs therefore keep separate observation anchors:

```text
listener_observed_at
docker_observed_at
```

The manifest has its own later observation time representing completion of the collector run.

v1 does not manufacture per-record timestamp precision that the source collectors do not provide.

## Live CLI

The operator entry point is:

```text
tools/service_exposure_capture.py
```

Default behavior collects both Windows listeners and Docker published ports.

Example:

```powershell
python .\tools\service_exposure_capture.py `
  --db .\.local\service-exposure-v1-live.sqlite3 `
  --details
```

Docker can be explicitly skipped:

```powershell
python .\tools\service_exposure_capture.py `
  --db .\.local\service-exposure-v1-live.sqlite3 `
  --skip-docker
```

The manifest records that state as `skipped`.

## Exit codes

Current CLI meanings are:

```text
0  all requested collectors succeeded, or a collector was explicitly skipped
1  fatal capture or EventStore error prevented normal persistence
2  persisted partial capture because at least one requested collector failed
3  persisted-stream verification failed
```

A partial capture is intentionally persisted before returning code `2`.

## Human output

The CLI prints:

```text
collector status and record counts
EventStore event counts
bind-scope counts
semantic limitations
```

With `--details` it also prints the observed listener and Docker publication facts.

The output explicitly states that bind scope is address topology only and that no remote reachability, authentication, or exploitability is inferred.

## Bind scope remains descriptive

The live capture reuses the evidence-layer vocabulary:

```text
loopback
wildcard
specific
unknown
```

For example:

```text
0.0.0.0:11434 scope=wildcard
```

means only that the observed listener was bound to an unspecified IPv4 address at the snapshot time.

It does not establish:

```text
LAN reachability
Internet reachability
firewall allowance
service identity
lack of authentication
vulnerability
exploitability
```

## PID attribution remains limited

Windows listener evidence still carries:

```text
owner_pid
owner_identity_basis = pid_only_snapshot
```

The live capture does not upgrade a raw owning PID into a stable `PID + started_at` process identity.

That requires a later bracketed attribution collector.

## Docker publication remains Docker evidence

A `DOCKER_PORT_PUBLISHED` event means Docker reported a host-port mapping for a running container.

It does not by itself prove that a corresponding Windows listener is visible, that traffic reaches the container, or that the application behind the publication accepts unauthenticated requests.

Future relationship logic may correlate publication and listener observations, but that correlation must remain explicit and evidence-bounded.

## EventStore stream shape

A successful non-empty stream is typically:

```text
TCP_LISTENER_OBSERVED ...
DOCKER_PORT_PUBLISHED ...
SERVICE_EXPOSURE_CAPTURE_MANIFEST
```

A successful zero-record capture is still represented:

```text
SERVICE_EXPOSURE_CAPTURE_MANIFEST
```

with both successful collector counts equal to zero.

A partial capture can likewise contain only surviving facts plus the manifest.

## Current Graph behavior

Evidence Graph v1 does not yet project service-exposure events into dedicated service/listener/container nodes.

Until that design is introduced, the events remain source-accounted through the existing fallback projection-note behavior.

The capture manifest is collection metadata and must not be interpreted as service behavior.

## Non-goals

Service Exposure Capture v1 does not perform:

```text
port-number service identification
Redis identification
Ollama identification
firewall evaluation
remote probing
HTTP/API requests
authentication checks
vulnerability checks
exploit attempts
severity scoring
anomaly classification
automatic blocking
```

## Design principle

```text
Record what was collected.
Record whether collection succeeded.
Never turn missing evidence into a negative fact.
```
