# Windows Firewall Evidence v1

## Scope

This layer records Windows firewall-profile and connection-profile source facts.
It does **not** decide whether a listener is remotely reachable, allowed by a
specific firewall rule, authenticated, vulnerable, or exploitable.

The intended evidence ladder is:

```text
listener bind
  -> stable process instance
  -> Windows service observations
  -> Windows firewall/network context
  -> later rule/path correlation
  -> later reachability evidence
```

The ordering above is methodological, not causal.

## Source collectors

### Firewall profiles

Source command:

```powershell
Get-NetFirewallProfile -PolicyStore ActiveStore
```

Observed fields:

- profile name
- enabled state
- default inbound action
- default outbound action
- `AllowInboundRules`
- `AllowLocalFirewallRules`

Event type:

```text
WINDOWS_FIREWALL_PROFILE_OBSERVED
```

Observation basis:

```text
windows_get_netfirewallprofile_active_store
```

### Connection profiles

Source command:

```powershell
Get-NetConnectionProfile
```

Observed fields:

- network name
- interface alias
- interface index
- network category
- IPv4 connectivity state
- IPv6 connectivity state

Event type:

```text
WINDOWS_NETWORK_PROFILE_OBSERVED
```

Observation basis:

```text
windows_get_netconnectionprofile
```

## Capture boundary

The two inventories are collected inside one PowerShell capture with explicit
start and finish timestamps. Events use the capture finish timestamp because
exact per-row timestamps are unavailable.

The endpoint model is:

```python
WindowsFirewallContext(
    firewall_profiles=(...),
    network_profiles=(...),
    capture_started_at=...,
    capture_finished_at=...,
)
```

`windows_firewall_context_event_batch()` serializes firewall-profile events
first, followed by connection-profile events. This is deterministic storage
order only. It must not be interpreted as temporal or causal ordering.

`append_windows_firewall_context()` writes the whole batch through one
`EventStore.append_many()` transaction.

## Explicit non-inferences

The following statements are intentionally outside Windows Firewall Evidence
v1:

```text
wildcard bind => remotely reachable
DefaultInboundAction=Block => listener is blocked
DefaultInboundAction=Allow => listener is reachable
Private network category => trusted path
Public network category => internet-exposed
firewall enabled => safe
firewall disabled => exploitable
```

A profile default is only one input into effective Windows Firewall behavior.
Rule applicability can also depend on direction, action, profile, protocol,
local/remote address, local/remote port, program, service, interface, policy
store, and other Windows filtering semantics.

Therefore v1 records profile context but does not yet correlate a listener to
specific effective rules.

## Next layer

The next firewall layer should capture structured inbound rule/filter evidence
from the active policy store and correlate candidate rules to listener facts
without silently collapsing Windows Firewall semantics into a Boolean
`allowed` value.

Only after rule/path evidence and an actual reachability observation exist
should a later analysis layer describe a service as reachable from a specified
network vantage point.
