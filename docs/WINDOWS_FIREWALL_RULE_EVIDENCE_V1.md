# Windows Firewall Rule Evidence v1

## Purpose

This layer records inbound Windows Firewall rules from `ActiveStore` together with the filter facts exposed by the NetSecurity cmdlets.

It is source evidence for later correlation. It is not a per-listener firewall verdict.

## Source

The collector reads inbound rules from:

```powershell
Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound
```

For every returned rule it also captures the associated filters through:

```text
Get-NetFirewallPortFilter
Get-NetFirewallAddressFilter
Get-NetFirewallApplicationFilter
Get-NetFirewallServiceFilter
Get-NetFirewallInterfaceTypeFilter
Get-NetFirewallInterfaceFilter
```

The inventory has its own capture start and finish timestamps. All events produced from one inventory use the inventory finish time as their observation anchor.

## Event type

```text
WINDOWS_FIREWALL_RULE_OBSERVED
```

One event represents one observed inbound ActiveStore rule and preserves:

```text
name
display_name
enabled
direction
action
profile
edge_traversal_policy
policy_store_source_type
policy_store_source
protocol
local_ports
remote_ports
local_addresses
remote_addresses
programs
packages
services
interface_types
interface_aliases
observation_basis
```

Filter values are preserved as arrays because a filter may expose multiple values. The evidence layer does not collapse them to a single value.

## What the event does not mean

An observed rule with:

```text
action = Allow
protocol = TCP
local_ports = ["5985"]
profile = Public
```

does not by itself prove that a listener on TCP/5985 is allowed through Windows Firewall.

Likewise an observed Block rule does not by itself prove that a particular listener is blocked.

Rule applicability may depend on more than port number, including profile, local and remote address scope, program, service, package, interface type, interface alias, rule enablement, policy source, and Windows Firewall policy semantics.

Therefore this layer does not emit fields such as:

```text
matches_listener
applies_to_listener
effective_action
allowed
blocked
reachable
exposed
```

## EventStore boundary

`windows_firewall_rule_event_batch()` deterministically adapts one inventory to events in rule-name order as already normalized by the endpoint parser.

`append_windows_firewall_rule_inventory()` writes the whole inventory through one `EventStore.append_many()` call.

Append order is persistence order only. It is not causal precedence and it is not firewall rule precedence.

## Relationship to firewall context

This rule inventory complements, but does not replace:

```text
WINDOWS_FIREWALL_PROFILE_OBSERVED
WINDOWS_NETWORK_PROFILE_OBSERVED
```

The profile events describe ActiveStore profile defaults. The network-profile events describe interface category assignment. Rule events describe inbound rule and filter facts.

A later derived correlation layer may combine these sources with listener, process, and Windows service evidence. That correlation must remain explicit about uncertainty and must not silently promote candidate applicability into reachability or exploitability.

## v1 non-goals

Windows Firewall Rule Evidence v1 does not:

- calculate effective firewall policy for a listener;
- rank Allow versus Block rules;
- resolve Windows Filtering Platform internals;
- perform packet probes;
- prove local or remote reachability;
- infer authentication state;
- infer vulnerability or exploitability;
- mutate EventStore observations.
