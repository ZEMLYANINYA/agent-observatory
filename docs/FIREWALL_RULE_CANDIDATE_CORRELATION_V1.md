# Firewall Rule Candidate Correlation v1

## Purpose

This layer derives **candidate relationships** between persisted TCP listener facts and persisted inbound Windows Firewall rule facts from the same service-exposure stream.

It does not compute Windows Firewall effective disposition.

The model is deliberately conservative:

```text
listener fact
    +
network-profile context
    +
process/service attribution
    +
inbound ActiveStore rule facts
        ↓
source-compatible candidate rules
```

The output is a read-only derived view. No new EventStore facts are appended.

## Firewall rule evidence versions

`WINDOWS_FIREWALL_RULE_OBSERVED` v1 captured the initial rule/filter surface:

- profile, protocol, ports, addresses;
- program/package/service filters;
- interface alias/type;
- action and basic rule metadata.

Live validation showed that this surface was not sufficient to call a surviving rule fully compatible. Windows Firewall rules can also carry owner/principal/security and dynamic-transport conditions.

`WINDOWS_FIREWALL_RULE_OBSERVED` v2 therefore additionally preserves:

- rule `Owner`;
- `PrimaryStatus` and status text;
- `LooseSourceMapping` and `LocalOnlyMapping`;
- `IcmpType` and `DynamicTarget`/dynamic transport;
- security-filter `Authentication`, `Encryption`, and `OverrideBlockRules`;
- security-filter `LocalUser`, `RemoteUser`, and `RemoteMachine`.

A v1 rule event is still readable, but candidate correlation always marks `RULE_CONDITION_SURFACE` unresolved for it. A v1 event can therefore never become a fully-known `CANDIDATE_MATCH` merely because the older captured fields line up.

## Result states

Each listener receives one of three descriptive states.

### `CANDIDATE_MATCH`

Exactly one enabled inbound rule remains compatible and all evaluated dimensions are known.

This means only that the persisted source facts line up under the v1 correlation rules.

It does **not** mean:

- Windows Firewall will allow the traffic;
- no higher-precedence block rule applies;
- the listener is remotely reachable;
- authentication is absent;
- the service is exploitable.

### `NO_CANDIDATE`

No enabled inbound rule remains compatible after applying known v1 dimensions.

This does **not** prove remote unreachability. The capture can still be incomplete and Windows filtering behavior is broader than this v1 model.

### `AMBIGUOUS`

At least one rule remains source-compatible, but either:

- more than one rule is compatible; or
- at least one relevant dimension cannot be resolved from captured evidence.

Examples of unresolved dimensions include restrictive remote peer scope, special Windows port tokens such as `RPC`, restrictive package/interface type filters, rule owner/principal/security filters, dynamic targets, incomplete v1 rule evidence, or missing process/service identity.

## Dimensions evaluated

v1 correlation evaluates these rule dimensions when the corresponding source evidence exists:

- rule condition-surface completeness/version;
- rule primary status;
- active network profile versus rule profile;
- protocol, with TCP and protocol number `6` treated as TCP;
- local port, including numeric ranges;
- local address, including exact IPs and CIDR ranges when the listener address is specific;
- executable program path when a concrete listener path exists;
- Windows service name when service attribution exists;
- package filter;
- rule owner;
- remote port scope;
- remote address scope;
- interface alias;
- interface type;
- dynamic target/transport;
- ICMP type condition;
- authentication and encryption conditions;
- override-block condition;
- local-user, remote-user, and remote-machine security conditions;
- loose-source and local-only mapping flags.

A known contradiction excludes a rule from the candidate set.

An unresolved restrictive dimension keeps the rule as a candidate but marks that dimension unknown.

## Important conservative cases

### Wildcard listener addresses

For listeners bound to `0.0.0.0` or `::`, a restrictive firewall local-address filter is not converted into a false mismatch. The concrete inbound interface/address has not been selected by an observed connection, so the local-address dimension remains unresolved.

### Remote peer filters

A listening socket has no concrete remote peer. Restrictive `RemoteAddress` or `RemotePort` filters therefore remain unresolved until evidence from an actual inbound path exists.

### Special Windows port tokens

Tokens such as `RPC` are preserved as unresolved rather than being guessed into numeric ports.

### Dynamic transports

Windows can use dynamic targets such as proximity sharing or Wi-Fi Direct where ordinary protocol/port conditions are not sufficient to describe matching. A non-`Any` dynamic target therefore remains unresolved in candidate correlation.

### Program paths

Exact concrete Windows paths can be compared case-insensitively. Environment-variable and wildcard-bearing rule program filters remain unresolved unless a later layer adds safe expansion semantics.

### Services

A restrictive service filter is compared only against persisted `WINDOWS_SERVICE_OBSERVED` facts for the listener-owning PID. Absence of service evidence does not become proof that the rule cannot apply.

### Package, owner, and principal identity

Restrictive package, owner, local-user, remote-user, or remote-machine conditions remain unresolved unless matching identity evidence is available. Rule names and display names are never parsed as substitutes for source filter evidence.

### Security conditions

Authentication, encryption, and authenticated-bypass conditions are preserved as source facts. Restrictive values remain unresolved at this layer because candidate correlation does not model IPsec/security-context fulfillment.

## Evidence bounds

Every candidate preserves:

- `listener_event_id`;
- `rule_event_id`;
- source rule action/profile;
- compatible dimensions;
- unresolved dimensions.

The correlation does not invent a new source fact and does not mutate EventStore.

## CLI

Use:

```powershell
python .\tools\firewall_rule_candidates.py `
  --db .\.local\service-exposure-rules-live.sqlite3 `
  --port 5985 `
  --details
```

Without `--stream-id`, the latest EventStore stream is selected.

The tool is an inspector only. Its output is not an allow/block verdict.

## Explicit non-goals

v1 does not implement:

- Windows Filtering Platform precedence;
- effective allow/block disposition;
- rule weighting or winner selection;
- IPsec/authentication fulfillment;
- edge-traversal behavior evaluation;
- NAT/router reachability;
- active remote probing;
- service authentication tests;
- exploitability assessment.

## Design rule

```text
Compatibility is not disposition.
Disposition is not reachability.
Reachability is not exploitability.
```
