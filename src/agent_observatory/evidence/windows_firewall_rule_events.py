from __future__ import annotations

from agent_observatory.endpoint.windows_firewall_rules import (
    WindowsFirewallRuleInventory,
    WindowsFirewallRuleSnapshot,
)
from agent_observatory.storage import EventStore, EventType, ObservationEvent, StoredEvent


FIREWALL_RULE_OBSERVATION_BASIS = (
    "windows_get_netfirewallrule_active_store_inbound_with_filters"
)


def windows_firewall_rule_event(
    rule: WindowsFirewallRuleSnapshot,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    """Adapt one inbound ActiveStore rule without inferring listener applicability."""

    return ObservationEvent(
        event_type=EventType.WINDOWS_FIREWALL_RULE_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "name": rule.name,
            "display_name": rule.display_name,
            "enabled": rule.enabled,
            "direction": rule.direction,
            "action": rule.action,
            "profile": rule.profile,
            "edge_traversal_policy": rule.edge_traversal_policy,
            "policy_store_source_type": rule.policy_store_source_type,
            "policy_store_source": rule.policy_store_source,
            "protocol": list(rule.protocol),
            "local_ports": list(rule.local_ports),
            "remote_ports": list(rule.remote_ports),
            "local_addresses": list(rule.local_addresses),
            "remote_addresses": list(rule.remote_addresses),
            "programs": list(rule.programs),
            "packages": list(rule.packages),
            "services": list(rule.services),
            "interface_types": list(rule.interface_types),
            "interface_aliases": list(rule.interface_aliases),
            "observation_basis": FIREWALL_RULE_OBSERVATION_BASIS,
        },
    )


def windows_firewall_rule_event_batch(
    inventory: WindowsFirewallRuleInventory,
    *,
    source: str,
    stream_id: str,
) -> tuple[ObservationEvent, ...]:
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must be a non-empty string")
    if not isinstance(stream_id, str) or not stream_id.strip():
        raise ValueError("stream_id must be a non-empty string")

    observed_at = inventory.capture_finished_at
    return tuple(
        windows_firewall_rule_event(
            rule,
            observed_at=observed_at,
            source=source,
            stream_id=stream_id,
        )
        for rule in inventory.rules
    )


def append_windows_firewall_rule_inventory(
    store: EventStore,
    inventory: WindowsFirewallRuleInventory,
    *,
    source: str,
    stream_id: str,
) -> tuple[StoredEvent, ...]:
    return store.append_many(
        windows_firewall_rule_event_batch(
            inventory,
            source=source,
            stream_id=stream_id,
        )
    )
