from __future__ import annotations

from agent_observatory.endpoint.windows_firewall import (
    WindowsFirewallProfileSnapshot,
    WindowsNetworkProfileSnapshot,
)
from agent_observatory.storage import EventType, ObservationEvent


FIREWALL_PROFILE_OBSERVATION_BASIS = "windows_get_netfirewallprofile_active_store"
NETWORK_PROFILE_OBSERVATION_BASIS = "windows_get_netconnectionprofile"


def windows_firewall_profile_event(
    profile: WindowsFirewallProfileSnapshot,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    return ObservationEvent(
        event_type=EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "profile_name": profile.name,
            "enabled": profile.enabled,
            "default_inbound_action": profile.default_inbound_action,
            "default_outbound_action": profile.default_outbound_action,
            "allow_inbound_rules": profile.allow_inbound_rules,
            "allow_local_firewall_rules": profile.allow_local_firewall_rules,
            "observation_basis": FIREWALL_PROFILE_OBSERVATION_BASIS,
        },
    )


def windows_network_profile_event(
    profile: WindowsNetworkProfileSnapshot,
    *,
    observed_at: float,
    source: str,
    stream_id: str | None = None,
) -> ObservationEvent:
    return ObservationEvent(
        event_type=EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
        observed_at=observed_at,
        source=source,
        stream_id=stream_id,
        payload={
            "name": profile.name,
            "interface_alias": profile.interface_alias,
            "interface_index": profile.interface_index,
            "network_category": profile.network_category,
            "ipv4_connectivity": profile.ipv4_connectivity,
            "ipv6_connectivity": profile.ipv6_connectivity,
            "observation_basis": NETWORK_PROFILE_OBSERVATION_BASIS,
        },
    )
