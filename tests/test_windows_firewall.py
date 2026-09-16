import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_observatory.endpoint.windows_firewall import (
    WindowsFirewallContext,
    WindowsFirewallProfileSnapshot,
    WindowsNetworkProfileSnapshot,
    collect_windows_firewall_context,
    parse_windows_firewall_context,
)
from agent_observatory.evidence import (
    windows_firewall_profile_event,
    windows_network_profile_event,
)
from agent_observatory.storage import EventStore, EventType


def _payload() -> dict:
    return {
        "capture_started_at": "2026-09-16T21:00:00.0000000Z",
        "capture_finished_at": "2026-09-16T21:00:00.0500000Z",
        "firewall_profiles": [
            {
                "name": "Public",
                "enabled": True,
                "default_inbound_action": "Block",
                "default_outbound_action": "Allow",
                "allow_inbound_rules": "True",
                "allow_local_firewall_rules": "True",
            },
            {
                "name": "Private",
                "enabled": True,
                "default_inbound_action": "Block",
                "default_outbound_action": "Allow",
                "allow_inbound_rules": "True",
                "allow_local_firewall_rules": "True",
            },
            {
                "name": "Domain",
                "enabled": True,
                "default_inbound_action": "Block",
                "default_outbound_action": "Allow",
                "allow_inbound_rules": "NotConfigured",
                "allow_local_firewall_rules": "NotConfigured",
            },
        ],
        "network_profiles": [
            {
                "name": "Home Wi-Fi",
                "interface_alias": "Wi-Fi",
                "interface_index": 17,
                "network_category": "Private",
                "ipv4_connectivity": "Internet",
                "ipv6_connectivity": "NoTraffic",
            },
            {
                "name": "Unidentified network",
                "interface_alias": "vEthernet (WSL)",
                "interface_index": 42,
                "network_category": "Public",
                "ipv4_connectivity": "LocalNetwork",
                "ipv6_connectivity": "NoTraffic",
            },
        ],
    }


class WindowsFirewallContextTests(unittest.TestCase):
    def test_parse_context_preserves_profiles_and_interface_categories(self) -> None:
        context = parse_windows_firewall_context(json.dumps(_payload()))

        self.assertIsInstance(context, WindowsFirewallContext)
        self.assertEqual(
            tuple(profile.name for profile in context.firewall_profiles),
            ("Domain", "Private", "Public"),
        )
        self.assertEqual(
            tuple(
                (profile.interface_alias, profile.network_category)
                for profile in context.network_profiles
            ),
            (("Wi-Fi", "Private"), ("vEthernet (WSL)", "Public")),
        )
        self.assertGreater(context.capture_finished_at, context.capture_started_at)

    def test_parse_context_preserves_active_store_policy_values_without_verdict(self) -> None:
        context = parse_windows_firewall_context(json.dumps(_payload()))
        domain = context.firewall_profiles[0]

        self.assertTrue(domain.enabled)
        self.assertEqual(domain.default_inbound_action, "Block")
        self.assertEqual(domain.default_outbound_action, "Allow")
        self.assertEqual(domain.allow_inbound_rules, "NotConfigured")
        self.assertEqual(domain.allow_local_firewall_rules, "NotConfigured")
        self.assertFalse(hasattr(domain, "reachable"))
        self.assertFalse(hasattr(domain, "exposed"))

    def test_collect_context_uses_powershell_inventory(self) -> None:
        raw = json.dumps(_payload())
        with patch(
            "agent_observatory.endpoint.windows_firewall.run_powershell_text",
            return_value=raw,
        ) as runner:
            context = collect_windows_firewall_context()

        runner.assert_called_once()
        self.assertEqual(len(context.firewall_profiles), 3)
        self.assertEqual(len(context.network_profiles), 2)

    def test_firewall_and_network_events_are_descriptive_only(self) -> None:
        firewall_event = windows_firewall_profile_event(
            WindowsFirewallProfileSnapshot(
                name="Private",
                enabled=True,
                default_inbound_action="Block",
                default_outbound_action="Allow",
                allow_inbound_rules="True",
                allow_local_firewall_rules="True",
            ),
            observed_at=10.0,
            source="firewall-test",
            stream_id="firewall:1",
        )
        network_event = windows_network_profile_event(
            WindowsNetworkProfileSnapshot(
                name="Home Wi-Fi",
                interface_alias="Wi-Fi",
                interface_index=17,
                network_category="Private",
                ipv4_connectivity="Internet",
                ipv6_connectivity="NoTraffic",
            ),
            observed_at=10.0,
            source="firewall-test",
            stream_id="firewall:1",
        )

        self.assertEqual(
            firewall_event.event_type,
            EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED,
        )
        self.assertEqual(
            network_event.event_type,
            EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
        )
        self.assertEqual(firewall_event.payload["default_inbound_action"], "Block")
        self.assertEqual(network_event.payload["network_category"], "Private")
        for event in (firewall_event, network_event):
            self.assertNotIn("reachable", event.payload)
            self.assertNotIn("allowed", event.payload)
            self.assertNotIn("exposed", event.payload)

    def test_firewall_context_events_round_trip_through_event_store(self) -> None:
        context = parse_windows_firewall_context(json.dumps(_payload()))
        events = tuple(
            windows_firewall_profile_event(
                profile,
                observed_at=context.capture_finished_at,
                source="firewall-test",
                stream_id="firewall:roundtrip",
            )
            for profile in context.firewall_profiles
        ) + tuple(
            windows_network_profile_event(
                profile,
                observed_at=context.capture_finished_at,
                source="firewall-test",
                stream_id="firewall:roundtrip",
            )
            for profile in context.network_profiles
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = store.append_many(events)
            loaded = store.read_events(stream_id="firewall:roundtrip")

        self.assertEqual(len(stored), 5)
        self.assertEqual(len(loaded), 5)
        self.assertEqual(
            tuple(event.event_type for event in loaded),
            (
                EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED,
                EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED,
                EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED,
                EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
                EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
            ),
        )


if __name__ == "__main__":
    unittest.main()
