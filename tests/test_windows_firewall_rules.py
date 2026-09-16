import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_observatory.endpoint.windows_firewall_rules import (
    WindowsFirewallRuleInventory,
    collect_windows_firewall_rule_inventory,
    parse_windows_firewall_rule_inventory,
)
from agent_observatory.evidence import (
    append_windows_firewall_rule_inventory,
    windows_firewall_rule_event,
    windows_firewall_rule_event_batch,
)
from agent_observatory.storage import EventStore, EventType


def _payload() -> dict:
    return {
        "capture_started_at": "2026-09-16T22:00:00.0000000Z",
        "capture_finished_at": "2026-09-16T22:00:00.0500000Z",
        "rules": [
            {
                "name": "rule-z",
                "display_name": "WinRM HTTPS",
                "enabled": True,
                "direction": "Inbound",
                "action": "Allow",
                "profile": "Public",
                "edge_traversal_policy": "Block",
                "policy_store_source_type": "Local",
                "policy_store_source": "PersistentStore",
                "protocol": ["TCP"],
                "local_ports": ["5986"],
                "remote_ports": ["Any"],
                "local_addresses": ["Any"],
                "remote_addresses": ["LocalSubnet", "10.0.0.0/8"],
                "programs": ["System"],
                "packages": ["Any"],
                "services": ["WinRM"],
                "interface_types": ["Wireless", "Lan"],
                "interface_aliases": ["Any"],
            },
            {
                "name": "rule-a",
                "display_name": "SMB block sample",
                "enabled": False,
                "direction": "Inbound",
                "action": "Block",
                "profile": "Domain, Private, Public",
                "edge_traversal_policy": "Block",
                "policy_store_source_type": "Local",
                "policy_store_source": "PersistentStore",
                "protocol": ["TCP"],
                "local_ports": ["445"],
                "remote_ports": ["Any"],
                "local_addresses": ["Any"],
                "remote_addresses": ["Any"],
                "programs": ["Any"],
                "packages": ["Any"],
                "services": ["Any"],
                "interface_types": ["Any"],
                "interface_aliases": ["Any"],
            },
        ],
    }


class WindowsFirewallRuleInventoryTests(unittest.TestCase):
    def test_parse_inventory_preserves_rule_and_filter_facts(self) -> None:
        inventory = parse_windows_firewall_rule_inventory(json.dumps(_payload()))

        self.assertIsInstance(inventory, WindowsFirewallRuleInventory)
        self.assertEqual(tuple(rule.name for rule in inventory.rules), ("rule-a", "rule-z"))
        allow = inventory.rules[1]
        self.assertTrue(allow.enabled)
        self.assertEqual(allow.action, "Allow")
        self.assertEqual(allow.profile, "Public")
        self.assertEqual(allow.protocol, ("TCP",))
        self.assertEqual(allow.local_ports, ("5986",))
        self.assertEqual(allow.remote_addresses, ("LocalSubnet", "10.0.0.0/8"))
        self.assertEqual(allow.services, ("WinRM",))
        self.assertEqual(allow.interface_types, ("Wireless", "Lan"))
        self.assertGreater(inventory.capture_finished_at, inventory.capture_started_at)

    def test_collect_inventory_uses_powershell_source(self) -> None:
        raw = json.dumps(_payload())
        with patch(
            "agent_observatory.endpoint.windows_firewall_rules.run_powershell_text",
            return_value=raw,
        ) as runner:
            inventory = collect_windows_firewall_rule_inventory()

        runner.assert_called_once()
        self.assertEqual(len(inventory.rules), 2)

    def test_rule_event_is_descriptive_only(self) -> None:
        inventory = parse_windows_firewall_rule_inventory(json.dumps(_payload()))
        event = windows_firewall_rule_event(
            inventory.rules[1],
            observed_at=10.0,
            source="firewall-rule-test",
            stream_id="rules:1",
        )

        self.assertEqual(event.event_type, EventType.WINDOWS_FIREWALL_RULE_OBSERVED)
        self.assertEqual(event.payload["action"], "Allow")
        self.assertEqual(event.payload["local_ports"], ["5986"])
        self.assertEqual(event.payload["services"], ["WinRM"])
        for forbidden in (
            "matches_listener",
            "applies_to_listener",
            "effective_action",
            "allowed",
            "blocked",
            "reachable",
            "exposed",
        ):
            self.assertNotIn(forbidden, event.payload)

    def test_rule_batch_is_deterministic_and_uses_inventory_time_anchor(self) -> None:
        inventory = parse_windows_firewall_rule_inventory(json.dumps(_payload()))
        batch = windows_firewall_rule_event_batch(
            inventory,
            source="firewall-rule-test",
            stream_id="rules:2",
        )

        self.assertEqual(tuple(event.payload["name"] for event in batch), ("rule-a", "rule-z"))
        self.assertEqual(
            tuple(event.observed_at for event in batch),
            (inventory.capture_finished_at, inventory.capture_finished_at),
        )

    def test_rule_inventory_round_trips_atomically_through_event_store(self) -> None:
        inventory = parse_windows_firewall_rule_inventory(json.dumps(_payload()))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = append_windows_firewall_rule_inventory(
                store,
                inventory,
                source="firewall-rule-test",
                stream_id="rules:roundtrip",
            )
            loaded = store.read_events(stream_id="rules:roundtrip")

        self.assertEqual(tuple(event.event_id for event in stored), (1, 2))
        self.assertEqual(tuple(event.event_id for event in loaded), (1, 2))
        self.assertTrue(
            all(event.event_type is EventType.WINDOWS_FIREWALL_RULE_OBSERVED for event in loaded)
        )
        self.assertEqual(loaded[1].payload["remote_addresses"], ["LocalSubnet", "10.0.0.0/8"])

    def test_empty_inventory_is_valid_and_emits_empty_batch(self) -> None:
        payload = _payload()
        payload["rules"] = []
        inventory = parse_windows_firewall_rule_inventory(json.dumps(payload))

        self.assertEqual(inventory.rules, ())
        self.assertEqual(
            windows_firewall_rule_event_batch(
                inventory,
                source="firewall-rule-test",
                stream_id="rules:empty",
            ),
            (),
        )

    def test_enabled_must_remain_boolean(self) -> None:
        payload = _payload()
        payload["rules"][0]["enabled"] = "True"
        with self.assertRaises(TypeError):
            parse_windows_firewall_rule_inventory(json.dumps(payload))


if __name__ == "__main__":
    unittest.main()
