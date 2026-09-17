import tempfile
import unittest
from pathlib import Path

from agent_observatory.analysis import (
    FirewallCandidateStatus,
    correlate_firewall_rule_candidates,
)
from agent_observatory.storage import EventStore, EventType, ObservationEvent


class FirewallCandidatePublicApiTests(unittest.TestCase):
    def test_v1_rule_remains_readable_and_condition_surface_unknown(self) -> None:
        stream_id = "service-exposure:v1-compat"
        listener = ObservationEvent(
            event_type=EventType.TCP_LISTENER_OBSERVED,
            observed_at=10.0,
            source="compat-test",
            stream_id=stream_id,
            payload={
                "owner_pid": 10,
                "local_address": "0.0.0.0",
                "local_port": 8000,
                "bind_scope": "wildcard",
                "owner_identity_basis": "stable_process_instance",
                "attribution_state": "attributed",
                "process": {"pid": 10, "started_at": 5.0},
                "process_name": "svc.exe",
                "executable_path": r"C:\Apps\svc.exe",
                "attribution_reason": None,
                "observation_basis": "test",
            },
        )
        principal = ObservationEvent(
            event_type=EventType.WINDOWS_PROCESS_PRINCIPAL_OBSERVED,
            observed_at=10.5,
            source="compat-test",
            stream_id=stream_id,
            payload={
                "process_id": 10,
                "process": {"pid": 10, "started_at": 5.0},
                "process_name": "svc.exe",
                "process_identity_basis": "stable_process_instance",
                "owner_sid": "S-1-5-21-user",
                "resolution_state": "resolved",
                "resolution_reason": None,
                "get_owner_sid_return_value": 0,
                "observation_basis": "test",
            },
        )
        network = ObservationEvent(
            event_type=EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
            observed_at=11.0,
            source="compat-test",
            stream_id=stream_id,
            payload={
                "name": "net",
                "interface_alias": "Wi-Fi",
                "interface_index": 10,
                "network_category": "Public",
                "ipv4_connectivity": "Internet",
                "ipv6_connectivity": "NoTraffic",
                "observation_basis": "test",
            },
        )
        rule = ObservationEvent(
            event_type=EventType.WINDOWS_FIREWALL_RULE_OBSERVED,
            event_version=1,
            observed_at=12.0,
            source="compat-test",
            stream_id=stream_id,
            payload={
                "name": "legacy-rule",
                "display_name": "legacy-rule",
                "enabled": True,
                "direction": "Inbound",
                "action": "Allow",
                "profile": "Public",
                "edge_traversal_policy": "Block",
                "policy_store_source_type": "Local",
                "policy_store_source": "PersistentStore",
                "protocol": ["TCP"],
                "local_ports": ["8000"],
                "remote_ports": ["Any"],
                "local_addresses": ["Any"],
                "remote_addresses": ["Any"],
                "programs": ["Any"],
                "packages": ["Any"],
                "services": ["Any"],
                "interface_types": ["Any"],
                "interface_aliases": ["Any"],
                "observation_basis": "legacy-test",
            },
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many((listener, principal, network, rule))
            result = correlate_firewall_rule_candidates(store, stream_id)

        correlated = result.listeners[0]
        self.assertEqual(correlated.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertEqual(len(correlated.candidates), 1)
        self.assertIn(
            "RULE_CONDITION_SURFACE",
            correlated.candidates[0].unknown_dimensions,
        )


if __name__ == "__main__":
    unittest.main()
