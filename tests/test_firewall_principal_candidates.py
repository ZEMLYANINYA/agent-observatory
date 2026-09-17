import tempfile
import unittest
from pathlib import Path

from agent_observatory.analysis.firewall_rule_candidates import (
    FirewallCandidateStatus,
    correlate_firewall_rule_candidates,
)
from agent_observatory.storage import EventStore, EventType, ObservationEvent


class FirewallPrincipalCandidateTests(unittest.TestCase):
    @staticmethod
    def _listener(*, started_at=5.0):
        return ObservationEvent(
            event_type=EventType.TCP_LISTENER_OBSERVED,
            observed_at=10.0,
            source="principal-candidate-test",
            stream_id="service-exposure:test",
            payload={
                "owner_pid": 10,
                "local_address": "0.0.0.0",
                "local_port": 8000,
                "bind_scope": "wildcard",
                "owner_identity_basis": "stable_process_instance",
                "attribution_state": "attributed",
                "process": {"pid": 10, "started_at": started_at},
                "process_name": "svc.exe",
                "executable_path": r"C:\Apps\svc.exe",
                "attribution_reason": None,
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _network_profile():
        return ObservationEvent(
            event_type=EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
            observed_at=11.0,
            source="principal-candidate-test",
            stream_id="service-exposure:test",
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

    @staticmethod
    def _principal(*, sid=None, state="resolved", started_at=5.0, reason=None):
        return ObservationEvent(
            event_type=EventType.WINDOWS_PROCESS_PRINCIPAL_OBSERVED,
            observed_at=11.5,
            source="principal-candidate-test",
            stream_id="service-exposure:test",
            payload={
                "process_id": 10,
                "process": {"pid": 10, "started_at": started_at},
                "process_name": "svc.exe",
                "process_identity_basis": "stable_process_instance",
                "owner_sid": sid,
                "resolution_state": state,
                "resolution_reason": reason,
                "get_owner_sid_return_value": 0 if state == "resolved" else 2,
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _service(*, started_at=5.0):
        return ObservationEvent(
            event_type=EventType.WINDOWS_SERVICE_OBSERVED,
            observed_at=11.7,
            source="principal-candidate-test",
            stream_id="service-exposure:test",
            payload={
                "service_name": "SvcName",
                "display_name": "SvcName",
                "state": "Running",
                "start_mode": "Auto",
                "service_type": "Own Process",
                "process_id": 10,
                "process": {"pid": 10, "started_at": started_at},
                "process_name": "svc.exe",
                "executable_path": r"C:\Apps\svc.exe",
                "process_attribution_state": "attributed",
                "process_attribution_basis": "stable_process_instance",
                "process_attribution_reason": None,
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _rule(*, owner=None, services=("Any",)):
        return ObservationEvent(
            event_type=EventType.WINDOWS_FIREWALL_RULE_OBSERVED,
            event_version=2,
            observed_at=12.0,
            source="principal-candidate-test",
            stream_id="service-exposure:test",
            payload={
                "name": "rule-1",
                "display_name": "rule-1",
                "enabled": True,
                "direction": "Inbound",
                "action": "Allow",
                "profile": "Public",
                "edge_traversal_policy": "Block",
                "policy_store_source_type": "Local",
                "policy_store_source": "PersistentStore",
                "owner": owner,
                "primary_status": "OK",
                "status": "OK",
                "loose_source_mapping": False,
                "local_only_mapping": False,
                "protocol": ["TCP"],
                "local_ports": ["8000"],
                "remote_ports": ["Any"],
                "icmp_types": ["Any"],
                "dynamic_targets": ["Any"],
                "local_addresses": ["Any"],
                "remote_addresses": ["Any"],
                "programs": ["Any"],
                "packages": ["Any"],
                "services": list(services),
                "interface_types": ["Any"],
                "interface_aliases": ["Any"],
                "authentication": ["NotRequired"],
                "encryption": ["NotRequired"],
                "override_block_rules": ["False"],
                "local_users": ["Any"],
                "remote_users": ["Any"],
                "remote_machines": ["Any"],
                "observation_basis": "test",
            },
        )

    def _correlate(self, *events):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many(events)
            result = correlate_firewall_rule_candidates(
                store,
                "service-exposure:test",
            )
        return result.listeners[0]

    def test_matching_principal_sid_resolves_owner_dimension(self) -> None:
        listener = self._correlate(
            self._listener(),
            self._network_profile(),
            self._principal(sid="S-1-5-21-user"),
            self._rule(owner="S-1-5-21-user"),
        )

        self.assertEqual(listener.status, FirewallCandidateStatus.CANDIDATE_MATCH)
        self.assertEqual(len(listener.candidates), 1)
        self.assertIn("OWNER", listener.candidates[0].compatible_dimensions)
        self.assertNotIn("OWNER", listener.candidates[0].unknown_dimensions)

    def test_mismatching_principal_sid_excludes_owner_rule(self) -> None:
        listener = self._correlate(
            self._listener(),
            self._network_profile(),
            self._principal(sid="S-1-5-21-user"),
            self._rule(owner="S-1-5-18"),
        )

        self.assertEqual(listener.status, FirewallCandidateStatus.NO_CANDIDATE)
        self.assertEqual(listener.candidates, ())

    def test_unresolved_principal_keeps_owner_unknown(self) -> None:
        listener = self._correlate(
            self._listener(),
            self._network_profile(),
            self._principal(
                sid=None,
                state="unresolved",
                reason="access_denied",
            ),
            self._rule(owner="S-1-5-21-user"),
        )

        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertEqual(len(listener.candidates), 1)
        self.assertIn("OWNER", listener.candidates[0].unknown_dimensions)

    def test_principal_for_reused_pid_does_not_resolve_listener_owner(self) -> None:
        listener = self._correlate(
            self._listener(started_at=5.0),
            self._network_profile(),
            self._principal(sid="S-1-5-21-user", started_at=6.0),
            self._rule(owner="S-1-5-21-user"),
        )

        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("OWNER", listener.candidates[0].unknown_dimensions)

    def test_service_name_requires_same_process_instance_not_pid_only(self) -> None:
        listener = self._correlate(
            self._listener(started_at=5.0),
            self._network_profile(),
            self._service(started_at=6.0),
            self._rule(services=("SvcName",)),
        )

        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("SERVICE", listener.candidates[0].unknown_dimensions)

    def test_service_name_same_process_instance_resolves_filter(self) -> None:
        listener = self._correlate(
            self._listener(started_at=5.0),
            self._network_profile(),
            self._service(started_at=5.0),
            self._rule(services=("SvcName",)),
        )

        self.assertEqual(listener.status, FirewallCandidateStatus.CANDIDATE_MATCH)
        self.assertIn("SERVICE", listener.candidates[0].compatible_dimensions)


if __name__ == "__main__":
    unittest.main()
