import tempfile
import unittest
from pathlib import Path

from agent_observatory.analysis.firewall_rule_candidates import (
    FirewallCandidateStatus,
    correlate_firewall_rule_candidates,
)
from agent_observatory.storage import EventStore, EventType, ObservationEvent


class FirewallRuleCandidateTests(unittest.TestCase):
    @staticmethod
    def _listener(*, port=8000, pid=10, path=r"C:\Apps\svc.exe", address="0.0.0.0"):
        return ObservationEvent(
            event_type=EventType.TCP_LISTENER_OBSERVED,
            observed_at=10.0,
            source="candidate-test",
            stream_id="service-exposure:test",
            payload={
                "owner_pid": pid,
                "local_address": address,
                "local_port": port,
                "bind_scope": "wildcard" if address in {"0.0.0.0", "::"} else "specific",
                "owner_identity_basis": "stable_process_instance",
                "attribution_state": "attributed",
                "process": {"pid": pid, "started_at": 5.0},
                "process_name": "svc.exe",
                "executable_path": path,
                "attribution_reason": None,
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _network_profile(category="Public", alias="Wi-Fi"):
        return ObservationEvent(
            event_type=EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
            observed_at=11.0,
            source="candidate-test",
            stream_id="service-exposure:test",
            payload={
                "name": "net",
                "interface_alias": alias,
                "interface_index": 10,
                "network_category": category,
                "ipv4_connectivity": "Internet",
                "ipv6_connectivity": "NoTraffic",
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _service(name="SvcName", pid=10):
        return ObservationEvent(
            event_type=EventType.WINDOWS_SERVICE_OBSERVED,
            observed_at=11.0,
            source="candidate-test",
            stream_id="service-exposure:test",
            payload={
                "service_name": name,
                "display_name": name,
                "state": "Running",
                "start_mode": "Auto",
                "service_type": "Own Process",
                "process_id": pid,
                "process": {"pid": pid, "started_at": 5.0},
                "process_name": "svc.exe",
                "executable_path": r"C:\Apps\svc.exe",
                "process_attribution_state": "attributed",
                "process_attribution_reason": None,
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _rule(
        *,
        name="rule-1",
        enabled=True,
        action="Allow",
        profile="Public",
        protocol=("TCP",),
        local_ports=("8000",),
        local_addresses=("Any",),
        remote_ports=("Any",),
        remote_addresses=("Any",),
        programs=("Any",),
        services=("Any",),
        interface_types=("Any",),
        interface_aliases=("Any",),
        packages=("Any",),
        owner=None,
        primary_status="OK",
        dynamic_targets=("Any",),
        authentication=("NotRequired",),
        encryption=("NotRequired",),
        override_block_rules=("False",),
        local_users=("Any",),
        remote_users=("Any",),
        remote_machines=("Any",),
        event_version=2,
    ):
        return ObservationEvent(
            event_type=EventType.WINDOWS_FIREWALL_RULE_OBSERVED,
            event_version=event_version,
            observed_at=12.0,
            source="candidate-test",
            stream_id="service-exposure:test",
            payload={
                "name": name,
                "display_name": name,
                "enabled": enabled,
                "direction": "Inbound",
                "action": action,
                "profile": profile,
                "edge_traversal_policy": "Block",
                "policy_store_source_type": "Local",
                "policy_store_source": "PersistentStore",
                "owner": owner,
                "primary_status": primary_status,
                "status": "OK",
                "loose_source_mapping": False,
                "local_only_mapping": False,
                "protocol": list(protocol),
                "local_ports": list(local_ports),
                "remote_ports": list(remote_ports),
                "icmp_types": ["Any"],
                "dynamic_targets": list(dynamic_targets),
                "local_addresses": list(local_addresses),
                "remote_addresses": list(remote_addresses),
                "programs": list(programs),
                "packages": list(packages),
                "services": list(services),
                "interface_types": list(interface_types),
                "interface_aliases": list(interface_aliases),
                "authentication": list(authentication),
                "encryption": list(encryption),
                "override_block_rules": list(override_block_rules),
                "local_users": list(local_users),
                "remote_users": list(remote_users),
                "remote_machines": list(remote_machines),
                "observation_basis": "test",
            },
        )

    def _correlate(self, *events):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many(events)
            result = correlate_firewall_rule_candidates(store, "service-exposure:test")
        return result

    def test_single_fully_compatible_rule_is_candidate_match(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._service(),
            self._rule(),
        )
        listener = result.listeners[0]

        self.assertEqual(listener.status, FirewallCandidateStatus.CANDIDATE_MATCH)
        self.assertEqual(len(listener.candidates), 1)
        self.assertEqual(listener.candidates[0].rule_name, "rule-1")
        self.assertEqual(listener.candidates[0].unknown_dimensions, ())
        self.assertEqual(result.active_network_categories, ("Public",))

    def test_disabled_rule_is_not_candidate(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._rule(enabled=False),
        )
        self.assertEqual(result.listeners[0].status, FirewallCandidateStatus.NO_CANDIDATE)
        self.assertEqual(result.listeners[0].candidates, ())

    def test_profile_mismatch_is_not_candidate(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(category="Public"),
            self._rule(profile="Private"),
        )
        self.assertEqual(result.listeners[0].status, FirewallCandidateStatus.NO_CANDIDATE)

    def test_multiple_compatible_rules_are_ambiguous(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._rule(name="allow-1"),
            self._rule(name="allow-2"),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertEqual(tuple(item.rule_name for item in listener.candidates), ("allow-1", "allow-2"))

    def test_restrictive_remote_scope_remains_ambiguous(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._rule(remote_addresses=("192.168.1.0/24",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertEqual(listener.candidates[0].unknown_dimensions, ("REMOTE_ADDRESS",))

    def test_matching_service_filter_uses_observed_service_name(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._service(name="RpcSs"),
            self._rule(services=("RpcSs",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.CANDIDATE_MATCH)
        self.assertIn("SERVICE", listener.candidates[0].compatible_dimensions)

    def test_program_path_mismatch_excludes_rule(self) -> None:
        result = self._correlate(
            self._listener(path=r"C:\Apps\svc.exe"),
            self._network_profile(),
            self._rule(programs=(r"C:\Other\other.exe",)),
        )
        self.assertEqual(result.listeners[0].status, FirewallCandidateStatus.NO_CANDIDATE)

    def test_special_port_token_is_unknown_not_false(self) -> None:
        result = self._correlate(
            self._listener(port=135),
            self._network_profile(),
            self._rule(local_ports=("RPC",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("LOCAL_PORT", listener.candidates[0].unknown_dimensions)

    def test_wildcard_listener_with_restrictive_local_address_stays_unknown(self) -> None:
        result = self._correlate(
            self._listener(address="0.0.0.0"),
            self._network_profile(),
            self._rule(local_addresses=("192.168.1.10",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("LOCAL_ADDRESS", listener.candidates[0].unknown_dimensions)

    def test_v1_rule_event_is_never_treated_as_full_condition_match(self) -> None:
        rule = self._rule(event_version=1)
        payload = dict(rule.payload)
        for field in (
            "owner",
            "primary_status",
            "status",
            "loose_source_mapping",
            "local_only_mapping",
            "icmp_types",
            "dynamic_targets",
            "authentication",
            "encryption",
            "override_block_rules",
            "local_users",
            "remote_users",
            "remote_machines",
        ):
            payload.pop(field, None)
        rule = ObservationEvent(
            event_type=rule.event_type,
            event_version=1,
            observed_at=rule.observed_at,
            source=rule.source,
            stream_id=rule.stream_id,
            payload=payload,
        )
        result = self._correlate(self._listener(), self._network_profile(), rule)
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("RULE_CONDITION_SURFACE", listener.candidates[0].unknown_dimensions)

    def test_restrictive_rule_owner_remains_unresolved_without_principal_evidence(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._rule(owner="S-1-5-21-owner"),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("OWNER", listener.candidates[0].unknown_dimensions)

    def test_restrictive_security_filter_remains_unresolved(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._rule(authentication=("Required",), remote_users=("S-1-5-21-user",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("AUTHENTICATION", listener.candidates[0].unknown_dimensions)
        self.assertIn("REMOTE_USER", listener.candidates[0].unknown_dimensions)

    def test_dynamic_target_is_unresolved_not_plain_port_match(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile(),
            self._rule(dynamic_targets=("ProximitySharing",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertIn("DYNAMIC_TARGET", listener.candidates[0].unknown_dimensions)


if __name__ == "__main__":
    unittest.main()
