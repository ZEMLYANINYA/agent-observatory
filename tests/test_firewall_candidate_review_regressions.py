import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent_observatory.analysis.firewall_rule_candidates import (
    FirewallCandidateStatus,
    correlate_firewall_rule_candidates,
)
from agent_observatory.storage import EventStore, EventType, ObservationEvent
from tools import firewall_rule_candidates as candidate_tool


STREAM_ID = "service-exposure:review-regression"
SOURCE = "firewall-review-regression"


class FirewallCandidateReviewRegressionTests(unittest.TestCase):
    @staticmethod
    def _listener(port: int = 8000) -> ObservationEvent:
        return ObservationEvent(
            event_type=EventType.TCP_LISTENER_OBSERVED,
            observed_at=10.0,
            source=SOURCE,
            stream_id=STREAM_ID,
            payload={
                "owner_pid": 10,
                "local_address": "0.0.0.0",
                "local_port": port,
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

    @staticmethod
    def _network_profile(
        category: str | None,
        alias: str | None,
        index: int,
    ) -> ObservationEvent:
        return ObservationEvent(
            event_type=EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
            observed_at=11.0,
            source=SOURCE,
            stream_id=STREAM_ID,
            payload={
                "name": f"net-{index}",
                "interface_alias": alias,
                "interface_index": index,
                "network_category": category,
                "ipv4_connectivity": "Internet",
                "ipv6_connectivity": "NoTraffic",
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _rule(
        *,
        profile: str = "Public",
        protocol: tuple[str, ...] = ("TCP",),
        interface_aliases: tuple[str, ...] = ("Any",),
        port: int = 8000,
    ) -> ObservationEvent:
        return ObservationEvent(
            event_type=EventType.WINDOWS_FIREWALL_RULE_OBSERVED,
            event_version=2,
            observed_at=12.0,
            source=SOURCE,
            stream_id=STREAM_ID,
            payload={
                "name": "review-rule",
                "display_name": "Review Rule",
                "enabled": True,
                "direction": "Inbound",
                "action": "Allow",
                "profile": profile,
                "edge_traversal_policy": "Block",
                "policy_store_source_type": "Local",
                "policy_store_source": "PersistentStore",
                "owner": None,
                "primary_status": "OK",
                "status": "OK",
                "loose_source_mapping": False,
                "local_only_mapping": False,
                "protocol": list(protocol),
                "local_ports": [str(port)],
                "remote_ports": ["Any"],
                "icmp_types": ["Any"],
                "dynamic_targets": ["Any"],
                "local_addresses": ["Any"],
                "remote_addresses": ["Any"],
                "programs": ["Any"],
                "packages": ["Any"],
                "services": ["Any"],
                "interface_types": ["Any"],
                "interface_aliases": list(interface_aliases),
                "authentication": ["NotRequired"],
                "encryption": ["NotRequired"],
                "override_block_rules": ["False"],
                "local_users": ["Any"],
                "remote_users": ["Any"],
                "remote_machines": ["Any"],
                "observation_basis": "test",
            },
        )

    @staticmethod
    def _manifest(
        *,
        status: str,
        record_count: object,
        include_rule_report: bool = True,
        collectors_override: object | None = None,
    ) -> ObservationEvent:
        collectors: object
        if collectors_override is not None:
            collectors = collectors_override
        else:
            generated_collectors = []
            if include_rule_report:
                generated_collectors.append(
                    {
                        "collector": "windows_firewall_rules",
                        "status": status,
                        "record_count": record_count,
                        "observation_basis": "test" if status == "succeeded" else None,
                        "error_type": "RuntimeError" if status == "failed" else None,
                        "error_message": "fixture failure" if status == "failed" else None,
                    }
                )
            collectors = generated_collectors

        return ObservationEvent(
            event_type=EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
            observed_at=13.0,
            source=SOURCE,
            stream_id=STREAM_ID,
            payload={
                "capture_kind": "service_exposure",
                "partial": status == "failed",
                "collectors": collectors,
            },
        )

    def _correlate(self, *events: ObservationEvent):
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many(events)
            return correlate_firewall_rule_candidates(store, STREAM_ID)

    def test_failed_or_skipped_rule_inventory_is_ambiguous_not_negative(self) -> None:
        for status in ("failed", "skipped"):
            with self.subTest(status=status):
                result = self._correlate(
                    self._listener(),
                    self._network_profile("Public", "Wi-Fi", 10),
                    self._manifest(status=status, record_count=None),
                )
                listener = result.listeners[0]
                self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
                self.assertEqual(listener.candidates, ())
                self.assertTrue(
                    any("inventory" in item for item in listener.limitations)
                )

    def test_manifest_without_rule_collector_is_also_unresolved(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("Public", "Wi-Fi", 10),
            self._manifest(
                status="succeeded",
                record_count=0,
                include_rule_report=False,
            ),
        )
        self.assertEqual(
            result.listeners[0].status,
            FirewallCandidateStatus.AMBIGUOUS,
        )

    def test_malformed_manifest_collector_shapes_remain_unresolved(self) -> None:
        malformed_collectors = (
            {"collector": "windows_firewall_rules"},
            [
                {
                    "collector": "windows_firewall_rules",
                    "status": "succeeded",
                    "record_count": 0,
                },
                {
                    "collector": "windows_firewall_rules",
                    "status": "succeeded",
                    "record_count": 0,
                },
            ],
            [
                {
                    "collector": "windows_firewall_rules",
                    "status": "succeeded",
                    "record_count": True,
                }
            ],
        )
        for collectors in malformed_collectors:
            with self.subTest(collectors=collectors):
                result = self._correlate(
                    self._listener(),
                    self._network_profile("Public", "Wi-Fi", 10),
                    self._manifest(
                        status="succeeded",
                        record_count=0,
                        collectors_override=collectors,
                    ),
                )
                listener = result.listeners[0]
                self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
                self.assertEqual(listener.candidates, ())

    def test_multiple_manifests_remain_unresolved(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("Public", "Wi-Fi", 10),
            self._manifest(status="succeeded", record_count=0),
            self._manifest(status="succeeded", record_count=0),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
        self.assertEqual(listener.candidates, ())

    def test_successful_zero_rule_inventory_remains_no_candidate(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("Public", "Wi-Fi", 10),
            self._manifest(status="succeeded", record_count=0),
        )
        self.assertEqual(
            result.listeners[0].status,
            FirewallCandidateStatus.NO_CANDIDATE,
        )

    def test_manifest_rule_count_mismatch_is_unresolved(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("Public", "Wi-Fi", 10),
            self._rule(),
            self._manifest(status="succeeded", record_count=0),
        )
        self.assertEqual(
            result.listeners[0].status,
            FirewallCandidateStatus.AMBIGUOUS,
        )
        self.assertEqual(result.listeners[0].candidates, ())

    def test_profile_and_alias_must_match_same_network_profile(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("Private", "Ethernet", 5),
            self._network_profile("Public", "Wi-Fi", 10),
            self._rule(profile="Public", interface_aliases=("Ethernet",)),
        )
        self.assertEqual(
            result.listeners[0].status,
            FirewallCandidateStatus.NO_CANDIDATE,
        )

    def test_profile_and_alias_match_when_same_record_satisfies_both(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("Public", "Ethernet", 5),
            self._network_profile("Private", "Wi-Fi", 10),
            self._rule(profile="Public", interface_aliases=("Ethernet",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.CANDIDATE_MATCH)
        self.assertIn("PROFILE", listener.candidates[0].compatible_dimensions)
        self.assertIn("INTERFACE_ALIAS", listener.candidates[0].compatible_dimensions)

    def test_missing_category_or_alias_in_network_profile_stays_unknown(self) -> None:
        cases = (
            (None, "Ethernet", "Public", ("Any",), "PROFILE"),
            ("Public", None, "Any", ("Ethernet",), "INTERFACE_ALIAS"),
        )
        for category, alias, profile, aliases, expected_unknown in cases:
            with self.subTest(
                category=category,
                alias=alias,
                expected_unknown=expected_unknown,
            ):
                result = self._correlate(
                    self._listener(),
                    self._network_profile(category, alias, 10),
                    self._rule(profile=profile, interface_aliases=aliases),
                )
                listener = result.listeners[0]
                self.assertEqual(listener.status, FirewallCandidateStatus.AMBIGUOUS)
                self.assertEqual(len(listener.candidates), 1)
                self.assertIn(expected_unknown, listener.candidates[0].unknown_dimensions)

    def test_domain_authenticated_maps_to_domain_firewall_profile(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("DomainAuthenticated", "Ethernet", 5),
            self._rule(profile="Domain"),
        )
        self.assertEqual(
            result.listeners[0].status,
            FirewallCandidateStatus.CANDIDATE_MATCH,
        )

    def test_numeric_protocol_256_is_firewall_any(self) -> None:
        result = self._correlate(
            self._listener(),
            self._network_profile("Public", "Wi-Fi", 10),
            self._rule(protocol=("256",)),
        )
        listener = result.listeners[0]
        self.assertEqual(listener.status, FirewallCandidateStatus.CANDIDATE_MATCH)
        self.assertIn("PROTOCOL", listener.candidates[0].compatible_dimensions)

    def test_udp_protocol_is_known_incompatible_with_tcp_listener(self) -> None:
        for protocol in (("UDP",), ("17",)):
            with self.subTest(protocol=protocol):
                result = self._correlate(
                    self._listener(),
                    self._network_profile("Public", "Wi-Fi", 10),
                    self._rule(protocol=protocol),
                )
                self.assertEqual(
                    result.listeners[0].status,
                    FirewallCandidateStatus.NO_CANDIDATE,
                )
                self.assertEqual(result.listeners[0].candidates, ())

    def test_candidate_inspector_opens_event_store_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "events.sqlite3"
            store = EventStore(db)
            store.append_many(
                (
                    self._listener(),
                    self._network_profile("Public", "Wi-Fi", 10),
                    self._rule(),
                )
            )

            with patch.object(
                candidate_tool,
                "EventStore",
                wraps=EventStore,
            ) as event_store_class:
                code = candidate_tool.main(
                    ["--db", str(db), "--stream-id", STREAM_ID]
                )

        self.assertEqual(code, 0)
        event_store_class.assert_called_once_with(db, read_only=True)


if __name__ == "__main__":
    unittest.main()
