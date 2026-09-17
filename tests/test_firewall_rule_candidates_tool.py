import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from agent_observatory.storage import EventStore, EventType, ObservationEvent
from tools import firewall_rule_candidates as tool


class FirewallRuleCandidateToolTests(unittest.TestCase):
    @staticmethod
    def _events(stream_id: str, port: int = 8000):
        return (
            ObservationEvent(
                event_type=EventType.TCP_LISTENER_OBSERVED,
                observed_at=1.0,
                source="tool-test",
                stream_id=stream_id,
                payload={
                    "owner_pid": 10,
                    "local_address": "0.0.0.0",
                    "local_port": port,
                    "bind_scope": "wildcard",
                    "owner_identity_basis": "stable_process_instance",
                    "attribution_state": "attributed",
                    "process": {"pid": 10, "started_at": 1.0},
                    "process_name": "svc.exe",
                    "executable_path": r"C:\Apps\svc.exe",
                    "attribution_reason": None,
                    "observation_basis": "test",
                },
            ),
            ObservationEvent(
                event_type=EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
                observed_at=1.0,
                source="tool-test",
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
            ),
            ObservationEvent(
                event_type=EventType.WINDOWS_FIREWALL_RULE_OBSERVED,
                event_version=2,
                observed_at=1.0,
                source="tool-test",
                stream_id=stream_id,
                payload={
                    "name": "allow-port",
                    "display_name": "Allow Port",
                    "enabled": True,
                    "direction": "Inbound",
                    "action": "Allow",
                    "profile": "Public",
                    "edge_traversal_policy": "Block",
                    "policy_store_source_type": "Local",
                    "policy_store_source": "PersistentStore",
                    "owner": None,
                    "primary_status": "OK",
                    "status": "OK",
                    "loose_source_mapping": False,
                    "local_only_mapping": False,
                    "protocol": ["TCP"],
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
                    "interface_aliases": ["Any"],
                    "authentication": ["NotRequired"],
                    "encryption": ["NotRequired"],
                    "override_block_rules": ["False"],
                    "local_users": ["Any"],
                    "remote_users": ["Any"],
                    "remote_machines": ["Any"],
                    "observation_basis": "test",
                },
            ),
        )

    def test_latest_stream_is_used_when_stream_id_omitted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "events.sqlite3"
            store = EventStore(db)
            store.append_many(self._events("service-exposure:first", 7000))
            store.append_many(self._events("service-exposure:latest", 8000))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = tool.main(["--db", str(db)])

        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("stream_id: service-exposure:latest", output)
        self.assertIn("0.0.0.0:8000", output)
        self.assertIn("CANDIDATE_MATCH", output)

    def test_port_filter_and_details_print_candidate_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "events.sqlite3"
            store = EventStore(db)
            store.append_many(self._events("service-exposure:test", 5985))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = tool.main(
                    [
                        "--db",
                        str(db),
                        "--stream-id",
                        "service-exposure:test",
                        "--port",
                        "5985",
                        "--details",
                    ]
                )

        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("listeners_selected: 1", output)
        self.assertIn("0.0.0.0:5985", output)
        self.assertIn("name='allow-port'", output)
        self.assertIn("action=Allow", output)
        self.assertIn("effective firewall verdicts", output)

    def test_missing_database_is_rejected_without_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db = Path(temp_dir) / "missing.sqlite3"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = tool.main(["--db", str(db)])

            self.assertFalse(db.exists())

        self.assertEqual(code, 1)
        self.assertIn("does not exist", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
