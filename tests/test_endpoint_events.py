import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.application_models import (
    ApplicationProfile,
    DiscoveredApplication,
)
from agent_observatory.endpoint.identity import (
    ExecutableHashState,
    ExecutableIdentity,
    FileHashObservation,
    FileIdentity,
    ProcessInstanceIdentity,
    hash_command_line,
)
from agent_observatory.endpoint.models import (
    ParentRelation,
    ProcessSnapshot,
    RelationBasis,
    RelationState,
)
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.evidence import (
    ApplicationDiscoveryOutcome,
    application_discovery_event,
    executable_evidence_events,
    file_hash_event,
    file_identity_event,
    operator_marker_event,
    process_observed_event,
    process_relationship_event,
    tcp_connection_event,
)
from agent_observatory.storage import EventStore, EventType


class EndpointEventAdapterTests(unittest.TestCase):
    @staticmethod
    def _process(
        *,
        pid: int = 100,
        ppid: int = 50,
        started_at: float = 1_700_000_000.0,
        name: str = "client.exe",
        command_line: str | None = "client.exe --token secret-value",
        executable_path: str | None = r"C:\Apps\client.exe",
    ) -> ProcessSnapshot:
        return ProcessSnapshot(
            pid=pid,
            ppid=ppid,
            name=name,
            started_at=started_at,
            command_line=command_line,
            executable_path=executable_path,
        )

    @staticmethod
    def _identity(
        *,
        file_identity: FileIdentity | None = FileIdentity(123, 456),
        hash_observed_at: float | None = 1_700_000_010.0,
        hash_state: ExecutableHashState = ExecutableHashState.HASHED,
        sha256: str | None = "abc123",
    ) -> ProcessInstanceIdentity:
        return ProcessInstanceIdentity(
            pid=100,
            ppid=50,
            started_at=1_700_000_000.0,
            name="client.exe",
            command_line_sha256="cmdhash",
            executable=ExecutableIdentity(
                path=r"C:\Apps\client.exe",
                file_identity=file_identity,
                hash_observation=FileHashObservation(
                    sha256=sha256,
                    state=hash_state,
                    observed_at=hash_observed_at,
                    hash_gap_ms=25.5,
                ),
            ),
        )

    def test_process_event_hashes_command_line_without_storing_raw_value(self) -> None:
        process = self._process()

        event = process_observed_event(
            process,
            observed_at=1_700_000_001.0,
            source="windows-process-sensor",
            stream_id="capture-001",
        )

        self.assertEqual(event.event_type, EventType.PROCESS_OBSERVED)
        self.assertEqual(event.payload["pid"], 100)
        self.assertEqual(event.payload["started_at"], process.started_at)
        self.assertEqual(
            event.payload["command_line_sha256"],
            hash_command_line(process.command_line),
        )
        self.assertNotIn("command_line", event.payload)
        self.assertNotIn("secret-value", repr(event.payload))

    def test_relationship_event_preserves_instance_timing_state_and_basis(self) -> None:
        relation = ParentRelation(
            child_pid=200,
            reported_parent_pid=100,
            state=RelationState.VALID,
            basis=RelationBasis.PARENT_OBSERVED_BEFORE_ONLY,
            reason="parent exited before second snapshot",
        )

        event = process_relationship_event(
            relation,
            child_started_at=1_700_000_020.0,
            parent_started_at=1_700_000_000.0,
            observed_at=1_700_000_030.0,
            source="windows-process-tree",
            stream_id="capture-001",
        )

        self.assertEqual(
            event.event_type,
            EventType.PROCESS_RELATIONSHIP_OBSERVED,
        )
        self.assertEqual(
            event.payload["child"],
            {"pid": 200, "started_at": 1_700_000_020.0},
        )
        self.assertEqual(
            event.payload["parent"],
            {"pid": 100, "started_at": 1_700_000_000.0},
        )
        self.assertEqual(event.payload["state"], "valid")
        self.assertEqual(event.payload["basis"], "parent_observed_before_only")

    def test_relationship_event_allows_unobserved_parent_instance(self) -> None:
        relation = ParentRelation(
            child_pid=200,
            reported_parent_pid=999,
            state=RelationState.UNKNOWN,
            basis=RelationBasis.REPORTED_PPID_ONLY,
            reason="parent was not jointly observed",
        )

        event = process_relationship_event(
            relation,
            child_started_at=1_700_000_020.0,
            parent_started_at=None,
            observed_at=1_700_000_030.0,
            source="windows-process-tree",
        )

        self.assertIsNone(event.payload["parent"])
        self.assertEqual(event.payload["reported_parent_pid"], 999)
        self.assertEqual(event.payload["state"], "unknown")
        self.assertEqual(event.payload["basis"], "reported_ppid_only")

    def test_tcp_event_binds_socket_to_process_instance(self) -> None:
        connection = TcpConnection(
            pid=100,
            state="Established",
            local_address="10.0.0.5",
            local_port=50000,
            remote_address="203.0.113.10",
            remote_port=443,
        )

        event = tcp_connection_event(
            connection,
            process_started_at=1_700_000_000.0,
            observed_at=1_700_000_005.0,
            source="windows-tcp-sensor",
            stream_id="capture-001",
        )

        self.assertEqual(event.event_type, EventType.TCP_CONNECTION_OBSERVED)
        self.assertEqual(
            event.payload["process"],
            {"pid": 100, "started_at": 1_700_000_000.0},
        )
        self.assertEqual(event.payload["state"], "Established")
        self.assertEqual(event.payload["attribution_basis"], "stable_process_instance")

    def test_file_identity_event_requires_caller_time_basis_semantics(self) -> None:
        event = file_identity_event(
            self._identity(),
            observed_at=1_700_000_009.0,
            source="windows-file-identity",
            stream_id="capture-001",
            observation_time_basis="identity_build_anchor",
        )

        self.assertEqual(event.event_type, EventType.FILE_IDENTITY_OBSERVED)
        self.assertEqual(event.observed_at, 1_700_000_009.0)
        self.assertEqual(event.payload["state"], "observed")
        self.assertEqual(event.payload["volume_serial"], 123)
        self.assertEqual(event.payload["file_id"], 456)
        self.assertEqual(
            event.payload["observation_time_basis"],
            "identity_build_anchor",
        )

    def test_file_identity_event_preserves_unavailable_state(self) -> None:
        event = file_identity_event(
            self._identity(file_identity=None),
            observed_at=1_700_000_009.0,
            source="windows-file-identity",
            observation_time_basis="identity_build_anchor",
        )

        self.assertEqual(event.payload["state"], "unavailable")
        self.assertIsNone(event.payload["volume_serial"])
        self.assertIsNone(event.payload["file_id"])

    def test_file_hash_event_prefers_hash_observation_time(self) -> None:
        event = file_hash_event(
            self._identity(hash_observed_at=1_700_000_010.0),
            fallback_observed_at=1_700_000_099.0,
            source="windows-file-hash",
            stream_id="capture-001",
        )

        self.assertEqual(event.event_type, EventType.FILE_HASH_OBSERVED)
        self.assertEqual(event.observed_at, 1_700_000_010.0)
        self.assertEqual(event.payload["observation_time_basis"], "hash_observation")
        self.assertEqual(event.payload["sha256"], "abc123")
        self.assertEqual(event.payload["state"], "hashed")
        self.assertEqual(event.payload["hash_gap_ms"], 25.5)

    def test_file_hash_event_marks_timestamp_fallback(self) -> None:
        event = file_hash_event(
            self._identity(
                hash_observed_at=None,
                hash_state=ExecutableHashState.NOT_REQUESTED,
                sha256=None,
            ),
            fallback_observed_at=1_700_000_099.0,
            source="windows-file-hash",
        )

        self.assertEqual(event.observed_at, 1_700_000_099.0)
        self.assertEqual(event.payload["observation_time_basis"], "caller_fallback")
        self.assertEqual(event.payload["state"], "not-requested")

    def test_executable_evidence_events_emit_identity_then_hash(self) -> None:
        events = executable_evidence_events(
            self._identity(),
            file_identity_observed_at=1_700_000_009.0,
            file_identity_time_basis="identity_build_anchor",
            hash_fallback_observed_at=1_700_000_099.0,
            source="identity-builder",
            stream_id="capture-001",
        )

        self.assertEqual(
            tuple(event.event_type for event in events),
            (
                EventType.FILE_IDENTITY_OBSERVED,
                EventType.FILE_HASH_OBSERVED,
            ),
        )

    def test_application_discovery_preserves_absent_unique_and_ambiguous(self) -> None:
        profile = ApplicationProfile(
            name="Perplexity",
            process_names=("Perplexity.exe",),
        )
        first = DiscoveredApplication(
            profile=profile,
            root_process=self._process(pid=100, name="Perplexity.exe"),
        )
        second = DiscoveredApplication(
            profile=profile,
            root_process=self._process(
                pid=200,
                name="Perplexity.exe",
                started_at=1_700_000_005.0,
            ),
        )

        cases = (
            ((), ApplicationDiscoveryOutcome.ABSENT, 0),
            ((first,), ApplicationDiscoveryOutcome.UNIQUE, 1),
            ((first, second), ApplicationDiscoveryOutcome.AMBIGUOUS, 2),
        )

        for candidates, outcome, count in cases:
            with self.subTest(outcome=outcome):
                event = application_discovery_event(
                    "Perplexity",
                    candidates,
                    observed_at=1_700_000_010.0,
                    source="application-discovery",
                    stream_id="capture-001",
                )
                self.assertEqual(
                    event.event_type,
                    EventType.APPLICATION_DISCOVERY_OBSERVED,
                )
                self.assertEqual(event.payload["outcome"], outcome.value)
                self.assertEqual(event.payload["candidate_count"], count)
                self.assertEqual(len(event.payload["candidates"]), count)

    def test_operator_marker_remains_source_attributed_observation(self) -> None:
        event = operator_marker_event(
            "RESPONSE_COMPLETE",
            observed_at=1_700_000_012.0,
            stream_id="transition-001",
            details={"basis": "visible_answer_complete"},
        )

        self.assertEqual(event.event_type, EventType.OPERATOR_MARKER_OBSERVED)
        self.assertEqual(event.source, "operator")
        self.assertEqual(event.payload["marker"], "RESPONSE_COMPLETE")
        self.assertEqual(
            event.payload["details"],
            {"basis": "visible_answer_complete"},
        )

    def test_adapter_events_round_trip_through_event_store(self) -> None:
        process = self._process()
        connection = TcpConnection(
            pid=100,
            state="Bound",
            local_address="0.0.0.0",
            local_port=50000,
            remote_address="0.0.0.0",
            remote_port=0,
        )
        events = (
            process_observed_event(
                process,
                observed_at=1_700_000_001.0,
                source="windows-process-sensor",
                stream_id="capture-001",
            ),
            tcp_connection_event(
                connection,
                process_started_at=process.started_at,
                observed_at=1_700_000_002.0,
                source="windows-tcp-sensor",
                stream_id="capture-001",
            ),
            *executable_evidence_events(
                self._identity(),
                file_identity_observed_at=1_700_000_009.0,
                file_identity_time_basis="identity_build_anchor",
                hash_fallback_observed_at=1_700_000_099.0,
                source="identity-builder",
                stream_id="capture-001",
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = store.append_many(events)
            readback = store.read_events(stream_id="capture-001")

        self.assertEqual(len(stored), 4)
        self.assertEqual(
            tuple(event.event_type for event in readback),
            (
                EventType.PROCESS_OBSERVED,
                EventType.TCP_CONNECTION_OBSERVED,
                EventType.FILE_IDENTITY_OBSERVED,
                EventType.FILE_HASH_OBSERVED,
            ),
        )


if __name__ == "__main__":
    unittest.main()
