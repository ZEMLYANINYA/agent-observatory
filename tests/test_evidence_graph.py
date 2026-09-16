import tempfile
import unittest
from collections import Counter
from pathlib import Path

from agent_observatory.graph import (
    EvidenceGraphProjectionError,
    GraphEdgeType,
    GraphNodeType,
    project_events,
    project_stream,
)
from agent_observatory.storage import EventStore, EventType, ObservationEvent, StoredEvent


class EvidenceGraphProjectionTests(unittest.TestCase):
    @staticmethod
    def _event(
        event_id: int,
        event_type: EventType,
        payload: dict[str, object],
        *,
        stream_id: str = "stream-1",
        observed_at: float | None = None,
    ) -> StoredEvent:
        timestamp = float(event_id if observed_at is None else observed_at)
        return StoredEvent(
            event_id=event_id,
            event_type=event_type,
            event_version=1,
            observed_at=timestamp,
            recorded_at=timestamp + 100.0,
            source="graph-test",
            stream_id=stream_id,
            payload=payload,
        )

    @classmethod
    def _representative_events(cls) -> tuple[StoredEvent, ...]:
        root_ref = {"pid": 100, "started_at": 1000.0}
        child_ref = {"pid": 101, "started_at": 1001.0}
        return (
            cls._event(
                1,
                EventType.APPLICATION_DISCOVERY_OBSERVED,
                {
                    "application": "Gemini",
                    "outcome": "unique",
                    "candidate_count": 1,
                    "candidates": [
                        {
                            "pid": 100,
                            "ppid": 50,
                            "started_at": 1000.0,
                            "name": "Gemini.exe",
                            "executable_path": r"C:\Google\Gemini\Gemini.exe",
                        }
                    ],
                },
            ),
            cls._event(
                2,
                EventType.PROCESS_OBSERVED,
                {
                    "pid": 100,
                    "ppid": 50,
                    "started_at": 1000.0,
                    "name": "Gemini.exe",
                    "executable_path": r"C:\Google\Gemini\Gemini.exe",
                    "command_line_sha256": "root-command",
                },
            ),
            cls._event(
                3,
                EventType.PROCESS_OBSERVED,
                {
                    "pid": 101,
                    "ppid": 100,
                    "started_at": 1001.0,
                    "name": "Gemini.exe",
                    "executable_path": r"C:\Google\Gemini\Gemini.exe",
                    "command_line_sha256": "child-command",
                },
            ),
            cls._event(
                4,
                EventType.PROCESS_RELATIONSHIP_OBSERVED,
                {
                    "child": child_ref,
                    "reported_parent_pid": 100,
                    "parent": root_ref,
                    "state": "valid",
                    "basis": "current_snapshot",
                    "reason": None,
                },
            ),
            cls._event(
                5,
                EventType.FILE_IDENTITY_OBSERVED,
                {
                    "process": child_ref,
                    "path": r"C:\Google\Gemini\Gemini.exe",
                    "state": "observed",
                    "observation_time_basis": "test-anchor",
                    "volume_serial": 123,
                    "file_id": 456,
                },
            ),
            cls._event(
                6,
                EventType.TCP_CONNECTION_OBSERVED,
                {
                    "process": child_ref,
                    "state": "Bound",
                    "local_address": "0.0.0.0",
                    "local_port": 50000,
                    "remote_address": "0.0.0.0",
                    "remote_port": 0,
                    "attribution_basis": "stable_process_instance",
                },
            ),
            cls._event(
                7,
                EventType.TCP_CONNECTION_OBSERVED,
                {
                    "process": child_ref,
                    "state": "Established",
                    "local_address": "10.0.0.5",
                    "local_port": 50000,
                    "remote_address": "203.0.113.10",
                    "remote_port": 443,
                    "attribution_basis": "stable_process_instance",
                },
            ),
            cls._event(
                8,
                EventType.FILE_HASH_OBSERVED,
                {
                    "process": child_ref,
                    "path": r"C:\Google\Gemini\Gemini.exe",
                    "file_identity": {"volume_serial": 123, "file_id": 456},
                    "sha256": "abc",
                    "state": "hashed",
                },
            ),
            cls._event(
                9,
                EventType.OPERATOR_MARKER_OBSERVED,
                {"marker": "QUERY_SENT", "details": {}},
            ),
        )

    def test_representative_stream_projects_expected_nodes_and_edges(self) -> None:
        graph = project_events(self._representative_events())

        node_counts = Counter(node.node_type for node in graph.nodes)
        edge_counts = Counter(edge.edge_type for edge in graph.edges)

        self.assertEqual(graph.stream_id, "stream-1")
        self.assertEqual(node_counts[GraphNodeType.APPLICATION], 1)
        self.assertEqual(node_counts[GraphNodeType.PROCESS_INSTANCE], 2)
        self.assertEqual(node_counts[GraphNodeType.FILE_IDENTITY], 1)
        self.assertEqual(node_counts[GraphNodeType.REMOTE_ENDPOINT], 1)
        self.assertEqual(edge_counts[GraphEdgeType.DISCOVERED_AS], 1)
        self.assertEqual(edge_counts[GraphEdgeType.PARENT_OF], 1)
        self.assertEqual(edge_counts[GraphEdgeType.EXECUTED_FROM], 1)
        self.assertEqual(edge_counts[GraphEdgeType.OBSERVED_TCP_TO], 1)

        reasons = {note.reason for note in graph.projection_notes}
        self.assertIn("tcp_remote_endpoint_unavailable", reasons)
        self.assertIn("file_hash_not_projected_v1", reasons)
        self.assertIn("operator_marker_not_projected_v1", reasons)
        self.assertEqual(graph.source_event_ids, tuple(range(1, 10)))

    def test_edges_preserve_exact_source_event_provenance(self) -> None:
        graph = project_events(self._representative_events())
        event_by_edge_type = {
            edge.edge_type: edge.evidence[0].event_id
            for edge in graph.edges
        }

        self.assertEqual(event_by_edge_type[GraphEdgeType.DISCOVERED_AS], 1)
        self.assertEqual(event_by_edge_type[GraphEdgeType.PARENT_OF], 4)
        self.assertEqual(event_by_edge_type[GraphEdgeType.EXECUTED_FROM], 5)
        self.assertEqual(event_by_edge_type[GraphEdgeType.OBSERVED_TCP_TO], 7)

    def test_external_observed_parent_is_projected_without_process_event(self) -> None:
        event = self._event(
            1,
            EventType.PROCESS_RELATIONSHIP_OBSERVED,
            {
                "child": {"pid": 20, "started_at": 200.0},
                "reported_parent_pid": 10,
                "parent": {"pid": 10, "started_at": 100.0},
                "state": "valid",
                "basis": "parent_observed_before_only",
                "reason": None,
            },
        )

        graph = project_events((event,))

        self.assertEqual(
            Counter(node.node_type for node in graph.nodes)[GraphNodeType.PROCESS_INSTANCE],
            2,
        )
        self.assertEqual(len(graph.edges), 1)
        self.assertEqual(graph.edges[0].edge_type, GraphEdgeType.PARENT_OF)
        self.assertEqual(graph.edges[0].attributes["basis"], "parent_observed_before_only")

    def test_invalid_relationship_does_not_become_parent_edge(self) -> None:
        event = self._event(
            1,
            EventType.PROCESS_RELATIONSHIP_OBSERVED,
            {
                "child": {"pid": 20, "started_at": 200.0},
                "reported_parent_pid": 10,
                "parent": {"pid": 10, "started_at": 300.0},
                "state": "invalid",
                "basis": "current_snapshot",
                "reason": "parent_pid_reused",
            },
        )

        graph = project_events((event,))

        self.assertFalse(graph.edges)
        self.assertIn(
            "relationship_not_valid:invalid",
            {note.reason for note in graph.projection_notes},
        )

    def test_ambiguous_discovery_preserves_all_candidates(self) -> None:
        event = self._event(
            1,
            EventType.APPLICATION_DISCOVERY_OBSERVED,
            {
                "application": "Perplexity",
                "outcome": "ambiguous",
                "candidate_count": 2,
                "candidates": [
                    {
                        "pid": 10,
                        "ppid": 1,
                        "started_at": 100.0,
                        "name": "Perplexity.exe",
                        "executable_path": r"C:\A\Perplexity.exe",
                    },
                    {
                        "pid": 20,
                        "ppid": 1,
                        "started_at": 200.0,
                        "name": "Perplexity.exe",
                        "executable_path": r"C:\B\Perplexity.exe",
                    },
                ],
            },
        )

        graph = project_events((event,))

        discovered_edges = [
            edge
            for edge in graph.edges
            if edge.edge_type is GraphEdgeType.DISCOVERED_AS
        ]
        self.assertEqual(len(discovered_edges), 2)
        self.assertEqual(
            {edge.target_node_id for edge in discovered_edges},
            {"process:10@100.0", "process:20@200.0"},
        )

    def test_unavailable_file_identity_does_not_create_file_node(self) -> None:
        event = self._event(
            1,
            EventType.FILE_IDENTITY_OBSERVED,
            {
                "process": {"pid": 10, "started_at": 100.0},
                "path": r"C:\App\client.exe",
                "state": "unavailable",
                "volume_serial": None,
                "file_id": None,
                "observation_time_basis": "test",
            },
        )

        graph = project_events((event,))

        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(graph.nodes[0].node_type, GraphNodeType.PROCESS_INSTANCE)
        self.assertFalse(graph.edges)
        self.assertEqual(graph.projection_notes[0].reason, "file_identity_unavailable")

    def test_mixed_streams_are_rejected(self) -> None:
        first = self._event(
            1,
            EventType.PROCESS_OBSERVED,
            {"pid": 10, "started_at": 100.0},
            stream_id="a",
        )
        second = self._event(
            2,
            EventType.PROCESS_OBSERVED,
            {"pid": 20, "started_at": 200.0},
            stream_id="b",
        )

        with self.assertRaises(EvidenceGraphProjectionError):
            project_events((first, second))

    def test_projection_is_deterministic_for_reversed_input(self) -> None:
        events = self._representative_events()
        forward = project_events(events)
        reverse = project_events(tuple(reversed(events)))

        self.assertEqual(forward, reverse)

    def test_attribute_conflict_is_preserved_as_projection_note(self) -> None:
        first = self._event(
            1,
            EventType.PROCESS_OBSERVED,
            {
                "pid": 10,
                "started_at": 100.0,
                "name": "client.exe",
                "executable_path": r"C:\One\client.exe",
            },
        )
        second = self._event(
            2,
            EventType.PROCESS_OBSERVED,
            {
                "pid": 10,
                "started_at": 100.0,
                "name": "client.exe",
                "executable_path": r"C:\Two\client.exe",
            },
        )

        graph = project_events((first, second))

        self.assertIn(
            "node_attribute_conflict:process:10@100.0:executable_path",
            {note.reason for note in graph.projection_notes},
        )
        self.assertEqual(graph.nodes[0].attributes["executable_path"], r"C:\One\client.exe")

    def test_project_stream_reads_persisted_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append(
                ObservationEvent(
                    event_type=EventType.PROCESS_OBSERVED,
                    observed_at=10.0,
                    source="graph-test",
                    stream_id="persisted",
                    payload={
                        "pid": 10,
                        "started_at": 100.0,
                        "name": "client.exe",
                        "executable_path": r"C:\App\client.exe",
                    },
                )
            )
            graph = project_stream(store, "persisted")

        self.assertEqual(graph.stream_id, "persisted")
        self.assertEqual(len(graph.nodes), 1)
        self.assertEqual(graph.nodes[0].node_id, "process:10@100.0")

    def test_project_stream_rejects_missing_stream(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            with self.assertRaises(KeyError):
                project_stream(store, "missing")


if __name__ == "__main__":
    unittest.main()
