from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent_observatory.analysis import (
    ProcessContinuityStatus,
    compare_graph_streams,
    compare_graphs,
)
from agent_observatory.graph import (
    EvidenceGraph,
    EvidenceRef,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    GraphProjectionNote,
)
from agent_observatory.storage import (
    EventStore,
    EventType,
    ObservationEvent,
)


class GraphDriftTests(unittest.TestCase):
    def _ref(
        self,
        event_id: int,
        stream_id: str,
        event_type: EventType = EventType.PROCESS_OBSERVED,
    ) -> EvidenceRef:
        return EvidenceRef(
            event_id=event_id,
            event_type=event_type,
            observed_at=1_700_000_000.0 + event_id,
            source="test",
            stream_id=stream_id,
        )

    def _node(
        self,
        node_id: str,
        node_type: GraphNodeType,
        attributes: dict[str, object],
        *,
        event_id: int,
        stream_id: str,
    ) -> GraphNode:
        return GraphNode(
            node_id=node_id,
            node_type=node_type,
            attributes=attributes,
            evidence=(self._ref(event_id, stream_id),),
        )

    def _edge(
        self,
        edge_id: str,
        edge_type: GraphEdgeType,
        source_node_id: str,
        target_node_id: str,
        attributes: dict[str, object],
        *,
        event_id: int,
        stream_id: str,
    ) -> GraphEdge:
        return GraphEdge(
            edge_id=edge_id,
            edge_type=edge_type,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            attributes=attributes,
            evidence=(self._ref(event_id, stream_id),),
        )

    def _graph(
        self,
        stream_id: str,
        *,
        nodes: tuple[GraphNode, ...] = (),
        edges: tuple[GraphEdge, ...] = (),
        notes: tuple[GraphProjectionNote, ...] = (),
    ) -> EvidenceGraph:
        return EvidenceGraph(
            stream_id=stream_id,
            nodes=nodes,
            edges=edges,
            projection_notes=notes,
        )

    def test_identical_structure_ignores_provenance_and_edge_ids(self) -> None:
        before_node = self._node(
            "process:10@100.0",
            GraphNodeType.PROCESS_INSTANCE,
            {"pid": 10, "started_at": 100.0, "name": "Gemini.exe"},
            event_id=1,
            stream_id="before",
        )
        after_node = self._node(
            "process:10@100.0",
            GraphNodeType.PROCESS_INSTANCE,
            {"pid": 10, "started_at": 100.0, "name": "Gemini.exe"},
            event_id=101,
            stream_id="after",
        )
        before_edge = self._edge(
            "event:2:OBSERVED_TCP_TO:0",
            GraphEdgeType.OBSERVED_TCP_TO,
            "process:10@100.0",
            "remote:tcp:[1.1.1.1]:443",
            {"state": "Established", "local_port": 50000},
            event_id=2,
            stream_id="before",
        )
        after_edge = self._edge(
            "event:102:OBSERVED_TCP_TO:0",
            GraphEdgeType.OBSERVED_TCP_TO,
            "process:10@100.0",
            "remote:tcp:[1.1.1.1]:443",
            {"state": "Established", "local_port": 50000},
            event_id=102,
            stream_id="after",
        )

        drift = compare_graphs(
            self._graph("before", nodes=(before_node,), edges=(before_edge,)),
            self._graph("after", nodes=(after_node,), edges=(after_edge,)),
        )

        self.assertFalse(drift.has_changes)
        self.assertEqual(drift.nodes[0].unchanged, ("process:10@100.0",))
        self.assertEqual(drift.edges[0].unchanged_count, 1)

    def test_nodes_are_reported_as_added_and_removed_by_identity(self) -> None:
        before = self._node(
            "remote:tcp:[1.1.1.1]:443",
            GraphNodeType.REMOTE_ENDPOINT,
            {"protocol": "tcp", "address": "1.1.1.1", "port": 443},
            event_id=1,
            stream_id="before",
        )
        after = self._node(
            "remote:tcp:[2.2.2.2]:443",
            GraphNodeType.REMOTE_ENDPOINT,
            {"protocol": "tcp", "address": "2.2.2.2", "port": 443},
            event_id=2,
            stream_id="after",
        )

        drift = compare_graphs(
            self._graph("before", nodes=(before,)),
            self._graph("after", nodes=(after,)),
        )

        item = drift.nodes[0]
        self.assertEqual(item.removed, ("remote:tcp:[1.1.1.1]:443",))
        self.assertEqual(item.added, ("remote:tcp:[2.2.2.2]:443",))
        self.assertTrue(drift.has_changes)

    def test_same_node_identity_with_changed_attributes_is_changed(self) -> None:
        before = self._node(
            "application:gemini",
            GraphNodeType.APPLICATION,
            {"name": "Gemini"},
            event_id=1,
            stream_id="before",
        )
        after = self._node(
            "application:gemini",
            GraphNodeType.APPLICATION,
            {"name": "GEMINI"},
            event_id=2,
            stream_id="after",
        )

        drift = compare_graphs(
            self._graph("before", nodes=(before,)),
            self._graph("after", nodes=(after,)),
        )

        change = drift.nodes[0].changed[0]
        self.assertEqual(change.node_id, "application:gemini")
        self.assertEqual(change.before_attributes["name"], "Gemini")
        self.assertEqual(change.after_attributes["name"], "GEMINI")

    def test_single_edge_pair_with_changed_attributes_is_changed(self) -> None:
        before = self._edge(
            "event:1:OBSERVED_TCP_TO:0",
            GraphEdgeType.OBSERVED_TCP_TO,
            "process:10@100.0",
            "remote:tcp:[1.1.1.1]:443",
            {"state": "Established", "local_port": 50000},
            event_id=1,
            stream_id="before",
        )
        after = self._edge(
            "event:2:OBSERVED_TCP_TO:0",
            GraphEdgeType.OBSERVED_TCP_TO,
            "process:10@100.0",
            "remote:tcp:[1.1.1.1]:443",
            {"state": "Established", "local_port": 50001},
            event_id=2,
            stream_id="after",
        )

        drift = compare_graphs(
            self._graph("before", edges=(before,)),
            self._graph("after", edges=(after,)),
        )

        item = drift.edges[0]
        self.assertEqual(len(item.changed), 1)
        self.assertEqual(item.changed[0].before_attributes["local_port"], 50000)
        self.assertEqual(item.changed[0].after_attributes["local_port"], 50001)
        self.assertFalse(item.added)
        self.assertFalse(item.removed)

    def test_edges_with_different_endpoints_are_added_and_removed(self) -> None:
        before = self._edge(
            "before",
            GraphEdgeType.OBSERVED_TCP_TO,
            "process:10@100.0",
            "remote:tcp:[1.1.1.1]:443",
            {"state": "Established"},
            event_id=1,
            stream_id="before",
        )
        after = self._edge(
            "after",
            GraphEdgeType.OBSERVED_TCP_TO,
            "process:10@100.0",
            "remote:tcp:[2.2.2.2]:443",
            {"state": "Established"},
            event_id=2,
            stream_id="after",
        )

        drift = compare_graphs(
            self._graph("before", edges=(before,)),
            self._graph("after", edges=(after,)),
        )

        item = drift.edges[0]
        self.assertEqual(len(item.removed), 1)
        self.assertEqual(len(item.added), 1)
        self.assertFalse(item.changed)

    def test_multiple_unmatched_edges_do_not_get_arbitrarily_paired(self) -> None:
        before = tuple(
            self._edge(
                f"before-{port}",
                GraphEdgeType.OBSERVED_TCP_TO,
                "process:10@100.0",
                "remote:tcp:[1.1.1.1]:443",
                {"state": "Established", "local_port": port},
                event_id=index,
                stream_id="before",
            )
            for index, port in enumerate((50000, 50001), start=1)
        )
        after = tuple(
            self._edge(
                f"after-{port}",
                GraphEdgeType.OBSERVED_TCP_TO,
                "process:10@100.0",
                "remote:tcp:[1.1.1.1]:443",
                {"state": "Established", "local_port": port},
                event_id=index,
                stream_id="after",
            )
            for index, port in enumerate((50002, 50003), start=10)
        )

        drift = compare_graphs(
            self._graph("before", edges=before),
            self._graph("after", edges=after),
        )

        item = drift.edges[0]
        self.assertFalse(item.changed)
        self.assertEqual(len(item.removed), 2)
        self.assertEqual(len(item.added), 2)
        self.assertEqual(len(item.ambiguous_keys), 1)

    def test_projection_note_drift_compares_reason_counts_not_event_ids(self) -> None:
        before = self._graph(
            "before",
            notes=(
                GraphProjectionNote(1, EventType.FILE_HASH_OBSERVED, "hash-note"),
                GraphProjectionNote(2, EventType.FILE_HASH_OBSERVED, "hash-note"),
            ),
        )
        after = self._graph(
            "after",
            notes=(
                GraphProjectionNote(101, EventType.FILE_HASH_OBSERVED, "hash-note"),
                GraphProjectionNote(102, EventType.FILE_HASH_OBSERVED, "hash-note"),
                GraphProjectionNote(103, EventType.FILE_HASH_OBSERVED, "hash-note"),
            ),
        )

        drift = compare_graphs(before, after)

        self.assertEqual(drift.projection_notes.unchanged_count, 2)
        self.assertEqual(len(drift.projection_notes.added), 1)
        self.assertEqual(drift.projection_notes.added[0].count, 1)
        self.assertFalse(drift.projection_notes.removed)

    def test_process_continuity_reports_same_instance_for_shared_pid_and_start(self) -> None:
        before = self._node(
            "process:10@100.0",
            GraphNodeType.PROCESS_INSTANCE,
            {"pid": 10, "started_at": 100.0},
            event_id=1,
            stream_id="before",
        )
        after = self._node(
            "process:10@100.0",
            GraphNodeType.PROCESS_INSTANCE,
            {"pid": 10, "started_at": 100.0},
            event_id=2,
            stream_id="after",
        )

        drift = compare_graphs(
            self._graph("before", nodes=(before,)),
            self._graph("after", nodes=(after,)),
        )

        continuity = drift.process_continuity[0]
        self.assertEqual(continuity.pid, 10)
        self.assertIs(continuity.status, ProcessContinuityStatus.SAME_INSTANCE)

    def test_process_continuity_detects_pid_reuse(self) -> None:
        before = self._node(
            "process:10@100.0",
            GraphNodeType.PROCESS_INSTANCE,
            {"pid": 10, "started_at": 100.0},
            event_id=1,
            stream_id="before",
        )
        after = self._node(
            "process:10@200.0",
            GraphNodeType.PROCESS_INSTANCE,
            {"pid": 10, "started_at": 200.0},
            event_id=2,
            stream_id="after",
        )

        drift = compare_graphs(
            self._graph("before", nodes=(before,)),
            self._graph("after", nodes=(after,)),
        )

        continuity = drift.process_continuity[0]
        self.assertIs(continuity.status, ProcessContinuityStatus.REPLACED_INSTANCE)
        self.assertEqual(continuity.before_instances, ("process:10@100.0",))
        self.assertEqual(continuity.after_instances, ("process:10@200.0",))

    def test_process_continuity_preserves_mixed_multi_instance_evidence(self) -> None:
        before_nodes = (
            self._node(
                "process:10@100.0",
                GraphNodeType.PROCESS_INSTANCE,
                {"pid": 10, "started_at": 100.0},
                event_id=1,
                stream_id="before",
            ),
            self._node(
                "process:10@150.0",
                GraphNodeType.PROCESS_INSTANCE,
                {"pid": 10, "started_at": 150.0},
                event_id=2,
                stream_id="before",
            ),
        )
        after_nodes = (
            self._node(
                "process:10@150.0",
                GraphNodeType.PROCESS_INSTANCE,
                {"pid": 10, "started_at": 150.0},
                event_id=3,
                stream_id="after",
            ),
            self._node(
                "process:10@200.0",
                GraphNodeType.PROCESS_INSTANCE,
                {"pid": 10, "started_at": 200.0},
                event_id=4,
                stream_id="after",
            ),
        )

        drift = compare_graphs(
            self._graph("before", nodes=before_nodes),
            self._graph("after", nodes=after_nodes),
        )

        self.assertIs(
            drift.process_continuity[0].status,
            ProcessContinuityStatus.MIXED,
        )

    def test_compare_graph_streams_projects_persisted_eventstore_streams(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            store.append_many(
                (
                    ObservationEvent(
                        event_type=EventType.PROCESS_OBSERVED,
                        observed_at=1_700_000_000.0,
                        source="test",
                        stream_id="before",
                        payload={
                            "pid": 10,
                            "ppid": 1,
                            "started_at": 100.0,
                            "name": "Gemini.exe",
                            "executable_path": r"C:\\Gemini.exe",
                            "command_line_sha256": "abc",
                        },
                    ),
                    ObservationEvent(
                        event_type=EventType.PROCESS_OBSERVED,
                        observed_at=1_700_000_100.0,
                        source="test",
                        stream_id="after",
                        payload={
                            "pid": 10,
                            "ppid": 1,
                            "started_at": 100.0,
                            "name": "Gemini.exe",
                            "executable_path": r"C:\\Gemini.exe",
                            "command_line_sha256": "abc",
                        },
                    ),
                )
            )

            drift = compare_graph_streams(store, "before", "after")

            self.assertFalse(drift.has_changes)
            self.assertEqual(drift.before_stream_id, "before")
            self.assertEqual(drift.after_stream_id, "after")
            self.assertIs(
                drift.process_continuity[0].status,
                ProcessContinuityStatus.SAME_INSTANCE,
            )


if __name__ == "__main__":
    unittest.main()
