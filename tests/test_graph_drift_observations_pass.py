import unittest

from agent_observatory.analysis import (
    AnalysisContext,
    run_analysis_passes,
)
from agent_observatory.analysis.graph_drift import compare_graphs
from agent_observatory.analysis.passes import (
    GRAPH_DRIFT_OBSERVATIONS_PASS_ID,
    GRAPH_DRIFT_OBSERVATIONS_VERSION,
    GraphDriftObservationsPass,
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
from agent_observatory.storage import EventType


class GraphDriftObservationsPassTests(unittest.TestCase):
    @staticmethod
    def _ref(
        event_id: int,
        stream_id: str,
        event_type: EventType = EventType.PROCESS_OBSERVED,
    ) -> EvidenceRef:
        return EvidenceRef(
            event_id=event_id,
            event_type=event_type,
            observed_at=float(event_id),
            source="graph-drift-observations-test",
            stream_id=stream_id,
        )

    def _process_node(
        self,
        stream_id: str,
        event_id: int,
        pid: int,
        started_at: float,
        *,
        name: str = "app.exe",
    ) -> GraphNode:
        return GraphNode(
            node_id=f"process:{pid}@{started_at}",
            node_type=GraphNodeType.PROCESS_INSTANCE,
            attributes={"pid": pid, "started_at": started_at, "name": name},
            evidence=(self._ref(event_id, stream_id),),
        )

    def _remote_node(
        self,
        stream_id: str,
        event_id: int,
        address: str,
        port: int,
    ) -> GraphNode:
        return GraphNode(
            node_id=f"remote:tcp:[{address}]:{port}",
            node_type=GraphNodeType.REMOTE_ENDPOINT,
            attributes={"protocol": "tcp", "address": address, "port": port},
            evidence=(
                self._ref(
                    event_id,
                    stream_id,
                    EventType.TCP_CONNECTION_OBSERVED,
                ),
            ),
        )

    def _edge(
        self,
        stream_id: str,
        event_id: int,
        edge_type: GraphEdgeType,
        source_node_id: str,
        target_node_id: str,
        attributes: dict[str, object],
    ) -> GraphEdge:
        event_type = {
            GraphEdgeType.PARENT_OF: EventType.PROCESS_RELATIONSHIP_OBSERVED,
            GraphEdgeType.OBSERVED_TCP_TO: EventType.TCP_CONNECTION_OBSERVED,
            GraphEdgeType.DISCOVERED_AS: EventType.APPLICATION_DISCOVERY_OBSERVED,
            GraphEdgeType.EXECUTED_FROM: EventType.FILE_IDENTITY_OBSERVED,
        }[edge_type]
        return GraphEdge(
            edge_id=f"event:{event_id}:{edge_type.value}:0",
            edge_type=edge_type,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            attributes=attributes,
            evidence=(self._ref(event_id, stream_id, event_type),),
        )

    @staticmethod
    def _graph(
        stream_id: str,
        *,
        nodes=(),
        edges=(),
        notes=(),
    ) -> EvidenceGraph:
        return EvidenceGraph(
            stream_id=stream_id,
            nodes=tuple(nodes),
            edges=tuple(edges),
            projection_notes=tuple(notes),
        )

    @staticmethod
    def _context(before: EvidenceGraph, after: EvidenceGraph) -> AnalysisContext:
        return AnalysisContext(
            before_graph=before,
            after_graph=after,
            graph_drift=compare_graphs(before, after),
        )

    @staticmethod
    def _reason_codes(result) -> set[str]:
        return {finding.reason_code.value for finding in result.findings}

    def _run(self, before: EvidenceGraph, after: EvidenceGraph):
        context = self._context(before, after)
        return run_analysis_passes(context, (GraphDriftObservationsPass(),))

    def test_metadata_is_stable_and_versioned(self) -> None:
        analysis_pass = GraphDriftObservationsPass()
        self.assertEqual(analysis_pass.metadata.pass_id, GRAPH_DRIFT_OBSERVATIONS_PASS_ID)
        self.assertEqual(analysis_pass.metadata.version, GRAPH_DRIFT_OBSERVATIONS_VERSION)
        self.assertEqual(str(analysis_pass.metadata.version), "1.0.0")

    def test_identical_structure_emits_no_findings(self) -> None:
        before = self._graph(
            "before",
            nodes=(self._process_node("before", 1, 100, 1000.0),),
        )
        after = self._graph(
            "after",
            nodes=(self._process_node("after", 10, 100, 1000.0),),
        )

        result = self._run(before, after)

        self.assertEqual(result.finding_count, 0)
        self.assertEqual(result.pass_results[0].findings, ())

    def test_remote_endpoint_appearance_is_descriptive_and_evidence_bounded(self) -> None:
        process_before = self._process_node("before", 1, 100, 1000.0)
        process_after = self._process_node("after", 10, 100, 1000.0)
        remote = self._remote_node("after", 11, "203.0.113.10", 443)
        before = self._graph("before", nodes=(process_before,))
        after = self._graph("after", nodes=(process_after, remote))

        result = self._run(before, after)
        finding = next(
            item
            for item in result.findings
            if item.reason_code.value == "REMOTE_ENDPOINT_APPEARED"
        )

        self.assertEqual(finding.attributes["node_id"], remote.node_id)
        self.assertEqual(finding.evidence[0].stream_id, "after")
        self.assertEqual(finding.evidence[0].event_ids, (11,))
        self.assertTrue(any("service identity" in item for item in finding.limitations))
        self.assertNotIn("suspicious", finding.summary.lower())

    def test_process_pid_reuse_emits_replacement_and_node_delta_findings(self) -> None:
        before = self._graph(
            "before",
            nodes=(self._process_node("before", 1, 100, 1000.0),),
        )
        after = self._graph(
            "after",
            nodes=(self._process_node("after", 10, 100, 2000.0),),
        )

        result = self._run(before, after)
        reasons = self._reason_codes(result)

        self.assertIn("PROCESS_INSTANCE_APPEARED", reasons)
        self.assertIn("PROCESS_INSTANCE_DISAPPEARED", reasons)
        self.assertIn("PROCESS_IDENTITY_REPLACED", reasons)
        replacement = next(
            item
            for item in result.findings
            if item.reason_code.value == "PROCESS_IDENTITY_REPLACED"
        )
        self.assertEqual(replacement.attributes["pid"], 100)
        self.assertEqual(
            {ref.stream_id for ref in replacement.evidence},
            {"before", "after"},
        )

    def test_parent_relation_appearance_preserves_edge_provenance(self) -> None:
        parent_before = self._process_node("before", 1, 50, 900.0)
        child_before = self._process_node("before", 2, 100, 1000.0)
        parent_after = self._process_node("after", 10, 50, 900.0)
        child_after = self._process_node("after", 11, 100, 1000.0)
        edge = self._edge(
            "after",
            12,
            GraphEdgeType.PARENT_OF,
            parent_after.node_id,
            child_after.node_id,
            {"state": "valid", "basis": "current_snapshot"},
        )
        before = self._graph("before", nodes=(parent_before, child_before))
        after = self._graph(
            "after",
            nodes=(parent_after, child_after),
            edges=(edge,),
        )

        result = self._run(before, after)
        finding = next(
            item
            for item in result.findings
            if item.reason_code.value == "PARENT_RELATION_APPEARED"
        )

        self.assertEqual(finding.attributes["delta_count"], 1)
        self.assertEqual(finding.evidence[0].reference_id, edge.edge_id)
        self.assertEqual(finding.evidence[0].event_ids, (12,))

    def test_edge_attribute_change_keeps_both_sides_of_evidence(self) -> None:
        parent_before = self._process_node("before", 1, 50, 900.0)
        child_before = self._process_node("before", 2, 100, 1000.0)
        parent_after = self._process_node("after", 10, 50, 900.0)
        child_after = self._process_node("after", 11, 100, 1000.0)
        before_edge = self._edge(
            "before",
            3,
            GraphEdgeType.PARENT_OF,
            parent_before.node_id,
            child_before.node_id,
            {"state": "valid", "basis": "parent_observed_before_only"},
        )
        after_edge = self._edge(
            "after",
            12,
            GraphEdgeType.PARENT_OF,
            parent_after.node_id,
            child_after.node_id,
            {"state": "valid", "basis": "current_snapshot"},
        )
        before = self._graph(
            "before",
            nodes=(parent_before, child_before),
            edges=(before_edge,),
        )
        after = self._graph(
            "after",
            nodes=(parent_after, child_after),
            edges=(after_edge,),
        )

        result = self._run(before, after)
        finding = next(
            item
            for item in result.findings
            if item.reason_code.value == "PARENT_RELATION_ATTRIBUTES_CHANGED"
        )

        self.assertEqual(
            {ref.stream_id for ref in finding.evidence},
            {"before", "after"},
        )
        self.assertEqual(
            finding.attributes["before_attributes"]["basis"],
            "parent_observed_before_only",
        )
        self.assertEqual(
            finding.attributes["after_attributes"]["basis"],
            "current_snapshot",
        )

    def test_ambiguous_edge_correspondence_is_not_silently_paired(self) -> None:
        parent_before = self._process_node("before", 1, 50, 900.0)
        child_before = self._process_node("before", 2, 100, 1000.0)
        parent_after = self._process_node("after", 10, 50, 900.0)
        child_after = self._process_node("after", 11, 100, 1000.0)
        before_edges = (
            self._edge(
                "before",
                3,
                GraphEdgeType.PARENT_OF,
                parent_before.node_id,
                child_before.node_id,
                {"basis": "before-a"},
            ),
            self._edge(
                "before",
                4,
                GraphEdgeType.PARENT_OF,
                parent_before.node_id,
                child_before.node_id,
                {"basis": "before-b"},
            ),
        )
        after_edges = (
            self._edge(
                "after",
                12,
                GraphEdgeType.PARENT_OF,
                parent_after.node_id,
                child_after.node_id,
                {"basis": "after-a"},
            ),
            self._edge(
                "after",
                13,
                GraphEdgeType.PARENT_OF,
                parent_after.node_id,
                child_after.node_id,
                {"basis": "after-b"},
            ),
        )
        before = self._graph(
            "before",
            nodes=(parent_before, child_before),
            edges=before_edges,
        )
        after = self._graph(
            "after",
            nodes=(parent_after, child_after),
            edges=after_edges,
        )

        result = self._run(before, after)
        ambiguous = next(
            item
            for item in result.findings
            if item.reason_code.value == "EDGE_CORRESPONDENCE_AMBIGUOUS"
        )

        self.assertEqual(ambiguous.attributes["before_candidate_count"], 2)
        self.assertEqual(ambiguous.attributes["after_candidate_count"], 2)
        self.assertEqual(
            {ref.stream_id for ref in ambiguous.evidence},
            {"before", "after"},
        )

    def test_projection_note_count_increase_uses_source_event_evidence(self) -> None:
        before = self._graph(
            "before",
            notes=(
                GraphProjectionNote(
                    event_id=1,
                    event_type=EventType.FILE_HASH_OBSERVED,
                    reason="file_hash_not_projected_v1",
                ),
            ),
        )
        after = self._graph(
            "after",
            notes=(
                GraphProjectionNote(
                    event_id=10,
                    event_type=EventType.FILE_HASH_OBSERVED,
                    reason="file_hash_not_projected_v1",
                ),
                GraphProjectionNote(
                    event_id=11,
                    event_type=EventType.FILE_HASH_OBSERVED,
                    reason="file_hash_not_projected_v1",
                ),
            ),
        )

        result = self._run(before, after)
        finding = next(
            item
            for item in result.findings
            if item.reason_code.value == "PROJECTION_NOTE_COUNT_INCREASED"
        )

        self.assertEqual(finding.attributes["delta_count"], 1)
        self.assertEqual(
            {event_id for ref in finding.evidence for event_id in ref.event_ids},
            {10, 11},
        )
        self.assertTrue(all(ref.stream_id == "after" for ref in finding.evidence))

    def test_findings_are_deterministic_for_same_context(self) -> None:
        before = self._graph(
            "before",
            nodes=(self._process_node("before", 1, 100, 1000.0),),
        )
        after = self._graph(
            "after",
            nodes=(
                self._process_node("after", 10, 100, 1000.0),
                self._remote_node("after", 11, "203.0.113.10", 443),
            ),
        )
        context = self._context(before, after)
        analysis_pass = GraphDriftObservationsPass()

        first = analysis_pass.run(context)
        second = analysis_pass.run(context)

        self.assertEqual(first, second)
        self.assertEqual(
            tuple(item.finding_id for item in first),
            tuple(sorted(item.finding_id for item in first)),
        )


if __name__ == "__main__":
    unittest.main()
