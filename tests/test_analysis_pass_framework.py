import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

from agent_observatory.analysis import (
    AnalysisContext,
    AnalysisContractError,
    AnalysisEvidenceRef,
    AnalysisFinding,
    AnalysisPassMetadata,
    EvidenceLayer,
    PassVersion,
    ReasonCode,
    build_analysis_context,
    edge_evidence_ref,
    event_evidence_ref,
    node_evidence_ref,
    run_analysis_passes,
)
from agent_observatory.analysis.graph_drift import compare_graphs
from agent_observatory.graph import (
    EvidenceGraph,
    EvidenceRef,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)
from agent_observatory.storage import EventStore, EventType, ObservationEvent


class _StaticPass:
    def __init__(
        self,
        pass_id: str,
        version: PassVersion,
        findings,
    ) -> None:
        self.metadata = AnalysisPassMetadata(
            pass_id=pass_id,
            version=version,
            description=f"Synthetic {pass_id} test pass.",
        )
        self._findings = findings

    def run(self, context: AnalysisContext):
        del context
        return self._findings


class AnalysisPassFrameworkTests(unittest.TestCase):
    @staticmethod
    def _ref(event_id: int, stream_id: str, event_type: EventType) -> EvidenceRef:
        return EvidenceRef(
            event_id=event_id,
            event_type=event_type,
            observed_at=float(event_id),
            source="analysis-pass-test",
            stream_id=stream_id,
        )

    def _graph(self, stream_id: str, base_event_id: int) -> EvidenceGraph:
        app = GraphNode(
            node_id="application:gemini",
            node_type=GraphNodeType.APPLICATION,
            attributes={"name": "Gemini"},
            evidence=(
                self._ref(
                    base_event_id,
                    stream_id,
                    EventType.APPLICATION_DISCOVERY_OBSERVED,
                ),
            ),
        )
        process = GraphNode(
            node_id="process:100@1000.0",
            node_type=GraphNodeType.PROCESS_INSTANCE,
            attributes={"pid": 100, "started_at": 1000.0, "name": "Gemini.exe"},
            evidence=(
                self._ref(
                    base_event_id + 1,
                    stream_id,
                    EventType.PROCESS_OBSERVED,
                ),
            ),
        )
        edge = GraphEdge(
            edge_id=f"event:{base_event_id}:DISCOVERED_AS:0",
            edge_type=GraphEdgeType.DISCOVERED_AS,
            source_node_id=app.node_id,
            target_node_id=process.node_id,
            attributes={"outcome": "unique", "candidate_count": 1},
            evidence=app.evidence,
        )
        return EvidenceGraph(
            stream_id=stream_id,
            nodes=(app, process),
            edges=(edge,),
            projection_notes=(),
        )

    def _context(self) -> AnalysisContext:
        before = self._graph("before-stream", 1)
        after = self._graph("after-stream", 10)
        return AnalysisContext(
            before_graph=before,
            after_graph=after,
            graph_drift=compare_graphs(before, after),
        )

    @staticmethod
    def _finding(
        finding_id: str,
        pass_id: str,
        version: PassVersion,
        evidence: tuple[AnalysisEvidenceRef, ...],
    ) -> AnalysisFinding:
        return AnalysisFinding(
            finding_id=finding_id,
            pass_id=pass_id,
            pass_version=version,
            reason_code=ReasonCode("PROCESS_INSTANCE_OBSERVED"),
            summary="Process instance is represented in the compared evidence.",
            evidence=evidence,
            limitations=("Descriptive observation only.",),
            attributes={"subject": "process:100@1000.0"},
        )

    def test_reason_code_requires_upper_snake_case(self) -> None:
        self.assertEqual(str(ReasonCode("REMOTE_ENDPOINT_APPEARED")), "REMOTE_ENDPOINT_APPEARED")
        for invalid in ("remote_endpoint", "RemoteEndpoint", "1INVALID", "BAD-CODE"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    ReasonCode(invalid)

    def test_pass_version_is_explicit_and_non_negative(self) -> None:
        self.assertEqual(str(PassVersion(1, 2, 3)), "1.2.3")
        with self.assertRaises(ValueError):
            PassVersion(1, -1, 0)
        with self.assertRaises(ValueError):
            PassVersion(True, 0, 0)

    def test_finding_contract_has_no_evaluative_fields(self) -> None:
        names = {item.name for item in fields(AnalysisFinding)}
        self.assertTrue(
            {"finding_id", "reason_code", "evidence", "limitations", "attributes"}
            <= names
        )
        self.assertTrue(
            {"severity", "confidence", "verdict", "causality", "malicious"}.isdisjoint(names)
        )

    def test_context_rejects_graph_drift_stream_mismatch(self) -> None:
        before = self._graph("before-stream", 1)
        after = self._graph("after-stream", 10)
        wrong_before = self._graph("wrong-before", 20)
        drift = compare_graphs(wrong_before, after)
        with self.assertRaises(AnalysisContractError):
            AnalysisContext(before_graph=before, after_graph=after, graph_drift=drift)

    def test_evidence_helpers_preserve_concrete_graph_provenance(self) -> None:
        graph = self._graph("after-stream", 10)
        node = next(item for item in graph.nodes if item.node_type is GraphNodeType.PROCESS_INSTANCE)
        edge = graph.edges[0]

        node_ref = node_evidence_ref(graph, node)
        edge_ref = edge_evidence_ref(graph, edge)
        event_ref = event_evidence_ref(stream_id=graph.stream_id, event_id=10)

        self.assertEqual(node_ref.layer, EvidenceLayer.GRAPH_NODE)
        self.assertEqual(node_ref.reference_id, "process:100@1000.0")
        self.assertEqual(node_ref.event_ids, (11,))
        self.assertEqual(edge_ref.layer, EvidenceLayer.GRAPH_EDGE)
        self.assertEqual(edge_ref.event_ids, (10,))
        self.assertEqual(event_ref.reference_id, "event:10")
        self.assertEqual(event_ref.event_ids, (10,))

    def test_runner_is_deterministic_across_pass_and_finding_order(self) -> None:
        context = self._context()
        after_process = next(
            node
            for node in context.after_graph.nodes
            if node.node_type is GraphNodeType.PROCESS_INSTANCE
        )
        evidence = (node_evidence_ref(context.after_graph, after_process),)
        version = PassVersion(1, 0, 0)

        beta = _StaticPass(
            "beta-pass",
            version,
            (
                self._finding("beta:z", "beta-pass", version, evidence),
                self._finding("beta:a", "beta-pass", version, evidence),
            ),
        )
        alpha = _StaticPass(
            "alpha-pass",
            version,
            (self._finding("alpha:a", "alpha-pass", version, evidence),),
        )

        first = run_analysis_passes(context, (beta, alpha))
        second = run_analysis_passes(context, (alpha, beta))

        self.assertEqual(first, second)
        self.assertEqual(
            tuple(result.pass_id for result in first.pass_results),
            ("alpha-pass", "beta-pass"),
        )
        self.assertEqual(
            tuple(finding.finding_id for finding in first.findings),
            ("alpha:a", "beta:a", "beta:z"),
        )
        self.assertEqual(first.finding_count, 3)

    def test_duplicate_pass_ids_are_rejected(self) -> None:
        context = self._context()
        version = PassVersion(1, 0, 0)
        first = _StaticPass("same-pass", version, ())
        second = _StaticPass("same-pass", version, ())
        with self.assertRaisesRegex(AnalysisContractError, "duplicate analysis pass id"):
            run_analysis_passes(context, (first, second))

    def test_finding_pass_id_must_match_pass_metadata(self) -> None:
        context = self._context()
        node = context.after_graph.nodes[1]
        evidence = (node_evidence_ref(context.after_graph, node),)
        version = PassVersion(1, 0, 0)
        finding = self._finding("wrong-pass:f1", "other-pass", version, evidence)
        analysis_pass = _StaticPass("right-pass", version, (finding,))
        with self.assertRaisesRegex(AnalysisContractError, "pass_id does not match"):
            run_analysis_passes(context, (analysis_pass,))

    def test_finding_version_must_match_pass_metadata(self) -> None:
        context = self._context()
        node = context.after_graph.nodes[1]
        evidence = (node_evidence_ref(context.after_graph, node),)
        finding = self._finding(
            "versioned-pass:f1",
            "versioned-pass",
            PassVersion(2, 0, 0),
            evidence,
        )
        analysis_pass = _StaticPass("versioned-pass", PassVersion(1, 0, 0), (finding,))
        with self.assertRaisesRegex(AnalysisContractError, "version does not match"):
            run_analysis_passes(context, (analysis_pass,))

    def test_duplicate_finding_ids_are_rejected_across_passes(self) -> None:
        context = self._context()
        node = context.after_graph.nodes[1]
        evidence = (node_evidence_ref(context.after_graph, node),)
        version = PassVersion(1, 0, 0)
        first = _StaticPass(
            "first-pass",
            version,
            (self._finding("shared:f1", "first-pass", version, evidence),),
        )
        second = _StaticPass(
            "second-pass",
            version,
            (self._finding("shared:f1", "second-pass", version, evidence),),
        )
        with self.assertRaisesRegex(AnalysisContractError, "duplicate finding id"):
            run_analysis_passes(context, (first, second))

    def test_pass_must_return_tuple(self) -> None:
        context = self._context()
        analysis_pass = _StaticPass("list-pass", PassVersion(1, 0, 0), [])
        with self.assertRaisesRegex(AnalysisContractError, "must return tuple"):
            run_analysis_passes(context, (analysis_pass,))

    def test_evidence_cannot_reference_stream_outside_context(self) -> None:
        context = self._context()
        version = PassVersion(1, 0, 0)
        evidence = (event_evidence_ref(stream_id="invented-stream", event_id=10),)
        finding = self._finding("bounded-pass:f1", "bounded-pass", version, evidence)
        analysis_pass = _StaticPass("bounded-pass", version, (finding,))
        with self.assertRaisesRegex(AnalysisContractError, "outside analysis context"):
            run_analysis_passes(context, (analysis_pass,))

    def test_evidence_cannot_invent_source_event_id(self) -> None:
        context = self._context()
        version = PassVersion(1, 0, 0)
        evidence = (event_evidence_ref(stream_id="after-stream", event_id=999),)
        finding = self._finding("bounded-pass:f1", "bounded-pass", version, evidence)
        analysis_pass = _StaticPass("bounded-pass", version, (finding,))
        with self.assertRaisesRegex(AnalysisContractError, "not present in graph"):
            run_analysis_passes(context, (analysis_pass,))

    def test_graph_node_reference_must_exist_in_referenced_graph(self) -> None:
        context = self._context()
        version = PassVersion(1, 0, 0)
        evidence = (
            AnalysisEvidenceRef(
                layer=EvidenceLayer.GRAPH_NODE,
                reference_id="process:999@999.0",
                stream_id="after-stream",
                event_ids=(10,),
            ),
        )
        finding = self._finding("bounded-pass:f1", "bounded-pass", version, evidence)
        analysis_pass = _StaticPass("bounded-pass", version, (finding,))
        with self.assertRaisesRegex(AnalysisContractError, "graph node evidence not found"):
            run_analysis_passes(context, (analysis_pass,))

    def test_build_analysis_context_projects_persisted_streams_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            for event_id, stream_id in ((1, "before"), (2, "after")):
                store.append(
                    ObservationEvent(
                        event_type=EventType.PROCESS_OBSERVED,
                        observed_at=float(event_id),
                        source="analysis-pass-test",
                        stream_id=stream_id,
                        payload={
                            "pid": 100,
                            "ppid": 1,
                            "started_at": 1000.0,
                            "name": "Gemini.exe",
                            "executable_path": r"C:\\Google\\Gemini\\Gemini.exe",
                            "command_line_sha256": "abc",
                        },
                    )
                )

            context = build_analysis_context(store, "before", "after")

        self.assertEqual(context.before_graph.stream_id, "before")
        self.assertEqual(context.after_graph.stream_id, "after")
        self.assertFalse(context.graph_drift.has_changes)
        self.assertEqual(len(context.before_graph.nodes), 1)
        self.assertEqual(len(context.after_graph.nodes), 1)


if __name__ == "__main__":
    unittest.main()
