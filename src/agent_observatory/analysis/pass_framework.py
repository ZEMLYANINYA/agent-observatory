from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Mapping, Protocol, Sequence

from agent_observatory.graph import EvidenceGraph, GraphEdge, GraphNode, project_stream
from agent_observatory.storage import EventStore

from .graph_drift import GraphDrift, compare_graphs


_REASON_CODE_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_PASS_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")


class AnalysisContractError(RuntimeError):
    """Raised when analysis inputs or pass outputs violate the v1 contract."""


class EvidenceLayer(str, Enum):
    EVENT = "event"
    GRAPH_NODE = "graph_node"
    GRAPH_EDGE = "graph_edge"


@dataclass(frozen=True, slots=True, order=True)
class ReasonCode:
    """Stable machine-readable reason for one descriptive finding."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not _REASON_CODE_RE.fullmatch(self.value):
            raise ValueError("reason code must match ^[A-Z][A-Z0-9_]*$")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True, order=True)
class PassVersion:
    """Small explicit semantic version for deterministic analysis behavior."""

    major: int
    minor: int
    patch: int = 0

    def __post_init__(self) -> None:
        for name, value in (
            ("major", self.major),
            ("minor", self.minor),
            ("patch", self.patch),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


@dataclass(frozen=True, slots=True)
class AnalysisPassMetadata:
    pass_id: str
    version: PassVersion
    description: str

    def __post_init__(self) -> None:
        if not isinstance(self.pass_id, str) or not _PASS_ID_RE.fullmatch(self.pass_id):
            raise ValueError(
                "pass_id must be lowercase kebab-case and start with a letter"
            )
        if not isinstance(self.version, PassVersion):
            raise TypeError("version must be PassVersion")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("description must be a non-empty string")


@dataclass(frozen=True, slots=True)
class AnalysisEvidenceRef:
    """Pointer from a finding back to concrete evidence and source events."""

    layer: EvidenceLayer
    reference_id: str
    stream_id: str
    event_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.layer, EvidenceLayer):
            raise TypeError("layer must be EvidenceLayer")
        if not isinstance(self.reference_id, str) or not self.reference_id.strip():
            raise ValueError("reference_id must be a non-empty string")
        if not isinstance(self.stream_id, str) or not self.stream_id.strip():
            raise ValueError("stream_id must be a non-empty string")
        if not isinstance(self.event_ids, tuple) or not self.event_ids:
            raise ValueError("event_ids must be a non-empty tuple")
        if any(
            isinstance(event_id, bool)
            or not isinstance(event_id, int)
            or event_id <= 0
            for event_id in self.event_ids
        ):
            raise ValueError("event_ids must contain positive integers")
        if tuple(sorted(set(self.event_ids))) != self.event_ids:
            raise ValueError("event_ids must be sorted and unique")


@dataclass(frozen=True, slots=True)
class AnalysisFinding:
    """One deterministic descriptive observation produced by an analysis pass.

    v1 intentionally has no severity, confidence, anomaly verdict, causality,
    maliciousness, or importance fields.
    """

    finding_id: str
    pass_id: str
    pass_version: PassVersion
    reason_code: ReasonCode
    summary: str
    evidence: tuple[AnalysisEvidenceRef, ...]
    limitations: tuple[str, ...] = ()
    attributes: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.finding_id, str) or not self.finding_id.strip():
            raise ValueError("finding_id must be a non-empty string")
        if not isinstance(self.pass_id, str) or not _PASS_ID_RE.fullmatch(self.pass_id):
            raise ValueError("finding pass_id must be lowercase kebab-case")
        if not isinstance(self.pass_version, PassVersion):
            raise TypeError("pass_version must be PassVersion")
        if not isinstance(self.reason_code, ReasonCode):
            raise TypeError("reason_code must be ReasonCode")
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("summary must be a non-empty string")
        if not isinstance(self.evidence, tuple) or not self.evidence:
            raise ValueError("a finding must reference a non-empty evidence tuple")
        if any(not isinstance(item, AnalysisEvidenceRef) for item in self.evidence):
            raise TypeError("evidence must contain AnalysisEvidenceRef values")
        if not isinstance(self.limitations, tuple):
            raise TypeError("limitations must be a tuple")
        if any(not isinstance(item, str) or not item.strip() for item in self.limitations):
            raise ValueError("limitations must contain non-empty strings")
        if not isinstance(self.attributes, Mapping):
            raise TypeError("attributes must be a mapping")
        if any(not isinstance(key, str) for key in self.attributes):
            raise TypeError("attribute keys must be strings")

        attributes = dict(self.attributes)
        try:
            json.dumps(
                attributes,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("attributes must be finite JSON-compatible data") from exc
        object.__setattr__(self, "attributes", attributes)


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """Evidence-bounded input for deterministic passes over one graph drift."""

    before_graph: EvidenceGraph
    after_graph: EvidenceGraph
    graph_drift: GraphDrift

    def __post_init__(self) -> None:
        if self.graph_drift.before_stream_id != self.before_graph.stream_id:
            raise AnalysisContractError(
                "graph_drift.before_stream_id does not match before_graph"
            )
        if self.graph_drift.after_stream_id != self.after_graph.stream_id:
            raise AnalysisContractError(
                "graph_drift.after_stream_id does not match after_graph"
            )


class AnalysisPass(Protocol):
    """Protocol implemented by deterministic read-only analysis passes."""

    metadata: AnalysisPassMetadata

    def run(self, context: AnalysisContext) -> tuple[AnalysisFinding, ...]: ...


@dataclass(frozen=True, slots=True)
class AnalysisPassResult:
    pass_id: str
    pass_version: PassVersion
    findings: tuple[AnalysisFinding, ...]


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    before_stream_id: str
    after_stream_id: str
    pass_results: tuple[AnalysisPassResult, ...]

    @property
    def findings(self) -> tuple[AnalysisFinding, ...]:
        return tuple(
            finding
            for result in self.pass_results
            for finding in result.findings
        )

    @property
    def finding_count(self) -> int:
        return sum(len(result.findings) for result in self.pass_results)


def _event_ids_from_refs(refs) -> tuple[int, ...]:
    return tuple(sorted({ref.event_id for ref in refs}))


def node_evidence_ref(graph: EvidenceGraph, node: GraphNode) -> AnalysisEvidenceRef:
    return AnalysisEvidenceRef(
        layer=EvidenceLayer.GRAPH_NODE,
        reference_id=node.node_id,
        stream_id=graph.stream_id,
        event_ids=_event_ids_from_refs(node.evidence),
    )


def edge_evidence_ref(graph: EvidenceGraph, edge: GraphEdge) -> AnalysisEvidenceRef:
    return AnalysisEvidenceRef(
        layer=EvidenceLayer.GRAPH_EDGE,
        reference_id=edge.edge_id,
        stream_id=graph.stream_id,
        event_ids=_event_ids_from_refs(edge.evidence),
    )


def event_evidence_ref(*, stream_id: str, event_id: int) -> AnalysisEvidenceRef:
    return AnalysisEvidenceRef(
        layer=EvidenceLayer.EVENT,
        reference_id=f"event:{event_id}",
        stream_id=stream_id,
        event_ids=(event_id,),
    )


def build_analysis_context(
    store: EventStore,
    before_stream_id: str,
    after_stream_id: str,
) -> AnalysisContext:
    """Project two persisted streams once and build a graph-drift context."""

    before_graph = project_stream(store, before_stream_id)
    after_graph = project_stream(store, after_stream_id)
    drift = compare_graphs(before_graph, after_graph)
    return AnalysisContext(
        before_graph=before_graph,
        after_graph=after_graph,
        graph_drift=drift,
    )


def _validate_contract_surface() -> None:
    prohibited = {"severity", "confidence", "verdict", "causality", "malicious"}
    finding_fields = {item.name for item in fields(AnalysisFinding)}
    overlap = prohibited & finding_fields
    if overlap:
        raise AnalysisContractError(
            "AnalysisFinding v1 contains prohibited evaluative fields: "
            + ", ".join(sorted(overlap))
        )


def _graph_for_stream(context: AnalysisContext, stream_id: str) -> EvidenceGraph:
    if stream_id == context.before_graph.stream_id:
        return context.before_graph
    if stream_id == context.after_graph.stream_id:
        return context.after_graph
    raise AnalysisContractError(
        f"evidence references stream outside analysis context: {stream_id}"
    )


def _validate_evidence_ref(
    context: AnalysisContext,
    evidence_ref: AnalysisEvidenceRef,
) -> None:
    graph = _graph_for_stream(context, evidence_ref.stream_id)
    graph_event_ids = set(graph.source_event_ids)
    missing = set(evidence_ref.event_ids) - graph_event_ids
    if missing:
        raise AnalysisContractError(
            "evidence references source event ids not present in graph: "
            + ", ".join(str(event_id) for event_id in sorted(missing))
        )

    if evidence_ref.layer is EvidenceLayer.EVENT:
        if len(evidence_ref.event_ids) != 1:
            raise AnalysisContractError("EVENT evidence must reference exactly one event")
        expected = f"event:{evidence_ref.event_ids[0]}"
        if evidence_ref.reference_id != expected:
            raise AnalysisContractError(
                f"EVENT evidence reference_id must be {expected!r}"
            )
        return

    if evidence_ref.layer is EvidenceLayer.GRAPH_NODE:
        nodes = {node.node_id: node for node in graph.nodes}
        node = nodes.get(evidence_ref.reference_id)
        if node is None:
            raise AnalysisContractError(
                f"graph node evidence not found: {evidence_ref.reference_id}"
            )
        node_event_ids = set(_event_ids_from_refs(node.evidence))
        if not set(evidence_ref.event_ids) <= node_event_ids:
            raise AnalysisContractError(
                "graph node evidence contains event ids outside node provenance"
            )
        return

    if evidence_ref.layer is EvidenceLayer.GRAPH_EDGE:
        edges = {edge.edge_id: edge for edge in graph.edges}
        edge = edges.get(evidence_ref.reference_id)
        if edge is None:
            raise AnalysisContractError(
                f"graph edge evidence not found: {evidence_ref.reference_id}"
            )
        edge_event_ids = set(_event_ids_from_refs(edge.evidence))
        if not set(evidence_ref.event_ids) <= edge_event_ids:
            raise AnalysisContractError(
                "graph edge evidence contains event ids outside edge provenance"
            )
        return

    raise AnalysisContractError(f"unsupported evidence layer: {evidence_ref.layer}")


def run_analysis_passes(
    context: AnalysisContext,
    passes: Sequence[AnalysisPass],
) -> AnalysisResult:
    """Run passes deterministically and validate every emitted finding."""

    _validate_contract_surface()

    by_id: dict[str, AnalysisPass] = {}
    for analysis_pass in passes:
        metadata = analysis_pass.metadata
        if not isinstance(metadata, AnalysisPassMetadata):
            raise AnalysisContractError("pass metadata must be AnalysisPassMetadata")
        if metadata.pass_id in by_id:
            raise AnalysisContractError(f"duplicate analysis pass id: {metadata.pass_id}")
        by_id[metadata.pass_id] = analysis_pass

    pass_results: list[AnalysisPassResult] = []
    seen_finding_ids: set[str] = set()

    for pass_id in sorted(by_id):
        analysis_pass = by_id[pass_id]
        metadata = analysis_pass.metadata
        emitted = analysis_pass.run(context)
        if not isinstance(emitted, tuple):
            raise AnalysisContractError(
                f"analysis pass {pass_id} must return tuple[AnalysisFinding, ...]"
            )

        findings_for_pass: list[AnalysisFinding] = []
        for finding in emitted:
            if not isinstance(finding, AnalysisFinding):
                raise AnalysisContractError(
                    f"analysis pass {pass_id} emitted a non-AnalysisFinding value"
                )
            if finding.pass_id != metadata.pass_id:
                raise AnalysisContractError(
                    f"finding {finding.finding_id!r} pass_id does not match pass metadata"
                )
            if finding.pass_version != metadata.version:
                raise AnalysisContractError(
                    f"finding {finding.finding_id!r} version does not match pass metadata"
                )
            if finding.finding_id in seen_finding_ids:
                raise AnalysisContractError(f"duplicate finding id: {finding.finding_id}")
            for evidence_ref in finding.evidence:
                _validate_evidence_ref(context, evidence_ref)
            seen_finding_ids.add(finding.finding_id)
            findings_for_pass.append(finding)

        pass_results.append(
            AnalysisPassResult(
                pass_id=metadata.pass_id,
                pass_version=metadata.version,
                findings=tuple(
                    sorted(findings_for_pass, key=lambda item: item.finding_id)
                ),
            )
        )

    return AnalysisResult(
        before_stream_id=context.before_graph.stream_id,
        after_stream_id=context.after_graph.stream_id,
        pass_results=tuple(pass_results),
    )
