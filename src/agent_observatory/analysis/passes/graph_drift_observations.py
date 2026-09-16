from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Iterable, Mapping

from agent_observatory.graph import (
    EvidenceGraph,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
)

from ..graph_drift import (
    EdgeFact,
    GraphDrift,
    ProcessContinuityStatus,
    ProjectionNoteCount,
)
from ..pass_framework import (
    AnalysisContext,
    AnalysisContractError,
    AnalysisEvidenceRef,
    AnalysisFinding,
    AnalysisPassMetadata,
    PassVersion,
    ReasonCode,
    edge_evidence_ref,
    event_evidence_ref,
    node_evidence_ref,
)


GRAPH_DRIFT_OBSERVATIONS_PASS_ID = "graph-drift-observations"
GRAPH_DRIFT_OBSERVATIONS_VERSION = PassVersion(1, 0, 0)

_COMMON_LIMITATION = (
    "Descriptive structural observation only; no anomaly, causality, "
    "maliciousness, importance, or operator intent is inferred."
)
_APPEARANCE_LIMITATION = (
    "Observed only in the later compared graph; this does not establish first occurrence."
)
_DISAPPEARANCE_LIMITATION = (
    "Not represented in the later compared graph; point-in-time absence does not establish termination or continuous absence."
)
_REMOTE_ENDPOINT_LIMITATION = (
    "Remote endpoint identity represents an observed protocol/address/port tuple only; service identity and transferred data are not inferred."
)
_DUPLICATE_EDGE_LIMITATION = (
    "For duplicate structurally identical edges, graph drift identifies multiplicity change but cannot assign the delta to one unique provenance instance."
)

_NODE_REASON_CODES: dict[GraphNodeType, tuple[ReasonCode, ReasonCode, ReasonCode]] = {
    GraphNodeType.APPLICATION: (
        ReasonCode("APPLICATION_APPEARED"),
        ReasonCode("APPLICATION_DISAPPEARED"),
        ReasonCode("APPLICATION_ATTRIBUTES_CHANGED"),
    ),
    GraphNodeType.PROCESS_INSTANCE: (
        ReasonCode("PROCESS_INSTANCE_APPEARED"),
        ReasonCode("PROCESS_INSTANCE_DISAPPEARED"),
        ReasonCode("PROCESS_INSTANCE_ATTRIBUTES_CHANGED"),
    ),
    GraphNodeType.FILE_IDENTITY: (
        ReasonCode("FILE_IDENTITY_APPEARED"),
        ReasonCode("FILE_IDENTITY_DISAPPEARED"),
        ReasonCode("FILE_IDENTITY_ATTRIBUTES_CHANGED"),
    ),
    GraphNodeType.REMOTE_ENDPOINT: (
        ReasonCode("REMOTE_ENDPOINT_APPEARED"),
        ReasonCode("REMOTE_ENDPOINT_DISAPPEARED"),
        ReasonCode("REMOTE_ENDPOINT_ATTRIBUTES_CHANGED"),
    ),
}

_EDGE_REASON_CODES: dict[GraphEdgeType, tuple[ReasonCode, ReasonCode, ReasonCode]] = {
    GraphEdgeType.DISCOVERED_AS: (
        ReasonCode("APPLICATION_DISCOVERY_RELATION_APPEARED"),
        ReasonCode("APPLICATION_DISCOVERY_RELATION_DISAPPEARED"),
        ReasonCode("APPLICATION_DISCOVERY_RELATION_ATTRIBUTES_CHANGED"),
    ),
    GraphEdgeType.PARENT_OF: (
        ReasonCode("PARENT_RELATION_APPEARED"),
        ReasonCode("PARENT_RELATION_DISAPPEARED"),
        ReasonCode("PARENT_RELATION_ATTRIBUTES_CHANGED"),
    ),
    GraphEdgeType.EXECUTED_FROM: (
        ReasonCode("EXECUTED_FROM_RELATION_APPEARED"),
        ReasonCode("EXECUTED_FROM_RELATION_DISAPPEARED"),
        ReasonCode("EXECUTED_FROM_RELATION_ATTRIBUTES_CHANGED"),
    ),
    GraphEdgeType.OBSERVED_TCP_TO: (
        ReasonCode("TCP_RELATION_APPEARED"),
        ReasonCode("TCP_RELATION_DISAPPEARED"),
        ReasonCode("TCP_RELATION_ATTRIBUTES_CHANGED"),
    ),
}


class GraphDriftObservationsPass:
    """Translate Graph Drift into evidence-bounded descriptive findings.

    This pass does not decide whether a structural change is expected, anomalous,
    important, causal, malicious, or actionable.
    """

    metadata = AnalysisPassMetadata(
        pass_id=GRAPH_DRIFT_OBSERVATIONS_PASS_ID,
        version=GRAPH_DRIFT_OBSERVATIONS_VERSION,
        description=(
            "Emit deterministic descriptive findings for structural Graph Drift "
            "changes while preserving evidence provenance."
        ),
    )

    def run(self, context: AnalysisContext) -> tuple[AnalysisFinding, ...]:
        findings: list[AnalysisFinding] = []
        findings.extend(_node_findings(context))
        findings.extend(_edge_findings(context))
        findings.extend(_process_continuity_findings(context))
        findings.extend(_projection_note_findings(context))
        return tuple(sorted(findings, key=lambda item: item.finding_id))


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _finding_id(reason_code: ReasonCode, subject: Mapping[str, object]) -> str:
    payload = {
        "pass_id": GRAPH_DRIFT_OBSERVATIONS_PASS_ID,
        "reason_code": reason_code.value,
        "subject": dict(subject),
    }
    digest = hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:16]
    return (
        f"{GRAPH_DRIFT_OBSERVATIONS_PASS_ID}:"
        f"{reason_code.value.lower()}:{digest}"
    )


def _evidence_sort_key(ref: AnalysisEvidenceRef) -> tuple[object, ...]:
    return (ref.stream_id, ref.layer.value, ref.reference_id, ref.event_ids)


def _dedupe_evidence(
    refs: Iterable[AnalysisEvidenceRef],
) -> tuple[AnalysisEvidenceRef, ...]:
    by_key: dict[tuple[object, ...], AnalysisEvidenceRef] = {}
    for ref in refs:
        by_key[_evidence_sort_key(ref)] = ref
    return tuple(by_key[key] for key in sorted(by_key))


def _finding(
    *,
    reason_code: ReasonCode,
    summary: str,
    evidence: Iterable[AnalysisEvidenceRef],
    attributes: Mapping[str, object],
    limitations: Iterable[str] = (),
) -> AnalysisFinding:
    evidence_tuple = _dedupe_evidence(evidence)
    if not evidence_tuple:
        raise AnalysisContractError(
            f"{GRAPH_DRIFT_OBSERVATIONS_PASS_ID} cannot emit evidence-free finding"
        )
    limitation_tuple = tuple(dict.fromkeys((_COMMON_LIMITATION, *limitations)))
    return AnalysisFinding(
        finding_id=_finding_id(reason_code, attributes),
        pass_id=GRAPH_DRIFT_OBSERVATIONS_PASS_ID,
        pass_version=GRAPH_DRIFT_OBSERVATIONS_VERSION,
        reason_code=reason_code,
        summary=summary,
        evidence=evidence_tuple,
        limitations=limitation_tuple,
        attributes=dict(attributes),
    )


def _nodes_by_id(graph: EvidenceGraph) -> dict[str, GraphNode]:
    return {node.node_id: node for node in graph.nodes}


def _require_node(graph: EvidenceGraph, node_id: str) -> GraphNode:
    node = _nodes_by_id(graph).get(node_id)
    if node is None:
        raise AnalysisContractError(
            f"graph drift references node missing from {graph.stream_id}: {node_id}"
        )
    return node


def _node_limitations(node_type: GraphNodeType, *, appeared: bool) -> tuple[str, ...]:
    values = [
        _APPEARANCE_LIMITATION if appeared else _DISAPPEARANCE_LIMITATION
    ]
    if node_type is GraphNodeType.REMOTE_ENDPOINT:
        values.append(_REMOTE_ENDPOINT_LIMITATION)
    return tuple(values)


def _node_findings(context: AnalysisContext) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    before = context.before_graph
    after = context.after_graph

    for drift in context.graph_drift.nodes:
        try:
            appeared_reason, disappeared_reason, changed_reason = _NODE_REASON_CODES[
                drift.node_type
            ]
        except KeyError as exc:
            raise AnalysisContractError(
                f"unsupported graph node type in observations pass: {drift.node_type}"
            ) from exc

        for node_id in drift.added:
            node = _require_node(after, node_id)
            attributes = {
                "change": "added",
                "node_type": drift.node_type.value,
                "node_id": node_id,
                "node_attributes": dict(node.attributes),
            }
            findings.append(
                _finding(
                    reason_code=appeared_reason,
                    summary=(
                        f"{drift.node_type.value} node is represented in the later "
                        f"graph but not the earlier graph: {node_id}"
                    ),
                    evidence=(node_evidence_ref(after, node),),
                    attributes=attributes,
                    limitations=_node_limitations(drift.node_type, appeared=True),
                )
            )

        for node_id in drift.removed:
            node = _require_node(before, node_id)
            attributes = {
                "change": "removed",
                "node_type": drift.node_type.value,
                "node_id": node_id,
                "node_attributes": dict(node.attributes),
            }
            findings.append(
                _finding(
                    reason_code=disappeared_reason,
                    summary=(
                        f"{drift.node_type.value} node is represented in the earlier "
                        f"graph but not the later graph: {node_id}"
                    ),
                    evidence=(node_evidence_ref(before, node),),
                    attributes=attributes,
                    limitations=_node_limitations(drift.node_type, appeared=False),
                )
            )

        for change in drift.changed:
            before_node = _require_node(before, change.node_id)
            after_node = _require_node(after, change.node_id)
            attributes = {
                "change": "attributes_changed",
                "node_type": drift.node_type.value,
                "node_id": change.node_id,
                "before_attributes": dict(change.before_attributes),
                "after_attributes": dict(change.after_attributes),
            }
            limitations: list[str] = []
            if drift.node_type is GraphNodeType.REMOTE_ENDPOINT:
                limitations.append(_REMOTE_ENDPOINT_LIMITATION)
            findings.append(
                _finding(
                    reason_code=changed_reason,
                    summary=(
                        f"{drift.node_type.value} node retains the same graph identity "
                        f"but has different semantic attributes: {change.node_id}"
                    ),
                    evidence=(
                        node_evidence_ref(before, before_node),
                        node_evidence_ref(after, after_node),
                    ),
                    attributes=attributes,
                    limitations=limitations,
                )
            )

    return findings


def _edge_key(edge: GraphEdge) -> str:
    return f"{edge.edge_type.value}:{edge.source_node_id}->{edge.target_node_id}"


def _edge_fact_key(fact: EdgeFact) -> tuple[str, str, str, str]:
    return (
        fact.edge_type.value,
        fact.source_node_id,
        fact.target_node_id,
        _canonical(dict(fact.attributes)),
    )


def _matching_edges_for_fact(graph: EvidenceGraph, fact: EdgeFact) -> tuple[GraphEdge, ...]:
    wanted_attributes = _canonical(dict(fact.attributes))
    matches = tuple(
        sorted(
            (
                edge
                for edge in graph.edges
                if edge.edge_type is fact.edge_type
                and edge.source_node_id == fact.source_node_id
                and edge.target_node_id == fact.target_node_id
                and _canonical(dict(edge.attributes)) == wanted_attributes
            ),
            key=lambda edge: edge.edge_id,
        )
    )
    if not matches:
        raise AnalysisContractError(
            "graph drift references edge fact absent from graph: "
            f"{fact.edge_type.value}:{fact.source_node_id}->{fact.target_node_id}"
        )
    return matches


def _matching_edges_for_change(
    graph: EvidenceGraph,
    *,
    edge_type: GraphEdgeType,
    source_node_id: str,
    target_node_id: str,
    attributes: Mapping[str, object],
) -> tuple[GraphEdge, ...]:
    wanted = _canonical(dict(attributes))
    matches = tuple(
        sorted(
            (
                edge
                for edge in graph.edges
                if edge.edge_type is edge_type
                and edge.source_node_id == source_node_id
                and edge.target_node_id == target_node_id
                and _canonical(dict(edge.attributes)) == wanted
            ),
            key=lambda edge: edge.edge_id,
        )
    )
    if not matches:
        raise AnalysisContractError(
            "graph drift attribute change references edge absent from graph: "
            f"{edge_type.value}:{source_node_id}->{target_node_id}"
        )
    return matches


def _group_edge_facts(facts: tuple[EdgeFact, ...]) -> tuple[tuple[EdgeFact, int], ...]:
    by_key: dict[tuple[str, str, str, str], EdgeFact] = {}
    counts: Counter[tuple[str, str, str, str]] = Counter()
    for fact in facts:
        key = _edge_fact_key(fact)
        by_key[key] = fact
        counts[key] += 1
    return tuple((by_key[key], counts[key]) for key in sorted(counts))


def _edge_limitations(edge_type: GraphEdgeType, *, appeared: bool) -> tuple[str, ...]:
    values = [
        _APPEARANCE_LIMITATION if appeared else _DISAPPEARANCE_LIMITATION,
        _DUPLICATE_EDGE_LIMITATION,
    ]
    if edge_type is GraphEdgeType.OBSERVED_TCP_TO:
        values.append(_REMOTE_ENDPOINT_LIMITATION)
    return tuple(values)


def _edge_findings(context: AnalysisContext) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    before = context.before_graph
    after = context.after_graph

    for drift in context.graph_drift.edges:
        try:
            appeared_reason, disappeared_reason, changed_reason = _EDGE_REASON_CODES[
                drift.edge_type
            ]
        except KeyError as exc:
            raise AnalysisContractError(
                f"unsupported graph edge type in observations pass: {drift.edge_type}"
            ) from exc

        for fact, delta_count in _group_edge_facts(drift.added):
            edges = _matching_edges_for_fact(after, fact)
            attributes = {
                "change": "added",
                "edge_type": fact.edge_type.value,
                "source_node_id": fact.source_node_id,
                "target_node_id": fact.target_node_id,
                "edge_attributes": dict(fact.attributes),
                "delta_count": delta_count,
            }
            findings.append(
                _finding(
                    reason_code=appeared_reason,
                    summary=(
                        f"{fact.edge_type.value} relation is represented more times in "
                        "the later graph than the earlier graph."
                    ),
                    evidence=(edge_evidence_ref(after, edge) for edge in edges),
                    attributes=attributes,
                    limitations=_edge_limitations(fact.edge_type, appeared=True),
                )
            )

        for fact, delta_count in _group_edge_facts(drift.removed):
            edges = _matching_edges_for_fact(before, fact)
            attributes = {
                "change": "removed",
                "edge_type": fact.edge_type.value,
                "source_node_id": fact.source_node_id,
                "target_node_id": fact.target_node_id,
                "edge_attributes": dict(fact.attributes),
                "delta_count": delta_count,
            }
            findings.append(
                _finding(
                    reason_code=disappeared_reason,
                    summary=(
                        f"{fact.edge_type.value} relation is represented more times in "
                        "the earlier graph than the later graph."
                    ),
                    evidence=(edge_evidence_ref(before, edge) for edge in edges),
                    attributes=attributes,
                    limitations=_edge_limitations(fact.edge_type, appeared=False),
                )
            )

        for change in drift.changed:
            before_edges = _matching_edges_for_change(
                before,
                edge_type=change.edge_type,
                source_node_id=change.source_node_id,
                target_node_id=change.target_node_id,
                attributes=change.before_attributes,
            )
            after_edges = _matching_edges_for_change(
                after,
                edge_type=change.edge_type,
                source_node_id=change.source_node_id,
                target_node_id=change.target_node_id,
                attributes=change.after_attributes,
            )
            attributes = {
                "change": "attributes_changed",
                "edge_type": change.edge_type.value,
                "source_node_id": change.source_node_id,
                "target_node_id": change.target_node_id,
                "before_attributes": dict(change.before_attributes),
                "after_attributes": dict(change.after_attributes),
            }
            limitations: list[str] = [_DUPLICATE_EDGE_LIMITATION]
            if change.edge_type is GraphEdgeType.OBSERVED_TCP_TO:
                limitations.append(_REMOTE_ENDPOINT_LIMITATION)
            findings.append(
                _finding(
                    reason_code=changed_reason,
                    summary=(
                        f"{change.edge_type.value} relation keeps the same endpoint "
                        "identities but has different semantic attributes."
                    ),
                    evidence=(
                        edge_evidence_ref(before, edge) for edge in before_edges
                    ),
                    attributes=attributes,
                    limitations=limitations,
                )
            )
            # Add after-side provenance without inventing one-to-one edge pairing.
            previous = findings.pop()
            findings.append(
                AnalysisFinding(
                    finding_id=previous.finding_id,
                    pass_id=previous.pass_id,
                    pass_version=previous.pass_version,
                    reason_code=previous.reason_code,
                    summary=previous.summary,
                    evidence=_dedupe_evidence(
                        (*previous.evidence, *(edge_evidence_ref(after, edge) for edge in after_edges))
                    ),
                    limitations=previous.limitations,
                    attributes=previous.attributes,
                )
            )

        for ambiguous_key in drift.ambiguous_keys:
            before_edges = tuple(
                edge
                for edge in before.edges
                if edge.edge_type is drift.edge_type and _edge_key(edge) == ambiguous_key
            )
            after_edges = tuple(
                edge
                for edge in after.edges
                if edge.edge_type is drift.edge_type and _edge_key(edge) == ambiguous_key
            )
            if not before_edges or not after_edges:
                raise AnalysisContractError(
                    f"ambiguous edge key lacks candidates in both graphs: {ambiguous_key}"
                )
            reason = ReasonCode("EDGE_CORRESPONDENCE_AMBIGUOUS")
            attributes = {
                "change": "ambiguous_correspondence",
                "edge_type": drift.edge_type.value,
                "edge_key": ambiguous_key,
                "before_candidate_count": len(before_edges),
                "after_candidate_count": len(after_edges),
            }
            findings.append(
                _finding(
                    reason_code=reason,
                    summary=(
                        "Multiple unmatched relations share the same graph endpoint key; "
                        "one-to-one edge correspondence is not inferred."
                    ),
                    evidence=(
                        *(edge_evidence_ref(before, edge) for edge in before_edges),
                        *(edge_evidence_ref(after, edge) for edge in after_edges),
                    ),
                    attributes=attributes,
                    limitations=(
                        "The evidence is intentionally left unmatched rather than assigning arbitrary edge continuity.",
                    ),
                )
            )

    return findings


def _process_continuity_findings(context: AnalysisContext) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    before = context.before_graph
    after = context.after_graph

    for continuity in context.graph_drift.process_continuity:
        if continuity.status is ProcessContinuityStatus.SAME_INSTANCE:
            continue

        refs: list[AnalysisEvidenceRef] = []
        for node_id in continuity.before_instances:
            refs.append(node_evidence_ref(before, _require_node(before, node_id)))
        for node_id in continuity.after_instances:
            refs.append(node_evidence_ref(after, _require_node(after, node_id)))

        if continuity.status is ProcessContinuityStatus.REPLACED_INSTANCE:
            reason = ReasonCode("PROCESS_IDENTITY_REPLACED")
            summary = (
                "The same PID slot maps to non-overlapping process-instance identities "
                "across the compared graphs."
            )
        elif continuity.status is ProcessContinuityStatus.MIXED:
            reason = ReasonCode("PROCESS_IDENTITY_CONTINUITY_MIXED")
            summary = (
                "The same PID slot has partially overlapping process-instance identities "
                "across the compared graphs."
            )
        else:
            raise AnalysisContractError(
                f"unsupported process continuity status: {continuity.status}"
            )

        attributes = {
            "pid": continuity.pid,
            "status": continuity.status.value,
            "before_instances": list(continuity.before_instances),
            "after_instances": list(continuity.after_instances),
        }
        findings.append(
            _finding(
                reason_code=reason,
                summary=summary,
                evidence=refs,
                attributes=attributes,
                limitations=(
                    "PID-slot comparison is identity continuity evidence; it does not establish why the process instance changed.",
                ),
            )
        )

    return findings


def _matching_note_event_refs(
    graph: EvidenceGraph,
    item: ProjectionNoteCount,
) -> tuple[AnalysisEvidenceRef, ...]:
    refs = tuple(
        event_evidence_ref(stream_id=graph.stream_id, event_id=note.event_id)
        for note in graph.projection_notes
        if note.event_type is item.event_type and note.reason == item.reason
    )
    if not refs:
        raise AnalysisContractError(
            "projection-note drift references note absent from graph: "
            f"{item.event_type.value}:{item.reason}"
        )
    return refs


def _projection_note_findings(context: AnalysisContext) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []
    drift: GraphDrift = context.graph_drift

    for item in drift.projection_notes.added:
        reason = ReasonCode("PROJECTION_NOTE_COUNT_INCREASED")
        attributes = {
            "change": "count_increased",
            "event_type": item.event_type.value,
            "projection_reason": item.reason,
            "delta_count": item.count,
        }
        findings.append(
            _finding(
                reason_code=reason,
                summary=(
                    "A projection-note reason is represented more times in the later "
                    "graph than the earlier graph."
                ),
                evidence=_matching_note_event_refs(context.after_graph, item),
                attributes=attributes,
                limitations=(
                    "Projection-note drift describes a change in unprojected evidence semantics, not necessarily a change in underlying system behavior.",
                ),
            )
        )

    for item in drift.projection_notes.removed:
        reason = ReasonCode("PROJECTION_NOTE_COUNT_DECREASED")
        attributes = {
            "change": "count_decreased",
            "event_type": item.event_type.value,
            "projection_reason": item.reason,
            "delta_count": item.count,
        }
        findings.append(
            _finding(
                reason_code=reason,
                summary=(
                    "A projection-note reason is represented more times in the earlier "
                    "graph than the later graph."
                ),
                evidence=_matching_note_event_refs(context.before_graph, item),
                attributes=attributes,
                limitations=(
                    "Projection-note drift describes a change in unprojected evidence semantics, not necessarily a change in underlying system behavior.",
                ),
            )
        )

    return findings
