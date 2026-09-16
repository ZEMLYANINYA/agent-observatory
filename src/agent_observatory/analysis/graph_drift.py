from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from agent_observatory.graph import (
    EvidenceGraph,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    project_stream,
)
from agent_observatory.storage import EventStore, EventType


class GraphDriftComparisonError(RuntimeError):
    """Raised when two graph projections cannot be compared safely."""


class ProcessContinuityStatus(str, Enum):
    SAME_INSTANCE = "same_instance"
    REPLACED_INSTANCE = "replaced_instance"
    MIXED = "mixed"


@dataclass(frozen=True, slots=True)
class NodeAttributeChange:
    node_id: str
    node_type: GraphNodeType
    before_attributes: Mapping[str, object]
    after_attributes: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class NodeTypeDrift:
    node_type: GraphNodeType
    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[NodeAttributeChange, ...]
    unchanged: tuple[str, ...]

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)


@dataclass(frozen=True, slots=True)
class EdgeFact:
    edge_type: GraphEdgeType
    source_node_id: str
    target_node_id: str
    attributes: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class EdgeAttributeChange:
    edge_key: str
    edge_type: GraphEdgeType
    source_node_id: str
    target_node_id: str
    before_attributes: Mapping[str, object]
    after_attributes: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class EdgeTypeDrift:
    edge_type: GraphEdgeType
    added: tuple[EdgeFact, ...]
    removed: tuple[EdgeFact, ...]
    changed: tuple[EdgeAttributeChange, ...]
    unchanged_count: int
    ambiguous_keys: tuple[str, ...]

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed or self.ambiguous_keys)


@dataclass(frozen=True, slots=True)
class ProjectionNoteCount:
    event_type: EventType
    reason: str
    count: int


@dataclass(frozen=True, slots=True)
class ProjectionNoteDrift:
    added: tuple[ProjectionNoteCount, ...]
    removed: tuple[ProjectionNoteCount, ...]
    unchanged_count: int

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)


@dataclass(frozen=True, slots=True)
class ProcessIdentityContinuity:
    """Continuity observation for one PID slot seen in both projections.

    PID is not treated as process identity. The comparison is useful precisely
    because a shared PID can map to a different ``PID + started_at`` instance.
    """

    pid: int
    status: ProcessContinuityStatus
    before_instances: tuple[str, ...]
    after_instances: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GraphDrift:
    before_stream_id: str
    after_stream_id: str
    nodes: tuple[NodeTypeDrift, ...]
    edges: tuple[EdgeTypeDrift, ...]
    process_continuity: tuple[ProcessIdentityContinuity, ...]
    projection_notes: ProjectionNoteDrift

    @property
    def has_changes(self) -> bool:
        return (
            any(item.has_changes for item in self.nodes)
            or any(item.has_changes for item in self.edges)
            or self.projection_notes.has_changes
        )



def _canonical_mapping(value: Mapping[str, object]) -> str:
    return json.dumps(
        dict(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )



def _validate_node_id_types(graph: EvidenceGraph) -> None:
    seen: dict[str, GraphNodeType] = {}
    for node in graph.nodes:
        previous = seen.get(node.node_id)
        if previous is not None and previous is not node.node_type:
            raise GraphDriftComparisonError(
                f"node id {node.node_id!r} has multiple node types"
            )
        seen[node.node_id] = node.node_type



def _node_drift(
    before: EvidenceGraph,
    after: EvidenceGraph,
) -> tuple[NodeTypeDrift, ...]:
    before_global = {node.node_id: node.node_type for node in before.nodes}
    after_global = {node.node_id: node.node_type for node in after.nodes}
    for node_id in sorted(set(before_global) & set(after_global)):
        if before_global[node_id] is not after_global[node_id]:
            raise GraphDriftComparisonError(
                f"node id {node_id!r} changed type from "
                f"{before_global[node_id].value} to {after_global[node_id].value}"
            )

    results: list[NodeTypeDrift] = []
    for node_type in GraphNodeType:
        before_nodes = {
            node.node_id: node
            for node in before.nodes
            if node.node_type is node_type
        }
        after_nodes = {
            node.node_id: node
            for node in after.nodes
            if node.node_type is node_type
        }
        if not before_nodes and not after_nodes:
            continue

        before_ids = set(before_nodes)
        after_ids = set(after_nodes)
        added = tuple(sorted(after_ids - before_ids))
        removed = tuple(sorted(before_ids - after_ids))

        changed: list[NodeAttributeChange] = []
        unchanged: list[str] = []
        for node_id in sorted(before_ids & after_ids):
            before_node = before_nodes[node_id]
            after_node = after_nodes[node_id]
            if _canonical_mapping(before_node.attributes) == _canonical_mapping(
                after_node.attributes
            ):
                unchanged.append(node_id)
            else:
                changed.append(
                    NodeAttributeChange(
                        node_id=node_id,
                        node_type=node_type,
                        before_attributes=dict(before_node.attributes),
                        after_attributes=dict(after_node.attributes),
                    )
                )

        results.append(
            NodeTypeDrift(
                node_type=node_type,
                added=added,
                removed=removed,
                changed=tuple(changed),
                unchanged=tuple(unchanged),
            )
        )

    return tuple(results)



def _edge_group_key(edge: GraphEdge) -> tuple[str, str]:
    return edge.source_node_id, edge.target_node_id



def _edge_key_text(
    edge_type: GraphEdgeType,
    source_node_id: str,
    target_node_id: str,
) -> str:
    return f"{edge_type.value}:{source_node_id}->{target_node_id}"



def _edge_fact(edge: GraphEdge) -> EdgeFact:
    return EdgeFact(
        edge_type=edge.edge_type,
        source_node_id=edge.source_node_id,
        target_node_id=edge.target_node_id,
        attributes=dict(edge.attributes),
    )



def _edge_fact_sort_key(fact: EdgeFact) -> tuple[str, str, str]:
    return (
        fact.source_node_id,
        fact.target_node_id,
        _canonical_mapping(fact.attributes),
    )



def _edge_type_drift(
    edge_type: GraphEdgeType,
    before_edges: tuple[GraphEdge, ...],
    after_edges: tuple[GraphEdge, ...],
) -> EdgeTypeDrift:
    before_groups: dict[tuple[str, str], list[GraphEdge]] = defaultdict(list)
    after_groups: dict[tuple[str, str], list[GraphEdge]] = defaultdict(list)
    for edge in before_edges:
        before_groups[_edge_group_key(edge)].append(edge)
    for edge in after_edges:
        after_groups[_edge_group_key(edge)].append(edge)

    added: list[EdgeFact] = []
    removed: list[EdgeFact] = []
    changed: list[EdgeAttributeChange] = []
    ambiguous_keys: list[str] = []
    unchanged_count = 0

    for group_key in sorted(set(before_groups) | set(after_groups)):
        source_node_id, target_node_id = group_key
        before_group = before_groups.get(group_key, [])
        after_group = after_groups.get(group_key, [])

        before_by_attributes: dict[str, list[GraphEdge]] = defaultdict(list)
        after_by_attributes: dict[str, list[GraphEdge]] = defaultdict(list)
        for edge in before_group:
            before_by_attributes[_canonical_mapping(edge.attributes)].append(edge)
        for edge in after_group:
            after_by_attributes[_canonical_mapping(edge.attributes)].append(edge)

        before_remaining: list[GraphEdge] = []
        after_remaining: list[GraphEdge] = []
        for attributes_key in sorted(
            set(before_by_attributes) | set(after_by_attributes)
        ):
            before_items = before_by_attributes.get(attributes_key, [])
            after_items = after_by_attributes.get(attributes_key, [])
            matched = min(len(before_items), len(after_items))
            unchanged_count += matched
            before_remaining.extend(before_items[matched:])
            after_remaining.extend(after_items[matched:])

        if len(before_remaining) == 1 and len(after_remaining) == 1:
            before_edge = before_remaining[0]
            after_edge = after_remaining[0]
            changed.append(
                EdgeAttributeChange(
                    edge_key=_edge_key_text(
                        edge_type,
                        source_node_id,
                        target_node_id,
                    ),
                    edge_type=edge_type,
                    source_node_id=source_node_id,
                    target_node_id=target_node_id,
                    before_attributes=dict(before_edge.attributes),
                    after_attributes=dict(after_edge.attributes),
                )
            )
            continue

        if before_remaining and after_remaining:
            ambiguous_keys.append(
                _edge_key_text(edge_type, source_node_id, target_node_id)
            )

        removed.extend(_edge_fact(edge) for edge in before_remaining)
        added.extend(_edge_fact(edge) for edge in after_remaining)

    return EdgeTypeDrift(
        edge_type=edge_type,
        added=tuple(sorted(added, key=_edge_fact_sort_key)),
        removed=tuple(sorted(removed, key=_edge_fact_sort_key)),
        changed=tuple(sorted(changed, key=lambda item: item.edge_key)),
        unchanged_count=unchanged_count,
        ambiguous_keys=tuple(sorted(ambiguous_keys)),
    )



def _edge_drift(
    before: EvidenceGraph,
    after: EvidenceGraph,
) -> tuple[EdgeTypeDrift, ...]:
    results: list[EdgeTypeDrift] = []
    for edge_type in GraphEdgeType:
        before_edges = tuple(
            edge for edge in before.edges if edge.edge_type is edge_type
        )
        after_edges = tuple(
            edge for edge in after.edges if edge.edge_type is edge_type
        )
        if not before_edges and not after_edges:
            continue
        results.append(_edge_type_drift(edge_type, before_edges, after_edges))
    return tuple(results)



def _projection_note_drift(
    before: EvidenceGraph,
    after: EvidenceGraph,
) -> ProjectionNoteDrift:
    before_counts = Counter(
        (note.event_type, note.reason) for note in before.projection_notes
    )
    after_counts = Counter(
        (note.event_type, note.reason) for note in after.projection_notes
    )

    unchanged_count = sum((before_counts & after_counts).values())
    removed_counter = before_counts - after_counts
    added_counter = after_counts - before_counts

    def expand(counter: Counter[tuple[EventType, str]]) -> tuple[ProjectionNoteCount, ...]:
        return tuple(
            ProjectionNoteCount(
                event_type=event_type,
                reason=reason,
                count=count,
            )
            for (event_type, reason), count in sorted(
                counter.items(),
                key=lambda item: (item[0][0].value, item[0][1]),
            )
            if count > 0
        )

    return ProjectionNoteDrift(
        added=expand(added_counter),
        removed=expand(removed_counter),
        unchanged_count=unchanged_count,
    )



def _process_nodes_by_pid(
    nodes: Iterable[GraphNode],
) -> dict[int, set[str]]:
    by_pid: dict[int, set[str]] = defaultdict(set)
    for node in nodes:
        if node.node_type is not GraphNodeType.PROCESS_INSTANCE:
            continue
        pid = node.attributes.get("pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            continue
        by_pid[pid].add(node.node_id)
    return by_pid



def _process_continuity(
    before: EvidenceGraph,
    after: EvidenceGraph,
) -> tuple[ProcessIdentityContinuity, ...]:
    before_by_pid = _process_nodes_by_pid(before.nodes)
    after_by_pid = _process_nodes_by_pid(after.nodes)
    results: list[ProcessIdentityContinuity] = []

    for pid in sorted(set(before_by_pid) & set(after_by_pid)):
        before_instances = before_by_pid[pid]
        after_instances = after_by_pid[pid]
        shared = before_instances & after_instances

        if before_instances == after_instances:
            status = ProcessContinuityStatus.SAME_INSTANCE
        elif not shared:
            status = ProcessContinuityStatus.REPLACED_INSTANCE
        else:
            status = ProcessContinuityStatus.MIXED

        results.append(
            ProcessIdentityContinuity(
                pid=pid,
                status=status,
                before_instances=tuple(sorted(before_instances)),
                after_instances=tuple(sorted(after_instances)),
            )
        )

    return tuple(results)



def compare_graphs(
    before: EvidenceGraph,
    after: EvidenceGraph,
) -> GraphDrift:
    """Compare two evidence-graph projections without comparing provenance ids.

    The result describes structural change. It does not label changes as normal,
    anomalous, causal, malicious, or important.
    """

    _validate_node_id_types(before)
    _validate_node_id_types(after)

    return GraphDrift(
        before_stream_id=before.stream_id,
        after_stream_id=after.stream_id,
        nodes=_node_drift(before, after),
        edges=_edge_drift(before, after),
        process_continuity=_process_continuity(before, after),
        projection_notes=_projection_note_drift(before, after),
    )



def compare_graph_streams(
    store: EventStore,
    before_stream_id: str,
    after_stream_id: str,
) -> GraphDrift:
    """Project two persisted streams and compare their derived graph structure."""

    before = project_stream(store, before_stream_id)
    after = project_stream(store, after_stream_id)
    return compare_graphs(before, after)
