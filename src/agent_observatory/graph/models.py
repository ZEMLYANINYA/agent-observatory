from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from agent_observatory.storage import EventType


class GraphNodeType(str, Enum):
    APPLICATION = "APPLICATION"
    PROCESS_INSTANCE = "PROCESS_INSTANCE"
    FILE_IDENTITY = "FILE_IDENTITY"
    REMOTE_ENDPOINT = "REMOTE_ENDPOINT"


class GraphEdgeType(str, Enum):
    DISCOVERED_AS = "DISCOVERED_AS"
    PARENT_OF = "PARENT_OF"
    EXECUTED_FROM = "EXECUTED_FROM"
    OBSERVED_TCP_TO = "OBSERVED_TCP_TO"


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """Provenance pointer from a derived graph object back to one stored event."""

    event_id: int
    event_type: EventType
    observed_at: float
    source: str
    stream_id: str | None


@dataclass(frozen=True, slots=True)
class GraphNode:
    """One identity-bearing entity projected from EventStore evidence."""

    node_id: str
    node_type: GraphNodeType
    attributes: Mapping[str, object]
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class GraphEdge:
    """One evidence-backed relation. The edge itself is never causal by default."""

    edge_id: str
    edge_type: GraphEdgeType
    source_node_id: str
    target_node_id: str
    attributes: Mapping[str, object]
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True, slots=True)
class GraphProjectionNote:
    """Explicit reason why some event semantics were not represented as an edge."""

    event_id: int
    event_type: EventType
    reason: str


@dataclass(frozen=True, slots=True)
class EvidenceGraph:
    """Deterministic read-only projection of one EventStore stream."""

    stream_id: str
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]
    projection_notes: tuple[GraphProjectionNote, ...]

    @property
    def source_event_ids(self) -> tuple[int, ...]:
        event_ids = {
            ref.event_id
            for node in self.nodes
            for ref in node.evidence
        }
        event_ids.update(
            ref.event_id
            for edge in self.edges
            for ref in edge.evidence
        )
        event_ids.update(note.event_id for note in self.projection_notes)
        return tuple(sorted(event_ids))
