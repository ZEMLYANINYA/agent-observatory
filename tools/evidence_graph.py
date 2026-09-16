from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from agent_observatory.graph import EvidenceGraph, project_stream
from agent_observatory.storage import EventStore


DEFAULT_DB_PATH = Path(".local") / "agent-observatory.sqlite3"


def _resolve_stream_id(store: EventStore, requested: str | None) -> str:
    if requested is not None:
        if not requested.strip():
            raise ValueError("stream_id must be a non-empty string")
        return requested

    streams = store.list_stream_ids()
    if not streams:
        raise ValueError("EventStore contains no persisted streams")
    return streams[-1]


def _evidence_ids(value) -> str:
    return ",".join(str(ref.event_id) for ref in value) or "none"


def _print_show(graph: EvidenceGraph) -> None:
    node_counts = Counter(node.node_type for node in graph.nodes)
    edge_counts = Counter(edge.edge_type for edge in graph.edges)

    print(f"stream_id: {graph.stream_id}")
    print(f"nodes: {len(graph.nodes)}")
    for node_type in sorted(node_counts, key=lambda item: item.value):
        print(f"  {node_type.value:<24} {node_counts[node_type]}")

    print(f"edges: {len(graph.edges)}")
    for edge_type in sorted(edge_counts, key=lambda item: item.value):
        print(f"  {edge_type.value:<24} {edge_counts[edge_type]}")

    print(f"projection_notes: {len(graph.projection_notes)}")
    print(f"source_events: {len(graph.source_event_ids)}")
    if graph.source_event_ids:
        print(
            "source_event_id_range: "
            f"{graph.source_event_ids[0]}..{graph.source_event_ids[-1]}"
        )
    else:
        print("source_event_id_range: none")


def _print_nodes(graph: EvidenceGraph) -> None:
    print(f"stream_id: {graph.stream_id}")
    print("NODES:")
    if not graph.nodes:
        print("  none")
        return

    for node in graph.nodes:
        attributes = json.dumps(
            dict(node.attributes),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        print(
            f"  {node.node_type.value:<18} {node.node_id} "
            f"evidence={_evidence_ids(node.evidence)} attrs={attributes}"
        )


def _print_edges(graph: EvidenceGraph) -> None:
    print(f"stream_id: {graph.stream_id}")
    print("EDGES:")
    if not graph.edges:
        print("  none")
    else:
        for edge in graph.edges:
            attributes = json.dumps(
                dict(edge.attributes),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            print(
                f"  {edge.edge_type.value:<18} "
                f"{edge.source_node_id} -> {edge.target_node_id} "
                f"evidence={_evidence_ids(edge.evidence)} attrs={attributes}"
            )

    print("PROJECTION NOTES:")
    if not graph.projection_notes:
        print("  none")
    else:
        for note in graph.projection_notes:
            print(
                f"  event={note.event_id} "
                f"type={note.event_type.value} reason={note.reason}"
            )


def _evidence_ref_payload(ref) -> dict[str, object]:
    return {
        "event_id": ref.event_id,
        "event_type": ref.event_type.value,
        "observed_at": ref.observed_at,
        "source": ref.source,
        "stream_id": ref.stream_id,
    }


def _graph_payload(graph: EvidenceGraph) -> dict[str, object]:
    return {
        "stream_id": graph.stream_id,
        "source_event_ids": list(graph.source_event_ids),
        "nodes": [
            {
                "node_id": node.node_id,
                "node_type": node.node_type.value,
                "attributes": dict(node.attributes),
                "evidence": [
                    _evidence_ref_payload(ref)
                    for ref in node.evidence
                ],
            }
            for node in graph.nodes
        ],
        "edges": [
            {
                "edge_id": edge.edge_id,
                "edge_type": edge.edge_type.value,
                "source_node_id": edge.source_node_id,
                "target_node_id": edge.target_node_id,
                "attributes": dict(edge.attributes),
                "evidence": [
                    _evidence_ref_payload(ref)
                    for ref in edge.evidence
                ],
            }
            for edge in graph.edges
        ],
        "projection_notes": [
            {
                "event_id": note.event_id,
                "event_type": note.event_type.value,
                "reason": note.reason,
            }
            for note in graph.projection_notes
        ],
    }


def _print_json(graph: EvidenceGraph) -> None:
    print(
        json.dumps(
            _graph_payload(graph),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Build a read-only Evidence Graph v1 projection from one "
            "persisted EventStore stream."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Existing EventStore SQLite path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--stream-id",
        help="Stream to project. Defaults to the latest persisted stream.",
    )
    parser.add_argument(
        "command",
        choices=("show", "nodes", "edges", "json"),
        help="Projection view to print.",
    )
    args = parser.parse_args(argv)

    if not args.db.is_file():
        print(f"Graph inspection failed: database does not exist: {args.db}", file=sys.stderr)
        return 1

    try:
        store = EventStore(args.db, read_only=True)
        stream_id = _resolve_stream_id(store, args.stream_id)
        graph = project_stream(store, stream_id)
    except (KeyError, OSError, ValueError, RuntimeError) as exc:
        print(f"Graph inspection failed: {exc}", file=sys.stderr)
        return 1

    if args.command == "show":
        _print_show(graph)
    elif args.command == "nodes":
        _print_nodes(graph)
    elif args.command == "edges":
        _print_edges(graph)
    elif args.command == "json":
        _print_json(graph)
    else:
        raise RuntimeError(f"unsupported command: {args.command}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
