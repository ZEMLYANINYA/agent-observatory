from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agent_observatory.analysis import (
    AnalysisResult,
    GraphDriftObservationsPass,
    build_analysis_context,
    run_analysis_passes,
)
from agent_observatory.storage import EventStore


DEFAULT_DB_PATH = Path(".local") / "agent-observatory.sqlite3"


def _resolve_stream_pair(
    store: EventStore,
    before_stream_id: str | None,
    after_stream_id: str | None,
) -> tuple[str, str]:
    if (before_stream_id is None) != (after_stream_id is None):
        raise ValueError("supply either zero stream ids or exactly two")

    if before_stream_id is not None and after_stream_id is not None:
        if not before_stream_id.strip() or not after_stream_id.strip():
            raise ValueError("stream ids must be non-empty strings")
        return before_stream_id, after_stream_id

    streams = store.list_stream_ids()
    if len(streams) < 2:
        raise ValueError("analysis requires at least two persisted streams")
    return streams[-2], streams[-1]


def _analysis_result(
    store: EventStore,
    before_stream_id: str,
    after_stream_id: str,
) -> AnalysisResult:
    context = build_analysis_context(store, before_stream_id, after_stream_id)
    return run_analysis_passes(context, (GraphDriftObservationsPass(),))


def _print_show(result: AnalysisResult, *, details: bool) -> None:
    print(f"before: {result.before_stream_id}")
    print(f"after:  {result.after_stream_id}")
    print()
    print("ANALYSIS RUN:")
    print("  deterministic descriptive findings only; no severity/confidence/verdict")
    print(f"findings: {result.finding_count}")

    for pass_result in result.pass_results:
        print(
            f"  {pass_result.pass_id} v{pass_result.pass_version} "
            f"findings={len(pass_result.findings)}"
        )
        if not details:
            continue

        for finding in pass_result.findings:
            print(f"    [{finding.reason_code}] {finding.finding_id}")
            print(f"      {finding.summary}")
            print(
                "      attributes="
                + json.dumps(
                    dict(finding.attributes),
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            )
            for evidence in finding.evidence:
                event_ids = ",".join(str(event_id) for event_id in evidence.event_ids)
                print(
                    "      evidence="
                    f"{evidence.layer.value}:{evidence.reference_id} "
                    f"stream={evidence.stream_id} events={event_ids}"
                )
            for limitation in finding.limitations:
                print(f"      limitation={limitation}")


def _finding_payload(finding) -> dict[str, object]:
    return {
        "finding_id": finding.finding_id,
        "pass_id": finding.pass_id,
        "pass_version": str(finding.pass_version),
        "reason_code": finding.reason_code.value,
        "summary": finding.summary,
        "evidence": [
            {
                "layer": evidence.layer.value,
                "reference_id": evidence.reference_id,
                "stream_id": evidence.stream_id,
                "event_ids": list(evidence.event_ids),
            }
            for evidence in finding.evidence
        ],
        "limitations": list(finding.limitations),
        "attributes": dict(finding.attributes),
    }


def _result_payload(result: AnalysisResult) -> dict[str, object]:
    return {
        "before_stream_id": result.before_stream_id,
        "after_stream_id": result.after_stream_id,
        "finding_count": result.finding_count,
        "pass_results": [
            {
                "pass_id": pass_result.pass_id,
                "pass_version": str(pass_result.pass_version),
                "finding_count": len(pass_result.findings),
                "findings": [
                    _finding_payload(finding)
                    for finding in pass_result.findings
                ],
            }
            for pass_result in result.pass_results
        ],
    }


def _print_json(result: AnalysisResult) -> None:
    print(
        json.dumps(
            _result_payload(result),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
            allow_nan=False,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run deterministic read-only Analysis Pass v1 over two persisted "
            "EventStore streams."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Existing EventStore SQLite path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--before",
        dest="before_stream_id",
        help="Earlier stream id. Omit with --after to use the latest two streams.",
    )
    parser.add_argument(
        "--after",
        dest="after_stream_id",
        help="Later stream id. Omit with --before to use the latest two streams.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    show_parser = subparsers.add_parser("show", help="Show analysis findings.")
    show_parser.add_argument(
        "--details",
        action="store_true",
        help="Print finding attributes, evidence references, and limitations.",
    )
    subparsers.add_parser("json", help="Print deterministic machine-readable output.")

    args = parser.parse_args(argv)

    if not args.db.is_file():
        print(f"Analysis failed: database does not exist: {args.db}", file=sys.stderr)
        return 1

    try:
        store = EventStore(args.db, read_only=True)
        before_stream_id, after_stream_id = _resolve_stream_pair(
            store,
            args.before_stream_id,
            args.after_stream_id,
        )
        result = _analysis_result(store, before_stream_id, after_stream_id)
    except (KeyError, OSError, RuntimeError, ValueError) as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 1

    if args.command == "show":
        _print_show(result, details=args.details)
    elif args.command == "json":
        _print_json(result)
    else:
        raise RuntimeError(f"unsupported command: {args.command}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
