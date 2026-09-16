from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from uuid import uuid4

from agent_observatory.evidence import (
    CollectorStatus,
    ServiceExposureCapture,
    append_service_exposure_capture,
    collect_service_exposure_capture,
)
from agent_observatory.storage import EventStore, EventType, StoredEvent


DEFAULT_DB_PATH = Path(".local") / "agent-observatory.sqlite3"
DEFAULT_SOURCE = "service-exposure-live-capture"


def _stream_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"service-exposure:{timestamp}:{uuid4().hex[:8]}"


def _collect_live_service_exposure_capture(
    *,
    include_docker: bool,
) -> ServiceExposureCapture:
    return collect_service_exposure_capture(
        include_docker=include_docker,
        include_firewall=True,
        include_firewall_rules=True,
    )


def capture_into_store(
    store: EventStore,
    *,
    source: str,
    stream_id: str,
    include_docker: bool = True,
    capture_provider: Callable[..., ServiceExposureCapture] = _collect_live_service_exposure_capture,
) -> tuple[ServiceExposureCapture, tuple[StoredEvent, ...]]:
    capture = capture_provider(include_docker=include_docker)
    appended = append_service_exposure_capture(
        store,
        capture,
        source=source,
        stream_id=stream_id,
    )
    return capture, appended


def _endpoint(address: object, port: object) -> str:
    address_text = str(address)
    if ":" in address_text and not address_text.startswith("["):
        return f"[{address_text}]:{port}"
    return f"{address_text}:{port}"


def _print_summary(
    store: EventStore,
    events: tuple[StoredEvent, ...],
    capture: ServiceExposureCapture,
    *,
    stream_id: str,
) -> None:
    counts = Counter(event.event_type for event in events)

    print(f"EventStore: {store.path}")
    print(f"journal_mode: {store.journal_mode()}")
    print(f"stream_id: {stream_id}")
    print(f"events_appended: {len(events)}")
    if events:
        print(f"event_id_range: {events[0].event_id}..{events[-1].event_id}")
    else:
        print("event_id_range: none")

    print()
    print("COLLECTORS:")
    for report in capture.collector_reports:
        count_text = "unknown" if report.record_count is None else str(report.record_count)
        line = (
            f"  {report.collector:<26} "
            f"status={report.status.value:<9} records={count_text}"
        )
        if report.error_type is not None:
            line += f" error={report.error_type}: {report.error_message}"
        print(line)

    print()
    print("EVIDENCE COUNTS:")
    for event_type in (
        EventType.TCP_LISTENER_OBSERVED,
        EventType.WINDOWS_SERVICE_OBSERVED,
        EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED,
        EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
        EventType.WINDOWS_FIREWALL_RULE_OBSERVED,
        EventType.DOCKER_PORT_PUBLISHED,
        EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
    ):
        print(f"  {event_type.value:<36} {counts.get(event_type, 0)}")

    scope_counts: Counter[str] = Counter()
    listener_attribution_counts: Counter[str] = Counter()
    service_attribution_counts: Counter[str] = Counter()
    network_category_counts: Counter[str] = Counter()
    firewall_rule_enabled_counts: Counter[str] = Counter()
    firewall_rule_action_counts: Counter[str] = Counter()
    firewall_rule_profile_counts: Counter[str] = Counter()

    for event in events:
        if event.event_type in (
            EventType.TCP_LISTENER_OBSERVED,
            EventType.DOCKER_PORT_PUBLISHED,
        ):
            scope_counts[str(event.payload.get("bind_scope"))] += 1
        if event.event_type is EventType.TCP_LISTENER_OBSERVED:
            listener_attribution_counts[str(event.payload.get("attribution_state"))] += 1
        if event.event_type is EventType.WINDOWS_SERVICE_OBSERVED:
            service_attribution_counts[
                str(event.payload.get("process_attribution_state"))
            ] += 1
        if event.event_type is EventType.WINDOWS_NETWORK_PROFILE_OBSERVED:
            network_category_counts[str(event.payload.get("network_category"))] += 1
        if event.event_type is EventType.WINDOWS_FIREWALL_RULE_OBSERVED:
            firewall_rule_enabled_counts[
                "enabled" if event.payload.get("enabled") is True else "disabled"
            ] += 1
            firewall_rule_action_counts[str(event.payload.get("action"))] += 1
            firewall_rule_profile_counts[str(event.payload.get("profile"))] += 1

    print()
    print("BIND SCOPE COUNTS:")
    if not scope_counts:
        print("  none")
    else:
        for scope in sorted(scope_counts):
            print(f"  {scope:<12} {scope_counts[scope]}")

    print()
    print("LISTENER ATTRIBUTION COUNTS:")
    if not listener_attribution_counts:
        print("  none")
    else:
        for state in sorted(listener_attribution_counts):
            print(f"  {state:<12} {listener_attribution_counts[state]}")

    print()
    print("SERVICE PROCESS ATTRIBUTION COUNTS:")
    if not service_attribution_counts:
        print("  none")
    else:
        for state in sorted(service_attribution_counts):
            print(f"  {state:<12} {service_attribution_counts[state]}")

    print()
    print("NETWORK CATEGORY COUNTS:")
    if not network_category_counts:
        print("  none")
    else:
        for category in sorted(network_category_counts):
            print(f"  {category:<12} {network_category_counts[category]}")

    print()
    print("FIREWALL RULE SUMMARY:")
    if not firewall_rule_enabled_counts:
        print("  none observed")
    else:
        print("  enabled state:")
        for state in ("enabled", "disabled"):
            if firewall_rule_enabled_counts[state]:
                print(f"    {state:<10} {firewall_rule_enabled_counts[state]}")
        print("  actions:")
        for action in sorted(firewall_rule_action_counts):
            print(f"    {action:<18} {firewall_rule_action_counts[action]}")
        print("  profile scopes:")
        for profile in sorted(firewall_rule_profile_counts):
            print(f"    {profile:<28} {firewall_rule_profile_counts[profile]}")

    print()
    print("SEMANTICS:")
    print("  bind scope is address topology only")
    print("  listener process attribution requires a stable bracketed process instance")
    print("  service process attribution also requires post-service process verification")
    print("  firewall profile defaults are context, not per-listener allow/block verdicts")
    print("  network category describes interface profile assignment only")
    print("  firewall rules are source facts; no listener applicability is inferred")
    print("  no remote reachability, authentication, or exploitability is inferred")
    if capture.has_failures:
        print("  capture is partial because at least one requested collector failed")


def _print_details(events: tuple[StoredEvent, ...]) -> None:
    listener_events = tuple(
        event
        for event in events
        if event.event_type is EventType.TCP_LISTENER_OBSERVED
    )
    service_events = tuple(
        event
        for event in events
        if event.event_type is EventType.WINDOWS_SERVICE_OBSERVED
    )
    firewall_events = tuple(
        event
        for event in events
        if event.event_type is EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED
    )
    network_profile_events = tuple(
        event
        for event in events
        if event.event_type is EventType.WINDOWS_NETWORK_PROFILE_OBSERVED
    )
    firewall_rule_events = tuple(
        event
        for event in events
        if event.event_type is EventType.WINDOWS_FIREWALL_RULE_OBSERVED
    )
    docker_events = tuple(
        event
        for event in events
        if event.event_type is EventType.DOCKER_PORT_PUBLISHED
    )

    print()
    print("TCP LISTENERS:")
    if not listener_events:
        print("  none observed")
    else:
        for event in listener_events:
            line = (
                "  "
                f"{_endpoint(event.payload.get('local_address'), event.payload.get('local_port'))} "
                f"scope={event.payload.get('bind_scope')} "
                f"owner_pid={event.payload.get('owner_pid')} "
                f"attribution={event.payload.get('attribution_state')} "
                f"owner_basis={event.payload.get('owner_identity_basis')}"
            )
            process = event.payload.get("process")
            if isinstance(process, dict):
                line += (
                    f" process={process.get('pid')}@{process.get('started_at')}"
                    f" name={event.payload.get('process_name') or '?'}"
                    f" path={event.payload.get('executable_path') or '?'}"
                )
            else:
                line += f" reason={event.payload.get('attribution_reason') or '?'}"
            print(line)

    print()
    print("WINDOWS SERVICES FOR LISTENER PROCESSES:")
    if not service_events:
        print("  none observed")
    else:
        for event in service_events:
            line = (
                "  "
                f"{event.payload.get('service_name')} "
                f"display={event.payload.get('display_name')} "
                f"pid={event.payload.get('process_id')} "
                f"state={event.payload.get('state')} "
                f"start_mode={event.payload.get('start_mode')} "
                f"attribution={event.payload.get('process_attribution_state')}"
            )
            process = event.payload.get("process")
            if isinstance(process, dict):
                line += (
                    f" process={process.get('pid')}@{process.get('started_at')}"
                    f" name={event.payload.get('process_name') or '?'}"
                    f" path={event.payload.get('executable_path') or '?'}"
                )
            else:
                line += (
                    " reason="
                    f"{event.payload.get('process_attribution_reason') or '?'}"
                )
            print(line)

    print()
    print("WINDOWS FIREWALL PROFILES:")
    if not firewall_events:
        print("  none observed")
    else:
        for event in firewall_events:
            print(
                "  "
                f"{event.payload.get('profile_name')} "
                f"enabled={event.payload.get('enabled')} "
                f"default_inbound={event.payload.get('default_inbound_action')} "
                f"default_outbound={event.payload.get('default_outbound_action')} "
                f"allow_inbound_rules={event.payload.get('allow_inbound_rules')} "
                f"allow_local_rules={event.payload.get('allow_local_firewall_rules')}"
            )

    print()
    print("WINDOWS NETWORK PROFILES:")
    if not network_profile_events:
        print("  none observed")
    else:
        for event in network_profile_events:
            print(
                "  "
                f"interface={event.payload.get('interface_alias')} "
                f"index={event.payload.get('interface_index')} "
                f"name={event.payload.get('name')} "
                f"category={event.payload.get('network_category')} "
                f"ipv4={event.payload.get('ipv4_connectivity')} "
                f"ipv6={event.payload.get('ipv6_connectivity')}"
            )

    print()
    print("WINDOWS FIREWALL RULES:")
    if not firewall_rule_events:
        print("  none observed")
    else:
        print(
            f"  {len(firewall_rule_events)} rule facts persisted; "
            "individual rules are intentionally not dumped by this command"
        )
        print("  use the filtered rule/correlation inspector in the next layer")

    print()
    print("DOCKER PUBLISHED PORTS:")
    if not docker_events:
        print("  none observed")
    else:
        for event in docker_events:
            container = event.payload.get("container")
            if isinstance(container, dict):
                name = container.get("name")
                image = container.get("image")
            else:
                name = None
                image = None
            print(
                "  "
                f"{name or '?'} "
                f"host={_endpoint(event.payload.get('host_address'), event.payload.get('host_port'))} "
                f"-> {event.payload.get('protocol')}/"
                f"{event.payload.get('container_port')} "
                f"scope={event.payload.get('bind_scope')} "
                f"image={image or '?'}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Capture point-in-time Windows TCP listener, listener-service, firewall "
            "context/rule, and Docker published-port evidence into the append-only "
            "EventStore without inferring reachability."
        )
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"EventStore SQLite path (default: {DEFAULT_DB_PATH})",
    )
    parser.add_argument(
        "--source",
        default=DEFAULT_SOURCE,
        help=f"Evidence source label (default: {DEFAULT_SOURCE})",
    )
    parser.add_argument(
        "--stream-id",
        help="Explicit stream id. A unique id is generated when omitted.",
    )
    parser.add_argument(
        "--skip-docker",
        action="store_true",
        help="Explicitly skip Docker published-port collection; manifest records skipped.",
    )
    parser.add_argument(
        "--details",
        action="store_true",
        help=(
            "Print observed listener, Windows service, firewall/network profile, "
            "firewall rule summary, and Docker publication facts."
        ),
    )
    args = parser.parse_args(argv)

    stream_id = args.stream_id or _stream_id()

    try:
        store = EventStore(args.db)
        capture, appended = capture_into_store(
            store,
            source=args.source,
            stream_id=stream_id,
            include_docker=not args.skip_docker,
        )
    except Exception as exc:
        print(f"Capture failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    persisted = store.read_events(stream_id=stream_id)
    if tuple(event.event_id for event in persisted) != tuple(
        event.event_id for event in appended
    ):
        print(
            "Capture failed: persisted stream does not match appended event ids",
            file=sys.stderr,
        )
        return 3

    manifests = tuple(
        event
        for event in persisted
        if event.event_type is EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST
    )
    if len(manifests) != 1:
        print(
            "Capture failed: persisted stream must contain exactly one capture manifest",
            file=sys.stderr,
        )
        return 3

    _print_summary(store, persisted, capture, stream_id=stream_id)
    if args.details:
        _print_details(persisted)

    if capture.has_failures:
        return 2
    if any(
        report.status not in (CollectorStatus.SUCCEEDED, CollectorStatus.SKIPPED)
        for report in capture.collector_reports
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
