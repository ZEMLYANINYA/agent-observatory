from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PureWindowsPath
from typing import Iterable

from agent_observatory.storage import EventStore, EventType, StoredEvent


class FirewallCandidateStatus(str, Enum):
    CANDIDATE_MATCH = "CANDIDATE_MATCH"
    NO_CANDIDATE = "NO_CANDIDATE"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class FirewallRuleCandidate:
    rule_event_id: int
    rule_name: str
    display_name: str
    action: str
    profile: str
    compatible_dimensions: tuple[str, ...]
    unknown_dimensions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ListenerFirewallCandidates:
    listener_event_id: int
    local_address: str
    local_port: int
    owner_pid: int
    status: FirewallCandidateStatus
    candidates: tuple[FirewallRuleCandidate, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FirewallCandidateCorrelation:
    stream_id: str
    active_network_categories: tuple[str, ...]
    listeners: tuple[ListenerFirewallCandidates, ...]


@dataclass(frozen=True, slots=True)
class _DimensionResult:
    compatible: bool
    known: bool


_ANY_VALUES = {"any", "*", "all"}
_TCP_VALUES = {"tcp", "6"}
_SPECIAL_PORT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
_FIREWALL_RULE_V2_FIELDS = {
    "owner",
    "primary_status",
    "status",
    "loose_source_mapping",
    "local_only_mapping",
    "icmp_types",
    "dynamic_targets",
    "authentication",
    "encryption",
    "override_block_rules",
    "local_users",
    "remote_users",
    "remote_machines",
}


def _strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(item) for item in value if item is not None)
    if isinstance(value, tuple):
        return tuple(str(item) for item in value if item is not None)
    return (str(value),)


def _tokens(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        for token in value.split(","):
            stripped = token.strip()
            if stripped:
                result.append(stripped)
    return tuple(result)


def _has_any(values: Iterable[str]) -> bool:
    return any(value.strip().casefold() in _ANY_VALUES for value in values)


def _profile_result(rule_profile: str, active_categories: tuple[str, ...]) -> _DimensionResult:
    tokens = tuple(item.casefold() for item in _tokens((rule_profile,)))
    if not tokens or any(item in _ANY_VALUES for item in tokens):
        return _DimensionResult(True, True)
    if not active_categories:
        return _DimensionResult(True, False)
    active = {item.casefold() for item in active_categories}
    return _DimensionResult(bool(active & set(tokens)), True)


def _protocol_result(values: tuple[str, ...]) -> _DimensionResult:
    tokens = tuple(item.casefold() for item in _tokens(values))
    if not tokens:
        return _DimensionResult(True, False)
    if any(item in _ANY_VALUES for item in tokens):
        return _DimensionResult(True, True)
    return _DimensionResult(any(item in _TCP_VALUES for item in tokens), True)


def _port_result(values: tuple[str, ...], port: int) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens:
        return _DimensionResult(True, False)
    if _has_any(tokens):
        return _DimensionResult(True, True)

    saw_unknown = False
    for token in tokens:
        if token.isdigit():
            if int(token) == port:
                return _DimensionResult(True, True)
            continue
        if "-" in token:
            left, right = token.split("-", 1)
            if left.strip().isdigit() and right.strip().isdigit():
                if int(left) <= port <= int(right):
                    return _DimensionResult(True, True)
                continue
        if _SPECIAL_PORT_RE.fullmatch(token):
            saw_unknown = True
        else:
            saw_unknown = True

    if saw_unknown:
        return _DimensionResult(True, False)
    return _DimensionResult(False, True)


def _address_result(values: tuple[str, ...], local_address: str) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens:
        return _DimensionResult(True, False)
    if _has_any(tokens):
        return _DimensionResult(True, True)

    if local_address in {"0.0.0.0", "::", "::0", "*"}:
        return _DimensionResult(True, False)

    try:
        listener_ip = ipaddress.ip_address(local_address)
    except ValueError:
        return _DimensionResult(True, False)

    saw_unknown = False
    for token in tokens:
        lowered = token.casefold()
        if lowered in {"localsubnet", "dns", "dhcp", "wins", "defaultgateway"}:
            saw_unknown = True
            continue
        try:
            if "/" in token:
                if listener_ip in ipaddress.ip_network(token, strict=False):
                    return _DimensionResult(True, True)
                continue
            if "-" in token:
                left, right = token.split("-", 1)
                start = ipaddress.ip_address(left.strip())
                end = ipaddress.ip_address(right.strip())
                if start.version == listener_ip.version == end.version and start <= listener_ip <= end:
                    return _DimensionResult(True, True)
                continue
            if listener_ip == ipaddress.ip_address(token):
                return _DimensionResult(True, True)
        except ValueError:
            saw_unknown = True

    if saw_unknown:
        return _DimensionResult(True, False)
    return _DimensionResult(False, True)


def _normalize_windows_path(value: str) -> str:
    return str(PureWindowsPath(value)).replace("/", "\\").casefold()


def _program_result(
    values: tuple[str, ...],
    executable_path: str | None,
    process_name: str | None,
) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens or _has_any(tokens):
        return _DimensionResult(True, True)

    if process_name and process_name.casefold() == "system":
        if any(token.casefold() == "system" for token in tokens):
            return _DimensionResult(True, True)

    if not executable_path:
        return _DimensionResult(True, False)

    executable = _normalize_windows_path(executable_path)
    saw_unknown = False
    for token in tokens:
        if "%" in token or "*" in token or "?" in token:
            saw_unknown = True
            continue
        if _normalize_windows_path(token) == executable:
            return _DimensionResult(True, True)

    if saw_unknown:
        return _DimensionResult(True, False)
    return _DimensionResult(False, True)


def _service_result(values: tuple[str, ...], service_names: tuple[str, ...]) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens or _has_any(tokens):
        return _DimensionResult(True, True)
    if not service_names:
        return _DimensionResult(True, False)
    expected = {item.casefold() for item in tokens}
    observed = {item.casefold() for item in service_names}
    return _DimensionResult(bool(expected & observed), True)


def _remote_scope_result(values: tuple[str, ...]) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens or _has_any(tokens):
        return _DimensionResult(True, True)
    return _DimensionResult(True, False)


def _interface_alias_result(values: tuple[str, ...], active_aliases: tuple[str, ...]) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens or _has_any(tokens):
        return _DimensionResult(True, True)
    if not active_aliases:
        return _DimensionResult(True, False)
    expected = {item.casefold() for item in tokens}
    active = {item.casefold() for item in active_aliases}
    return _DimensionResult(bool(expected & active), True)


def _interface_type_result(values: tuple[str, ...]) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens or _has_any(tokens):
        return _DimensionResult(True, True)
    return _DimensionResult(True, False)


def _package_result(values: tuple[str, ...]) -> _DimensionResult:
    tokens = _tokens(values)
    if not tokens or _has_any(tokens):
        return _DimensionResult(True, True)
    return _DimensionResult(True, False)


def _rule_identity_result(value: object) -> _DimensionResult:
    if value is None:
        return _DimensionResult(True, True)
    text = str(value).strip()
    if not text or text.casefold() in _ANY_VALUES:
        return _DimensionResult(True, True)
    return _DimensionResult(True, False)


def _constraint_result(
    values: tuple[str, ...],
    *,
    unrestricted: frozenset[str] = frozenset(),
) -> _DimensionResult:
    tokens = tuple(item.casefold() for item in _tokens(values))
    if not tokens or any(item in _ANY_VALUES for item in tokens):
        return _DimensionResult(True, True)
    if unrestricted and all(item in unrestricted for item in tokens):
        return _DimensionResult(True, True)
    return _DimensionResult(True, False)


def _mapping_flag_result(value: object) -> _DimensionResult:
    if value is None or value is False:
        return _DimensionResult(True, True)
    if value is True:
        return _DimensionResult(True, False)
    return _DimensionResult(True, False)


def _rule_status_result(value: object) -> _DimensionResult:
    if value is None:
        return _DimensionResult(True, False)
    text = str(value).strip().casefold()
    if text in {"ok"}:
        return _DimensionResult(True, True)
    return _DimensionResult(True, False)


def _condition_surface_result(rule: StoredEvent) -> _DimensionResult:
    if rule.event_version < 2:
        return _DimensionResult(True, False)
    if not _FIREWALL_RULE_V2_FIELDS.issubset(rule.payload):
        return _DimensionResult(True, False)
    return _DimensionResult(True, True)


def _service_names_by_pid(events: tuple[StoredEvent, ...]) -> dict[int, tuple[str, ...]]:
    names: dict[int, set[str]] = {}
    for event in events:
        if event.event_type is not EventType.WINDOWS_SERVICE_OBSERVED:
            continue
        pid = event.payload.get("process_id")
        name = event.payload.get("service_name")
        if isinstance(pid, int) and not isinstance(pid, bool) and isinstance(name, str) and name:
            names.setdefault(pid, set()).add(name)
    return {pid: tuple(sorted(values, key=str.casefold)) for pid, values in names.items()}


def _candidate_for_rule(
    listener: StoredEvent,
    rule: StoredEvent,
    *,
    active_categories: tuple[str, ...],
    active_aliases: tuple[str, ...],
    service_names: tuple[str, ...],
) -> FirewallRuleCandidate | None:
    payload = rule.payload
    if payload.get("enabled") is not True:
        return None
    if str(payload.get("direction", "")).casefold() != "inbound":
        return None

    local_address = str(listener.payload.get("local_address"))
    local_port = int(listener.payload.get("local_port"))
    executable_path = listener.payload.get("executable_path")
    process_name = listener.payload.get("process_name")

    dimensions = {
        "RULE_CONDITION_SURFACE": _condition_surface_result(rule),
        "RULE_STATUS": _rule_status_result(payload.get("primary_status")),
        "PROFILE": _profile_result(str(payload.get("profile", "")), active_categories),
        "PROTOCOL": _protocol_result(_strings(payload.get("protocol"))),
        "LOCAL_PORT": _port_result(_strings(payload.get("local_ports")), local_port),
        "LOCAL_ADDRESS": _address_result(_strings(payload.get("local_addresses")), local_address),
        "PROGRAM": _program_result(
            _strings(payload.get("programs")),
            executable_path if isinstance(executable_path, str) else None,
            process_name if isinstance(process_name, str) else None,
        ),
        "PACKAGE": _package_result(_strings(payload.get("packages"))),
        "SERVICE": _service_result(_strings(payload.get("services")), service_names),
        "OWNER": _rule_identity_result(payload.get("owner")),
        "REMOTE_PORT": _remote_scope_result(_strings(payload.get("remote_ports"))),
        "REMOTE_ADDRESS": _remote_scope_result(_strings(payload.get("remote_addresses"))),
        "INTERFACE_ALIAS": _interface_alias_result(
            _strings(payload.get("interface_aliases")), active_aliases
        ),
        "INTERFACE_TYPE": _interface_type_result(_strings(payload.get("interface_types"))),
        "DYNAMIC_TARGET": _constraint_result(_strings(payload.get("dynamic_targets"))),
        "ICMP_TYPE": _constraint_result(_strings(payload.get("icmp_types"))),
        "AUTHENTICATION": _constraint_result(
            _strings(payload.get("authentication")),
            unrestricted=frozenset({"notrequired", "none"}),
        ),
        "ENCRYPTION": _constraint_result(
            _strings(payload.get("encryption")),
            unrestricted=frozenset({"notrequired", "none"}),
        ),
        "OVERRIDE_BLOCK_RULES": _constraint_result(
            _strings(payload.get("override_block_rules")),
            unrestricted=frozenset({"false", "none"}),
        ),
        "LOCAL_USER": _constraint_result(_strings(payload.get("local_users"))),
        "REMOTE_USER": _constraint_result(_strings(payload.get("remote_users"))),
        "REMOTE_MACHINE": _constraint_result(_strings(payload.get("remote_machines"))),
        "LOOSE_SOURCE_MAPPING": _mapping_flag_result(payload.get("loose_source_mapping")),
        "LOCAL_ONLY_MAPPING": _mapping_flag_result(payload.get("local_only_mapping")),
    }

    if any(result.known and not result.compatible for result in dimensions.values()):
        return None

    compatible = tuple(
        name for name, result in sorted(dimensions.items()) if result.known and result.compatible
    )
    unknown = tuple(
        name for name, result in sorted(dimensions.items()) if not result.known
    )

    return FirewallRuleCandidate(
        rule_event_id=rule.event_id,
        rule_name=str(payload.get("name", "")),
        display_name=str(payload.get("display_name", "")),
        action=str(payload.get("action", "")),
        profile=str(payload.get("profile", "")),
        compatible_dimensions=compatible,
        unknown_dimensions=unknown,
    )


def correlate_firewall_rule_candidates(
    store: EventStore,
    stream_id: str,
) -> FirewallCandidateCorrelation:
    if not isinstance(stream_id, str) or not stream_id.strip():
        raise ValueError("stream_id must be a non-empty string")

    events = store.read_events(stream_id=stream_id)
    if not events:
        raise ValueError(f"stream not found or empty: {stream_id}")

    listeners = tuple(
        event for event in events if event.event_type is EventType.TCP_LISTENER_OBSERVED
    )
    rules = tuple(
        event for event in events if event.event_type is EventType.WINDOWS_FIREWALL_RULE_OBSERVED
    )
    network_profiles = tuple(
        event for event in events if event.event_type is EventType.WINDOWS_NETWORK_PROFILE_OBSERVED
    )
    services_by_pid = _service_names_by_pid(events)

    active_categories = tuple(
        sorted(
            {
                str(event.payload.get("network_category"))
                for event in network_profiles
                if event.payload.get("network_category")
            },
            key=str.casefold,
        )
    )
    active_aliases = tuple(
        sorted(
            {
                str(event.payload.get("interface_alias"))
                for event in network_profiles
                if event.payload.get("interface_alias")
            },
            key=str.casefold,
        )
    )

    results: list[ListenerFirewallCandidates] = []
    for listener in sorted(
        listeners,
        key=lambda event: (
            str(event.payload.get("local_address")),
            int(event.payload.get("local_port", 0)),
            int(event.payload.get("owner_pid", 0)),
            event.event_id,
        ),
    ):
        owner_pid = int(listener.payload.get("owner_pid"))
        candidates = tuple(
            candidate
            for rule in rules
            if (
                candidate := _candidate_for_rule(
                    listener,
                    rule,
                    active_categories=active_categories,
                    active_aliases=active_aliases,
                    service_names=services_by_pid.get(owner_pid, ()),
                )
            )
            is not None
        )
        candidates = tuple(sorted(candidates, key=lambda item: item.rule_event_id))

        if not candidates:
            status = FirewallCandidateStatus.NO_CANDIDATE
        elif len(candidates) == 1 and not candidates[0].unknown_dimensions:
            status = FirewallCandidateStatus.CANDIDATE_MATCH
        else:
            status = FirewallCandidateStatus.AMBIGUOUS

        limitations = (
            "candidate correlation does not compute Windows Firewall precedence or effective disposition",
            "candidate correlation does not prove remote reachability",
            "restrictive remote peer, principal, package, owner, dynamic-target, and security filters remain unresolved without matching evidence",
            "v1 firewall-rule events have an intentionally incomplete condition surface and remain unresolved",
        )
        results.append(
            ListenerFirewallCandidates(
                listener_event_id=listener.event_id,
                local_address=str(listener.payload.get("local_address")),
                local_port=int(listener.payload.get("local_port")),
                owner_pid=owner_pid,
                status=status,
                candidates=candidates,
                limitations=limitations,
            )
        )

    return FirewallCandidateCorrelation(
        stream_id=stream_id,
        active_network_categories=active_categories,
        listeners=tuple(results),
    )
