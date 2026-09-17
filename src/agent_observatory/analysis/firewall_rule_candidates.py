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
_ANY_PROTOCOL_VALUES = {"256"}
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
_ProcessKey = tuple[int, float]
_NetworkProfile = tuple[str | None, str | None]


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


def _normalize_firewall_profile(value: str) -> str:
    normalized = value.strip().casefold()
    if normalized == "domainauthenticated":
        return "domain"
    return normalized


def _network_scope_results(
    rule_profile: str,
    interface_aliases: tuple[str, ...],
    active_network_profiles: tuple[_NetworkProfile, ...],
) -> tuple[_DimensionResult, _DimensionResult]:
    profile_tokens = tuple(
        _normalize_firewall_profile(item)
        for item in _tokens((rule_profile,))
    )
    alias_tokens = tuple(item.casefold() for item in _tokens(interface_aliases))

    profile_unrestricted = (
        not profile_tokens or any(item in _ANY_VALUES for item in profile_tokens)
    )
    alias_unrestricted = (
        not alias_tokens or any(item in _ANY_VALUES for item in alias_tokens)
    )

    if profile_unrestricted and alias_unrestricted:
        known = _DimensionResult(True, True)
        return known, known

    if not active_network_profiles:
        return (
            _DimensionResult(True, profile_unrestricted),
            _DimensionResult(True, alias_unrestricted),
        )

    expected_profiles = set(profile_tokens)
    expected_aliases = set(alias_tokens)

    if alias_unrestricted:
        saw_unknown = False
        for category, _alias in active_network_profiles:
            if not category:
                saw_unknown = True
                continue
            if _normalize_firewall_profile(category) in expected_profiles:
                return _DimensionResult(True, True), _DimensionResult(True, True)
        if saw_unknown:
            return _DimensionResult(True, False), _DimensionResult(True, True)
        return _DimensionResult(False, True), _DimensionResult(True, True)

    if profile_unrestricted:
        saw_unknown = False
        for _category, alias in active_network_profiles:
            if not alias:
                saw_unknown = True
                continue
            if alias.casefold() in expected_aliases:
                return _DimensionResult(True, True), _DimensionResult(True, True)
        if saw_unknown:
            return _DimensionResult(True, True), _DimensionResult(True, False)
        return _DimensionResult(True, True), _DimensionResult(False, True)

    saw_possible_unknown = False
    for category, alias in active_network_profiles:
        category_known = bool(category)
        alias_known = bool(alias)
        category_matches = (
            not category_known
            or _normalize_firewall_profile(category or "") in expected_profiles
        )
        alias_matches = (
            not alias_known
            or (alias or "").casefold() in expected_aliases
        )

        if not category_matches or not alias_matches:
            continue
        if category_known and alias_known:
            known = _DimensionResult(True, True)
            return known, known
        saw_possible_unknown = True

    if saw_possible_unknown:
        unknown = _DimensionResult(True, False)
        return unknown, unknown

    incompatible = _DimensionResult(False, True)
    return incompatible, incompatible


def _protocol_result(values: tuple[str, ...]) -> _DimensionResult:
    tokens = tuple(item.casefold() for item in _tokens(values))
    if not tokens:
        return _DimensionResult(True, False)
    if any(item in _ANY_VALUES or item in _ANY_PROTOCOL_VALUES for item in tokens):
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
                if (
                    start.version == listener_ip.version == end.version
                    and start <= listener_ip <= end
                ):
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


def _service_result(
    values: tuple[str, ...],
    service_names: tuple[str, ...],
) -> _DimensionResult:
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


def _owner_result(value: object, owner_sids: tuple[str, ...]) -> _DimensionResult:
    if value is None:
        return _DimensionResult(True, True)
    text = str(value).strip()
    if not text or text.casefold() in _ANY_VALUES:
        return _DimensionResult(True, True)

    normalized = {sid.strip().casefold() for sid in owner_sids if sid.strip()}
    if not normalized:
        return _DimensionResult(True, False)
    if len(normalized) != 1:
        return _DimensionResult(True, False)
    return _DimensionResult(text.casefold() in normalized, True)


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


def _process_key(payload: dict[str, object]) -> _ProcessKey | None:
    process = payload.get("process")
    if not isinstance(process, dict):
        return None
    pid = process.get("pid")
    started_at = process.get("started_at")
    if isinstance(pid, bool) or not isinstance(pid, int):
        return None
    if isinstance(started_at, bool) or not isinstance(started_at, (int, float)):
        return None
    return (pid, float(started_at))


def _service_names_by_process(
    events: tuple[StoredEvent, ...],
) -> dict[_ProcessKey, tuple[str, ...]]:
    names: dict[_ProcessKey, set[str]] = {}
    for event in events:
        if event.event_type is not EventType.WINDOWS_SERVICE_OBSERVED:
            continue
        if event.payload.get("process_attribution_state") != "attributed":
            continue
        key = _process_key(event.payload)
        name = event.payload.get("service_name")
        if key is not None and isinstance(name, str) and name:
            names.setdefault(key, set()).add(name)
    return {
        key: tuple(sorted(values, key=str.casefold))
        for key, values in names.items()
    }


def _principal_sids_by_process(
    events: tuple[StoredEvent, ...],
) -> dict[_ProcessKey, tuple[str, ...]]:
    sids: dict[_ProcessKey, set[str]] = {}
    for event in events:
        if event.event_type is not EventType.WINDOWS_PROCESS_PRINCIPAL_OBSERVED:
            continue
        if event.payload.get("resolution_state") != "resolved":
            continue
        key = _process_key(event.payload)
        sid = event.payload.get("owner_sid")
        if key is not None and isinstance(sid, str) and sid.strip():
            sids.setdefault(key, set()).add(sid.strip())
    return {
        key: tuple(sorted(values, key=str.casefold))
        for key, values in sids.items()
    }


def _firewall_rule_inventory_available(
    events: tuple[StoredEvent, ...],
    rules: tuple[StoredEvent, ...],
) -> bool | None:
    manifests = tuple(
        event
        for event in events
        if event.event_type is EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST
    )
    if not manifests:
        return None
    if len(manifests) != 1:
        return False

    collectors = manifests[0].payload.get("collectors")
    if not isinstance(collectors, list):
        return False

    reports = tuple(
        report
        for report in collectors
        if isinstance(report, dict)
        and report.get("collector") == "windows_firewall_rules"
    )
    if len(reports) != 1:
        return False

    report = reports[0]
    if str(report.get("status", "")).casefold() != "succeeded":
        return False

    record_count = report.get("record_count")
    if isinstance(record_count, bool) or not isinstance(record_count, int):
        return False
    if record_count != len(rules):
        return False
    return True


def _candidate_for_rule(
    listener: StoredEvent,
    rule: StoredEvent,
    *,
    active_network_profiles: tuple[_NetworkProfile, ...],
    service_names: tuple[str, ...],
    owner_sids: tuple[str, ...],
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
    profile_result, interface_alias_result = _network_scope_results(
        str(payload.get("profile", "")),
        _strings(payload.get("interface_aliases")),
        active_network_profiles,
    )

    dimensions = {
        "RULE_CONDITION_SURFACE": _condition_surface_result(rule),
        "RULE_STATUS": _rule_status_result(payload.get("primary_status")),
        "PROFILE": profile_result,
        "PROTOCOL": _protocol_result(_strings(payload.get("protocol"))),
        "LOCAL_PORT": _port_result(
            _strings(payload.get("local_ports")),
            local_port,
        ),
        "LOCAL_ADDRESS": _address_result(
            _strings(payload.get("local_addresses")),
            local_address,
        ),
        "PROGRAM": _program_result(
            _strings(payload.get("programs")),
            executable_path if isinstance(executable_path, str) else None,
            process_name if isinstance(process_name, str) else None,
        ),
        "PACKAGE": _package_result(_strings(payload.get("packages"))),
        "SERVICE": _service_result(
            _strings(payload.get("services")),
            service_names,
        ),
        "OWNER": _owner_result(payload.get("owner"), owner_sids),
        "REMOTE_PORT": _remote_scope_result(_strings(payload.get("remote_ports"))),
        "REMOTE_ADDRESS": _remote_scope_result(
            _strings(payload.get("remote_addresses"))
        ),
        "INTERFACE_ALIAS": interface_alias_result,
        "INTERFACE_TYPE": _interface_type_result(
            _strings(payload.get("interface_types"))
        ),
        "DYNAMIC_TARGET": _constraint_result(
            _strings(payload.get("dynamic_targets"))
        ),
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
        "REMOTE_MACHINE": _constraint_result(
            _strings(payload.get("remote_machines"))
        ),
        "LOOSE_SOURCE_MAPPING": _mapping_flag_result(
            payload.get("loose_source_mapping")
        ),
        "LOCAL_ONLY_MAPPING": _mapping_flag_result(payload.get("local_only_mapping")),
    }

    if any(
        result.known and not result.compatible
        for result in dimensions.values()
    ):
        return None

    compatible = tuple(
        name
        for name, result in sorted(dimensions.items())
        if result.known and result.compatible
    )
    unknown = tuple(
        name
        for name, result in sorted(dimensions.items())
        if not result.known
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
        event
        for event in events
        if event.event_type is EventType.TCP_LISTENER_OBSERVED
    )
    rules = tuple(
        event
        for event in events
        if event.event_type is EventType.WINDOWS_FIREWALL_RULE_OBSERVED
    )
    network_profiles = tuple(
        event
        for event in events
        if event.event_type is EventType.WINDOWS_NETWORK_PROFILE_OBSERVED
    )
    services_by_process = _service_names_by_process(events)
    principal_sids_by_process = _principal_sids_by_process(events)
    firewall_rule_inventory_available = _firewall_rule_inventory_available(
        events,
        rules,
    )

    active_network_profiles: tuple[_NetworkProfile, ...] = tuple(
        (
            str(event.payload.get("network_category"))
            if event.payload.get("network_category")
            else None,
            str(event.payload.get("interface_alias"))
            if event.payload.get("interface_alias")
            else None,
        )
        for event in network_profiles
    )
    active_categories = tuple(
        sorted(
            {
                category
                for category, _alias in active_network_profiles
                if category
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
        process_key = _process_key(listener.payload)
        service_names = (
            ()
            if process_key is None
            else services_by_process.get(process_key, ())
        )
        owner_sids = (
            ()
            if process_key is None
            else principal_sids_by_process.get(process_key, ())
        )

        limitations = [
            "candidate correlation does not compute Windows Firewall precedence or effective disposition",
            "candidate correlation does not prove remote reachability",
            "restrictive remote peer, package, dynamic-target, and security filters remain unresolved without matching evidence",
            "owner filters resolve only from principal evidence tied to the same stable process instance",
            "service filters resolve only from service evidence tied to the same stable process instance",
            "v1 firewall-rule events have an intentionally incomplete condition surface and remain unresolved",
        ]

        if firewall_rule_inventory_available is False:
            candidates: tuple[FirewallRuleCandidate, ...] = ()
            status = FirewallCandidateStatus.AMBIGUOUS
            limitations.append(
                "firewall rule inventory was not successfully collected; candidate absence is unresolved"
            )
        else:
            candidates = tuple(
                candidate
                for rule in rules
                if (
                    candidate := _candidate_for_rule(
                        listener,
                        rule,
                        active_network_profiles=active_network_profiles,
                        service_names=service_names,
                        owner_sids=owner_sids,
                    )
                )
                is not None
            )
            candidates = tuple(
                sorted(candidates, key=lambda item: item.rule_event_id)
            )

            if not candidates:
                status = FirewallCandidateStatus.NO_CANDIDATE
            elif len(candidates) == 1 and not candidates[0].unknown_dimensions:
                status = FirewallCandidateStatus.CANDIDATE_MATCH
            else:
                status = FirewallCandidateStatus.AMBIGUOUS

        results.append(
            ListenerFirewallCandidates(
                listener_event_id=listener.event_id,
                local_address=str(listener.payload.get("local_address")),
                local_port=int(listener.payload.get("local_port")),
                owner_pid=owner_pid,
                status=status,
                candidates=candidates,
                limitations=tuple(limitations),
            )
        )

    return FirewallCandidateCorrelation(
        stream_id=stream_id,
        active_network_categories=active_categories,
        listeners=tuple(results),
    )
