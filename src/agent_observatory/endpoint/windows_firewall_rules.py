from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .windows_powershell import run_powershell_text


@dataclass(frozen=True, slots=True)
class WindowsFirewallRuleSnapshot:
    """One ActiveStore inbound Windows Firewall rule plus source filters."""

    name: str
    display_name: str
    enabled: bool
    direction: str
    action: str
    profile: str
    edge_traversal_policy: str
    policy_store_source_type: str | None
    policy_store_source: str | None
    owner: str | None
    primary_status: str | None
    status: str | None
    loose_source_mapping: bool | None
    local_only_mapping: bool | None
    protocol: tuple[str, ...]
    local_ports: tuple[str, ...]
    remote_ports: tuple[str, ...]
    icmp_types: tuple[str, ...]
    dynamic_targets: tuple[str, ...]
    local_addresses: tuple[str, ...]
    remote_addresses: tuple[str, ...]
    programs: tuple[str, ...]
    packages: tuple[str, ...]
    services: tuple[str, ...]
    interface_types: tuple[str, ...]
    interface_aliases: tuple[str, ...]
    authentication: tuple[str, ...]
    encryption: tuple[str, ...]
    override_block_rules: tuple[str, ...]
    local_users: tuple[str, ...]
    remote_users: tuple[str, ...]
    remote_machines: tuple[str, ...]

    def __post_init__(self) -> None:
        for field_name in (
            "name",
            "display_name",
            "direction",
            "action",
            "profile",
            "edge_traversal_policy",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a boolean")
        for field_name in (
            "policy_store_source_type",
            "policy_store_source",
            "owner",
            "primary_status",
            "status",
        ):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, str):
                raise TypeError(f"{field_name} must be a string or None")
        for field_name in ("loose_source_mapping", "local_only_mapping"):
            value = getattr(self, field_name)
            if value is not None and not isinstance(value, bool):
                raise TypeError(f"{field_name} must be a boolean or None")
        for field_name in (
            "protocol",
            "local_ports",
            "remote_ports",
            "icmp_types",
            "dynamic_targets",
            "local_addresses",
            "remote_addresses",
            "programs",
            "packages",
            "services",
            "interface_types",
            "interface_aliases",
            "authentication",
            "encryption",
            "override_block_rules",
            "local_users",
            "remote_users",
            "remote_machines",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, tuple) or not all(
                isinstance(item, str) for item in value
            ):
                raise TypeError(f"{field_name} must be a tuple of strings")


@dataclass(frozen=True, slots=True)
class WindowsFirewallRuleInventory:
    rules: tuple[WindowsFirewallRuleSnapshot, ...]
    capture_started_at: float
    capture_finished_at: float

    def __post_init__(self) -> None:
        for field_name in ("capture_started_at", "capture_finished_at"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{field_name} must be a finite number")
            if not math.isfinite(float(value)):
                raise ValueError(f"{field_name} must be finite")
        if self.capture_finished_at < self.capture_started_at:
            raise ValueError("capture_finished_at must not precede capture_started_at")


def _powershell_inbound_firewall_rules() -> str:
    command = r''' 
function To-StringArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    return @($Value | ForEach-Object { $_.ToString() })
}

function To-NullableBool {
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = $Value.ToString()
    if ($text -eq 'True') { return $true }
    if ($text -eq 'False') { return $false }
    return $null
}

$startedAt = [DateTime]::UtcNow
$records = @(
    Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -ErrorAction Stop |
    ForEach-Object {
        $rule = $_
        $port = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
        $address = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
        $application = @($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop)
        $service = @($rule | Get-NetFirewallServiceFilter -ErrorAction Stop)
        $interfaceType = @($rule | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
        $interface = @($rule | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
        $security = @($rule | Get-NetFirewallSecurityFilter -ErrorAction Stop)

        [PSCustomObject]@{
            name = $rule.Name
            display_name = $rule.DisplayName
            enabled = [bool]($rule.Enabled.ToString() -eq 'True')
            direction = $rule.Direction.ToString()
            action = $rule.Action.ToString()
            profile = $rule.Profile.ToString()
            edge_traversal_policy = $rule.EdgeTraversalPolicy.ToString()
            policy_store_source_type = if ($null -eq $rule.PolicyStoreSourceType) { $null } else { $rule.PolicyStoreSourceType.ToString() }
            policy_store_source = if ($null -eq $rule.PolicyStoreSource) { $null } else { $rule.PolicyStoreSource.ToString() }
            owner = if ($null -eq $rule.Owner) { $null } else { $rule.Owner.ToString() }
            primary_status = if ($null -eq $rule.PrimaryStatus) { $null } else { $rule.PrimaryStatus.ToString() }
            status = if ($null -eq $rule.Status) { $null } else { $rule.Status.ToString() }
            loose_source_mapping = To-NullableBool $rule.LooseSourceMapping
            local_only_mapping = To-NullableBool $rule.LocalOnlyMapping
            protocol = @(To-StringArray ($port | ForEach-Object { $_.Protocol }))
            local_ports = @(To-StringArray ($port | ForEach-Object { $_.LocalPort }))
            remote_ports = @(To-StringArray ($port | ForEach-Object { $_.RemotePort }))
            icmp_types = @(To-StringArray ($port | ForEach-Object { $_.IcmpType }))
            dynamic_targets = @(To-StringArray ($port | ForEach-Object {
                if ($null -ne $_.DynamicTarget) { $_.DynamicTarget }
                elseif ($null -ne $_.DynamicTransport) { $_.DynamicTransport }
            }))
            local_addresses = @(To-StringArray ($address | ForEach-Object { $_.LocalAddress }))
            remote_addresses = @(To-StringArray ($address | ForEach-Object { $_.RemoteAddress }))
            programs = @(To-StringArray ($application | ForEach-Object { $_.Program }))
            packages = @(To-StringArray ($application | ForEach-Object { $_.Package }))
            services = @(To-StringArray ($service | ForEach-Object { $_.Service }))
            interface_types = @(To-StringArray ($interfaceType | ForEach-Object { $_.InterfaceType }))
            interface_aliases = @(To-StringArray ($interface | ForEach-Object { $_.InterfaceAlias }))
            authentication = @(To-StringArray ($security | ForEach-Object { $_.Authentication }))
            encryption = @(To-StringArray ($security | ForEach-Object { $_.Encryption }))
            override_block_rules = @(To-StringArray ($security | ForEach-Object { $_.OverrideBlockRules }))
            local_users = @(To-StringArray ($security | ForEach-Object { $_.LocalUser }))
            remote_users = @(To-StringArray ($security | ForEach-Object { $_.RemoteUser }))
            remote_machines = @(To-StringArray ($security | ForEach-Object { $_.RemoteMachine }))
        }
    }
)
$finishedAt = [DateTime]::UtcNow

[PSCustomObject]@{
    capture_started_at = $startedAt.ToString("o")
    capture_finished_at = $finishedAt.ToString("o")
    rules = $records
} | ConvertTo-Json -Compress -Depth 8
'''
    return run_powershell_text(command)


def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(item, dict) for item in value):
        return value
    raise TypeError("rules must be a JSON object or list of objects")


def _timestamp(value: Any) -> float:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _optional_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise TypeError("optional firewall rule boolean fields must remain booleans")
    return value


def _string_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, list):
        return tuple(str(item) for item in value if item is not None)
    return (str(value),)


def parse_windows_firewall_rule_inventory(raw: str) -> WindowsFirewallRuleInventory:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty Windows firewall rule inventory")

    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Windows firewall rule inventory must be a JSON object")

    rules = tuple(
        sorted(
            (
                WindowsFirewallRuleSnapshot(
                    name=str(record["name"]),
                    display_name=str(record["display_name"]),
                    enabled=record["enabled"],
                    direction=str(record["direction"]),
                    action=str(record["action"]),
                    profile=str(record["profile"]),
                    edge_traversal_policy=str(record["edge_traversal_policy"]),
                    policy_store_source_type=_optional_text(
                        record.get("policy_store_source_type")
                    ),
                    policy_store_source=_optional_text(
                        record.get("policy_store_source")
                    ),
                    owner=_optional_text(record.get("owner")),
                    primary_status=_optional_text(record.get("primary_status")),
                    status=_optional_text(record.get("status")),
                    loose_source_mapping=_optional_bool(record.get("loose_source_mapping")),
                    local_only_mapping=_optional_bool(record.get("local_only_mapping")),
                    protocol=_string_tuple(record.get("protocol")),
                    local_ports=_string_tuple(record.get("local_ports")),
                    remote_ports=_string_tuple(record.get("remote_ports")),
                    icmp_types=_string_tuple(record.get("icmp_types")),
                    dynamic_targets=_string_tuple(record.get("dynamic_targets")),
                    local_addresses=_string_tuple(record.get("local_addresses")),
                    remote_addresses=_string_tuple(record.get("remote_addresses")),
                    programs=_string_tuple(record.get("programs")),
                    packages=_string_tuple(record.get("packages")),
                    services=_string_tuple(record.get("services")),
                    interface_types=_string_tuple(record.get("interface_types")),
                    interface_aliases=_string_tuple(record.get("interface_aliases")),
                    authentication=_string_tuple(record.get("authentication")),
                    encryption=_string_tuple(record.get("encryption")),
                    override_block_rules=_string_tuple(record.get("override_block_rules")),
                    local_users=_string_tuple(record.get("local_users")),
                    remote_users=_string_tuple(record.get("remote_users")),
                    remote_machines=_string_tuple(record.get("remote_machines")),
                )
                for record in _records(payload.get("rules"))
            ),
            key=lambda item: (item.name.casefold(), item.display_name.casefold()),
        )
    )

    return WindowsFirewallRuleInventory(
        rules=rules,
        capture_started_at=_timestamp(payload["capture_started_at"]),
        capture_finished_at=_timestamp(payload["capture_finished_at"]),
    )


def collect_windows_firewall_rule_inventory() -> WindowsFirewallRuleInventory:
    return parse_windows_firewall_rule_inventory(_powershell_inbound_firewall_rules())
