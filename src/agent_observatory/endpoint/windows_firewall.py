from __future__ import annotations

import json
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .windows_powershell import run_powershell_text


@dataclass(frozen=True, slots=True)
class WindowsFirewallProfileSnapshot:
    """One ActiveStore Windows Firewall profile observation."""

    name: str
    enabled: bool
    default_inbound_action: str
    default_outbound_action: str
    allow_inbound_rules: str | None
    allow_local_firewall_rules: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.enabled, bool):
            raise TypeError("enabled must be a boolean")
        for field_name in ("default_inbound_action", "default_outbound_action"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        for field_name in ("allow_inbound_rules", "allow_local_firewall_rules"):
            value = getattr(self, field_name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{field_name} must be a non-empty string or None")


@dataclass(frozen=True, slots=True)
class WindowsNetworkProfileSnapshot:
    """One Get-NetConnectionProfile observation for a Windows interface."""

    name: str
    interface_alias: str
    interface_index: int
    network_category: str
    ipv4_connectivity: str
    ipv6_connectivity: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise ValueError("name must be a non-empty string")
        if not isinstance(self.interface_alias, str) or not self.interface_alias.strip():
            raise ValueError("interface_alias must be a non-empty string")
        if isinstance(self.interface_index, bool) or not isinstance(self.interface_index, int):
            raise TypeError("interface_index must be an integer")
        if self.interface_index < 0:
            raise ValueError("interface_index must be non-negative")
        for field_name in ("network_category", "ipv4_connectivity", "ipv6_connectivity"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")


@dataclass(frozen=True, slots=True)
class WindowsFirewallContext:
    """One bracketed firewall-profile and connection-profile context snapshot."""

    firewall_profiles: tuple[WindowsFirewallProfileSnapshot, ...]
    network_profiles: tuple[WindowsNetworkProfileSnapshot, ...]
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


def _powershell_firewall_context() -> str:
    command = r"""
$startedAt = [DateTime]::UtcNow

$firewallProfiles = @(
    Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
    Select-Object `
        @{Name='name';Expression={$_.Name.ToString()}},
        @{Name='enabled';Expression={[bool]$_.Enabled}},
        @{Name='default_inbound_action';Expression={$_.DefaultInboundAction.ToString()}},
        @{Name='default_outbound_action';Expression={$_.DefaultOutboundAction.ToString()}},
        @{Name='allow_inbound_rules';Expression={
            if ($null -eq $_.AllowInboundRules) { $null }
            else { $_.AllowInboundRules.ToString() }
        }},
        @{Name='allow_local_firewall_rules';Expression={
            if ($null -eq $_.AllowLocalFirewallRules) { $null }
            else { $_.AllowLocalFirewallRules.ToString() }
        }}
)

$networkProfiles = @(
    Get-NetConnectionProfile -ErrorAction Stop |
    Select-Object `
        @{Name='name';Expression={$_.Name}},
        @{Name='interface_alias';Expression={$_.InterfaceAlias}},
        @{Name='interface_index';Expression={$_.InterfaceIndex}},
        @{Name='network_category';Expression={$_.NetworkCategory.ToString()}},
        @{Name='ipv4_connectivity';Expression={$_.IPv4Connectivity.ToString()}},
        @{Name='ipv6_connectivity';Expression={$_.IPv6Connectivity.ToString()}}
)

$finishedAt = [DateTime]::UtcNow

[PSCustomObject]@{
    capture_started_at = $startedAt.ToString("o")
    capture_finished_at = $finishedAt.ToString("o")
    firewall_profiles = $firewallProfiles
    network_profiles = $networkProfiles
} | ConvertTo-Json -Compress -Depth 6
"""
    return run_powershell_text(command)


def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        if not all(isinstance(item, dict) for item in value):
            raise TypeError("inventory records must be objects")
        return value
    raise TypeError(f"inventory records must be a list or object, got {type(value).__name__}")


def _timestamp(value: Any) -> float:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def parse_windows_firewall_context(raw: str) -> WindowsFirewallContext:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty Windows firewall context")

    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("Windows firewall context must be a JSON object")

    firewall_profiles = tuple(
        sorted(
            (
                WindowsFirewallProfileSnapshot(
                    name=str(record["name"]),
                    enabled=record["enabled"],
                    default_inbound_action=str(record["default_inbound_action"]),
                    default_outbound_action=str(record["default_outbound_action"]),
                    allow_inbound_rules=_optional_text(record.get("allow_inbound_rules")),
                    allow_local_firewall_rules=_optional_text(
                        record.get("allow_local_firewall_rules")
                    ),
                )
                for record in _records(payload.get("firewall_profiles"))
            ),
            key=lambda item: item.name.casefold(),
        )
    )

    network_profiles = tuple(
        sorted(
            (
                WindowsNetworkProfileSnapshot(
                    name=str(record["name"]),
                    interface_alias=str(record["interface_alias"]),
                    interface_index=int(record["interface_index"]),
                    network_category=str(record["network_category"]),
                    ipv4_connectivity=str(record["ipv4_connectivity"]),
                    ipv6_connectivity=str(record["ipv6_connectivity"]),
                )
                for record in _records(payload.get("network_profiles"))
            ),
            key=lambda item: (
                item.interface_index,
                item.interface_alias.casefold(),
                item.name.casefold(),
            ),
        )
    )

    return WindowsFirewallContext(
        firewall_profiles=firewall_profiles,
        network_profiles=network_profiles,
        capture_started_at=_timestamp(payload["capture_started_at"]),
        capture_finished_at=_timestamp(payload["capture_finished_at"]),
    )


def collect_windows_firewall_context() -> WindowsFirewallContext:
    return parse_windows_firewall_context(_powershell_firewall_context())
