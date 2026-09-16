from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RelationState(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


class RelationBasis(str, Enum):
    CURRENT_SNAPSHOT = "current_snapshot"
    PARENT_OBSERVED_BEFORE_ONLY = "parent_observed_before_only"
    REPORTED_PPID_ONLY = "reported_ppid_only"


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    """Minimal process evidence used for process-tree attribution."""

    pid: int
    ppid: int
    name: str
    started_at: float
    command_line: str | None = None
    executable_path: str | None = None


@dataclass(frozen=True, slots=True)
class ParentRelation:
    """Result of validating a reported parent-child relationship."""

    child_pid: int
    reported_parent_pid: int
    state: RelationState
    basis: RelationBasis = RelationBasis.CURRENT_SNAPSHOT
    reason: str | None = None
