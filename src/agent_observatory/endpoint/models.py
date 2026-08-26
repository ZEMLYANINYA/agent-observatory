from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RelationState(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    """Minimal process identity used for process-tree attribution."""

    pid: int
    ppid: int
    name: str
    started_at: float


@dataclass(frozen=True, slots=True)
class ParentRelation:
    """Result of validating a reported parent-child relationship."""

    child_pid: int
    reported_parent_pid: int
    state: RelationState
    reason: str | None = None