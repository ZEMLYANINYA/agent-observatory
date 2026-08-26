from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .models import ParentRelation, ProcessSnapshot, RelationState


def validate_parent_relation(
    parent: ProcessSnapshot,
    child: ProcessSnapshot,
) -> ParentRelation:
    """
    Validate whether the current process occupying child.ppid can
    plausibly be the child's parent.

    A process cannot be the historical parent of another process if
    it started after that child.

    This check protects process-tree reconstruction from PID reuse.
    """

    if child.ppid != parent.pid:
        return ParentRelation(
            child_pid=child.pid,
            reported_parent_pid=child.ppid,
            state=RelationState.INVALID,
            reason="ppid_mismatch",
        )

    if child.started_at < parent.started_at:
        return ParentRelation(
            child_pid=child.pid,
            reported_parent_pid=child.ppid,
            state=RelationState.INVALID,
            reason="parent_pid_reused",
        )

    return ParentRelation(
        child_pid=child.pid,
        reported_parent_pid=child.ppid,
        state=RelationState.VALID,
    )


def build_validated_process_tree(
    processes: Iterable[ProcessSnapshot],
) -> tuple[
    dict[int, tuple[ProcessSnapshot, ...]],
    tuple[ParentRelation, ...],
]:
    """
    Build parent -> children mappings using temporally validated relations.

    Returns:
        validated_children:
            Mapping of parent PID to validated child processes.

        rejected_relations:
            Relationships rejected during validation.
    """

    process_list = list(processes)
    by_pid = {process.pid: process for process in process_list}

    children: dict[int, list[ProcessSnapshot]] = defaultdict(list)
    rejected: list[ParentRelation] = []

    for child in process_list:
        if child.ppid <= 0:
            continue

        parent = by_pid.get(child.ppid)

        if parent is None:
            continue

        relation = validate_parent_relation(parent, child)

        if relation.state is RelationState.VALID:
            children[parent.pid].append(child)
        else:
            rejected.append(relation)

    validated_children = {
        parent_pid: tuple(
            sorted(child_processes, key=lambda process: process.pid)
        )
        for parent_pid, child_processes in children.items()
    }

    return validated_children, tuple(rejected)