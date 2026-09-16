from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from .identity import capture_identity_key
from .models import (
    ParentRelation,
    ProcessSnapshot,
    RelationBasis,
    RelationState,
)


def validate_parent_relation(
    parent: ProcessSnapshot,
    child: ProcessSnapshot,
    *,
    basis: RelationBasis = RelationBasis.CURRENT_SNAPSHOT,
) -> ParentRelation:
    """
    Validate whether an observed process can plausibly be the child's parent.

    A process cannot be the historical parent of another process if it started
    after that child. The relation basis records how directly the parent was
    observed rather than collapsing all relationships into one confidence-like
    state.
    """

    if child.ppid != parent.pid:
        return ParentRelation(
            child_pid=child.pid,
            reported_parent_pid=child.ppid,
            state=RelationState.INVALID,
            basis=basis,
            reason="ppid_mismatch",
        )

    if child.started_at < parent.started_at:
        return ParentRelation(
            child_pid=child.pid,
            reported_parent_pid=child.ppid,
            state=RelationState.INVALID,
            basis=basis,
            reason="parent_pid_reused",
        )

    return ParentRelation(
        child_pid=child.pid,
        reported_parent_pid=child.ppid,
        state=RelationState.VALID,
        basis=basis,
    )


def build_capture_parent_relations(
    processes_before: Iterable[ProcessSnapshot],
    processes_after: Iterable[ProcessSnapshot],
) -> tuple[ParentRelation, ...]:
    """
    Preserve parent relationship evidence across a bracketing capture.

    If a parent disappears between the before/after process snapshots but the
    same child and parent were observed together beforehand, retain that
    historical relation with ``PARENT_OBSERVED_BEFORE_ONLY``. A PPID whose
    parent was never observed remains explicit ``UNKNOWN`` evidence instead of
    being silently discarded.
    """

    before = tuple(processes_before)
    after = tuple(processes_after)
    before_by_pid = {process.pid: process for process in before}
    after_by_pid = {process.pid: process for process in after}
    relations: list[ParentRelation] = []

    for child_after in after:
        if child_after.ppid <= 0:
            continue

        parent_after = after_by_pid.get(child_after.ppid)
        if parent_after is not None:
            relations.append(
                validate_parent_relation(
                    parent_after,
                    child_after,
                    basis=RelationBasis.CURRENT_SNAPSHOT,
                )
            )
            continue

        child_before = before_by_pid.get(child_after.pid)
        parent_before = before_by_pid.get(child_after.ppid)

        if child_before is not None and parent_before is not None:
            if capture_identity_key(child_before) != capture_identity_key(child_after):
                relations.append(
                    ParentRelation(
                        child_pid=child_after.pid,
                        reported_parent_pid=child_after.ppid,
                        state=RelationState.UNKNOWN,
                        basis=RelationBasis.REPORTED_PPID_ONLY,
                        reason="child_pid_reused_across_capture",
                    )
                )
                continue

            historical = validate_parent_relation(
                parent_before,
                child_before,
                basis=RelationBasis.PARENT_OBSERVED_BEFORE_ONLY,
            )
            relations.append(historical)
            continue

        relations.append(
            ParentRelation(
                child_pid=child_after.pid,
                reported_parent_pid=child_after.ppid,
                state=RelationState.UNKNOWN,
                basis=RelationBasis.REPORTED_PPID_ONLY,
                reason=(
                    "parent_not_observed_with_child"
                    if parent_before is not None
                    else "parent_not_observed"
                ),
            )
        )

    return tuple(relations)


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
