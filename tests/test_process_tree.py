import unittest

from agent_observatory.endpoint.models import (
    ProcessSnapshot,
    RelationState,
)
from agent_observatory.endpoint.process_tree import (
    build_validated_process_tree,
    validate_parent_relation,
)


class ParentRelationTests(unittest.TestCase):
    def test_valid_parent_child_relation(self) -> None:
        parent = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="ai-client.exe",
            started_at=1_000.0,
        )

        child = ProcessSnapshot(
            pid=200,
            ppid=100,
            name="renderer.exe",
            started_at=1_001.0,
        )

        relation = validate_parent_relation(parent, child)

        self.assertEqual(relation.state, RelationState.VALID)
        self.assertIsNone(relation.reason)

    def test_rejects_pid_reuse_when_child_predates_parent(self) -> None:
        """
        Regression test derived from EXP-000.

        A long-running adb.exe process reported a PPID that had later
        been reused by a newly started ChatGPT renderer.

        PPID alone therefore produced a false process-tree relationship.
        """

        current_parent = ProcessSnapshot(
            pid=13436,
            ppid=9000,
            name="ChatGPT Classic.exe",
            started_at=200_000.0,
        )

        old_child = ProcessSnapshot(
            pid=6492,
            ppid=13436,
            name="adb.exe",
            started_at=100_000.0,
        )

        relation = validate_parent_relation(current_parent, old_child)

        self.assertEqual(relation.state, RelationState.INVALID)
        self.assertEqual(relation.reason, "parent_pid_reused")

    def test_rejects_ppid_mismatch(self) -> None:
        parent = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="ai-client.exe",
            started_at=1_000.0,
        )

        child = ProcessSnapshot(
            pid=200,
            ppid=999,
            name="helper.exe",
            started_at=1_001.0,
        )

        relation = validate_parent_relation(parent, child)

        self.assertEqual(relation.state, RelationState.INVALID)
        self.assertEqual(relation.reason, "ppid_mismatch")


class ProcessTreeTests(unittest.TestCase):
    def test_tree_excludes_reused_parent_pid_relation(self) -> None:
        processes = [
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="ai-client.exe",
                started_at=200.0,
            ),
            ProcessSnapshot(
                pid=101,
                ppid=100,
                name="network-service.exe",
                started_at=201.0,
            ),
            ProcessSnapshot(
                pid=102,
                ppid=100,
                name="old-tool.exe",
                started_at=50.0,
            ),
        ]

        tree, rejected = build_validated_process_tree(processes)

        self.assertIn(100, tree)
        self.assertEqual(
            [process.pid for process in tree[100]],
            [101],
        )

        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0].child_pid, 102)
        self.assertEqual(rejected[0].reason, "parent_pid_reused")


if __name__ == "__main__":
    unittest.main()