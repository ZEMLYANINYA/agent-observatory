import unittest

from agent_observatory.endpoint.discovery import (
    ApplicationProfile,
    discover_root_processes,
)
from agent_observatory.endpoint.models import ProcessSnapshot


class DiscoveryTests(unittest.TestCase):
    def test_discovers_root_process(self) -> None:
        processes = [
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="claude.exe",
                started_at=100.0,
            ),
            ProcessSnapshot(
                pid=101,
                ppid=100,
                name="claude.exe",
                started_at=101.0,
            ),
        ]

        applications = discover_root_processes(
            processes,
            profiles=(
                ApplicationProfile(
                    name="Claude",
                    process_names=("claude.exe",),
                ),
            ),
        )

        self.assertEqual(len(applications), 1)
        self.assertEqual(
            applications[0].root_process.pid,
            100,
        )

    def test_does_not_treat_same_name_child_as_root(self) -> None:
        processes = [
            ProcessSnapshot(
                pid=200,
                ppid=20,
                name="ChatGPT Classic.exe",
                started_at=200.0,
            ),
            ProcessSnapshot(
                pid=201,
                ppid=200,
                name="ChatGPT Classic.exe",
                started_at=201.0,
            ),
            ProcessSnapshot(
                pid=202,
                ppid=200,
                name="ChatGPT Classic.exe",
                started_at=202.0,
            ),
        ]

        applications = discover_root_processes(
            processes,
            profiles=(
                ApplicationProfile(
                    name="ChatGPT",
                    process_names=("ChatGPT Classic.exe",),
                ),
            ),
        )

        self.assertEqual(
            [item.root_process.pid for item in applications],
            [200],
        )

    def test_multiple_profiles(self) -> None:
        processes = [
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="claude.exe",
                started_at=100.0,
            ),
            ProcessSnapshot(
                pid=200,
                ppid=10,
                name="ChatGPT Classic.exe",
                started_at=100.0,
            ),
        ]

        applications = discover_root_processes(processes)

        self.assertEqual(
            [
                (
                    item.profile.name,
                    item.root_process.pid,
                )
                for item in applications
            ],
            [
                ("ChatGPT", 200),
                ("Claude", 100),
            ],
        )


if __name__ == "__main__":
    unittest.main()