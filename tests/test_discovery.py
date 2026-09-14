import unittest

from agent_observatory.endpoint.discovery import (
    ApplicationProfile,
    discover_root_processes,
    matches_application_profile,
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

    def test_does_not_treat_same_profile_child_as_root(self) -> None:
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

    def test_path_constraints_distinguish_shared_executable_name(self) -> None:
        processes = [
            ProcessSnapshot(
                pid=300,
                ppid=30,
                name="ChatGPT.exe",
                started_at=300.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "OpenAI.Codex_26.908.4834.0_x64__package\\app\\ChatGPT.exe"
                ),
            ),
            ProcessSnapshot(
                pid=400,
                ppid=40,
                name="ChatGPT.exe",
                started_at=400.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "OpenAI.ChatGPT_1.0.0.0_x64__package\\app\\ChatGPT.exe"
                ),
            ),
        ]

        profiles = (
            ApplicationProfile(
                name="Codex",
                process_names=("ChatGPT.exe",),
                executable_path_contains=("\\WindowsApps\\OpenAI.Codex_",),
            ),
            ApplicationProfile(
                name="ChatGPT",
                process_names=("ChatGPT.exe",),
                executable_path_contains=("\\WindowsApps\\OpenAI.ChatGPT_",),
            ),
        )

        applications = discover_root_processes(
            processes,
            profiles=profiles,
        )

        self.assertEqual(
            [
                (item.profile.name, item.root_process.pid)
                for item in applications
            ],
            [
                ("ChatGPT", 400),
                ("Codex", 300),
            ],
        )

    def test_same_name_parent_from_other_profile_does_not_hide_root(self) -> None:
        profile = ApplicationProfile(
            name="Codex",
            process_names=("ChatGPT.exe",),
            executable_path_contains=("\\WindowsApps\\OpenAI.Codex_",),
        )
        processes = [
            ProcessSnapshot(
                pid=500,
                ppid=50,
                name="ChatGPT.exe",
                started_at=500.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "OpenAI.ChatGPT_1.0.0.0_x64__package\\app\\ChatGPT.exe"
                ),
            ),
            ProcessSnapshot(
                pid=501,
                ppid=500,
                name="ChatGPT.exe",
                started_at=501.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "OpenAI.Codex_26.908.4834.0_x64__package\\app\\ChatGPT.exe"
                ),
            ),
        ]

        applications = discover_root_processes(
            processes,
            profiles=(profile,),
        )

        self.assertEqual(
            [item.root_process.pid for item in applications],
            [501],
        )

    def test_path_constraint_requires_observed_path(self) -> None:
        profile = ApplicationProfile(
            name="Codex",
            process_names=("ChatGPT.exe",),
            executable_path_contains=("OpenAI.Codex_",),
        )
        process = ProcessSnapshot(
            pid=600,
            ppid=60,
            name="ChatGPT.exe",
            started_at=600.0,
        )

        self.assertFalse(
            matches_application_profile(process, profile)
        )

    def test_command_line_constraint_is_case_insensitive(self) -> None:
        profile = ApplicationProfile(
            name="Example",
            process_names=("client.exe",),
            command_line_contains=("--Mode=Agent",),
        )
        process = ProcessSnapshot(
            pid=700,
            ppid=70,
            name="CLIENT.EXE",
            started_at=700.0,
            command_line="client.exe --mode=agent --flag=value",
        )

        self.assertTrue(
            matches_application_profile(process, profile)
        )

    def test_default_profiles_include_observed_desktop_clients(self) -> None:
        processes = [
            ProcessSnapshot(
                pid=100,
                ppid=10,
                name="claude.exe",
                started_at=100.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "Claude_1.52386.6.0_x64__package\\app\\claude.exe"
                ),
            ),
            ProcessSnapshot(
                pid=200,
                ppid=20,
                name="ChatGPT.exe",
                started_at=200.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "OpenAI.Codex_26.908.4834.0_x64__package\\app\\ChatGPT.exe"
                ),
            ),
            ProcessSnapshot(
                pid=300,
                ppid=30,
                name="Gemini.exe",
                started_at=300.0,
                executable_path=(
                    "C:\\Users\\test\\AppData\\Local\\Google\\Gemini\\"
                    "app-1.10.5\\Gemini.exe"
                ),
            ),
            ProcessSnapshot(
                pid=400,
                ppid=40,
                name="Manus.exe",
                started_at=400.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "ManusAI.Manus_1.7.5.0_x64__package\\Manus.exe"
                ),
            ),
            ProcessSnapshot(
                pid=500,
                ppid=50,
                name="Perplexity.exe",
                started_at=500.0,
                executable_path=(
                    "C:\\Program Files\\WindowsApps\\"
                    "PerplexityAI.PerplexityApp_2026.9.15407.0_x64__package\\"
                    "app\\Perplexity.exe"
                ),
            ),
        ]

        applications = discover_root_processes(processes)

        self.assertEqual(
            [item.profile.name for item in applications],
            [
                "Claude",
                "Codex",
                "Gemini",
                "Manus",
                "Perplexity",
            ],
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
