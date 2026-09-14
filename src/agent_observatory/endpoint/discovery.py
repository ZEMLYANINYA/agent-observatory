from __future__ import annotations

from typing import Iterable

from .application_models import (
    ApplicationProfile,
    DiscoveredApplication,
)
from .models import ProcessSnapshot


DEFAULT_PROFILES: tuple[ApplicationProfile, ...] = (
    ApplicationProfile(
        name="ChatGPT",
        process_names=("ChatGPT Classic.exe",),
    ),
    ApplicationProfile(
        name="Claude",
        process_names=("claude.exe",),
    ),
    ApplicationProfile(
        name="Codex",
        process_names=("ChatGPT.exe",),
        executable_path_contains=("\\WindowsApps\\OpenAI.Codex_",),
    ),
    ApplicationProfile(
        name="Gemini",
        process_names=("Gemini.exe",),
        executable_path_contains=("\\Google\\Gemini\\",),
    ),
    ApplicationProfile(
        name="Manus",
        process_names=("Manus.exe",),
        executable_path_contains=("\\WindowsApps\\ManusAI.Manus_",),
    ),
    ApplicationProfile(
        name="Perplexity",
        process_names=("Perplexity.exe",),
        executable_path_contains=(
            "\\WindowsApps\\PerplexityAI.PerplexityApp_",
        ),
    ),
)


def _matches_optional_contains(
    value: str | None,
    markers: tuple[str, ...],
) -> bool:
    if not markers:
        return True

    if value is None:
        return False

    normalized = value.casefold()

    return any(
        marker.casefold() in normalized
        for marker in markers
    )


def matches_application_profile(
    process: ProcessSnapshot,
    profile: ApplicationProfile,
) -> bool:
    """
    Return whether one process satisfies all configured profile evidence.

    Process-name matching is always required. Optional path and command-line
    groups are ANDed with the name check. Within each optional group, any one
    configured marker is sufficient. Matching is case-insensitive.
    """

    expected_names = {
        name.casefold()
        for name in profile.process_names
    }

    if process.name.casefold() not in expected_names:
        return False

    if not _matches_optional_contains(
        process.executable_path,
        profile.executable_path_contains,
    ):
        return False

    return _matches_optional_contains(
        process.command_line,
        profile.command_line_contains,
    )


def discover_root_processes(
    processes: Iterable[ProcessSnapshot],
    profiles: Iterable[ApplicationProfile] = DEFAULT_PROFILES,
) -> tuple[DiscoveredApplication, ...]:
    """
    Discover likely AI application root processes.

    A process is considered a root candidate when it matches the configured
    application profile and its reported parent does not match that same
    profile. This avoids treating same-application Electron children as roots
    while still allowing different applications to share an executable name.
    """

    process_list = list(processes)
    by_pid = {process.pid: process for process in process_list}

    discovered: list[DiscoveredApplication] = []

    for profile in profiles:
        for process in process_list:
            if not matches_application_profile(process, profile):
                continue

            parent = by_pid.get(process.ppid)

            if (
                parent is not None
                and matches_application_profile(parent, profile)
            ):
                continue

            discovered.append(
                DiscoveredApplication(
                    profile=profile,
                    root_process=process,
                )
            )

    return tuple(
        sorted(
            discovered,
            key=lambda item: (
                item.profile.name.casefold(),
                item.root_process.pid,
            ),
        )
    )
