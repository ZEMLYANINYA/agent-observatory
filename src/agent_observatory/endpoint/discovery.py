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
)

def discover_root_processes(
    processes: Iterable[ProcessSnapshot],
    profiles: Iterable[ApplicationProfile] = DEFAULT_PROFILES,
) -> tuple[DiscoveredApplication, ...]:
    """
    Discover likely AI application root processes.

    A process is considered a root candidate when:
    - its executable name matches a configured application profile;
    - its reported parent process is not another process with the same
      executable name.

    This intentionally avoids assuming that every process with a matching
    name is a separate application instance.
    """

    process_list = list(processes)
    by_pid = {process.pid: process for process in process_list}

    discovered: list[DiscoveredApplication] = []

    for profile in profiles:
        expected_names = {
            name.casefold()
            for name in profile.process_names
        }

        for process in process_list:
            if process.name.casefold() not in expected_names:
                continue

            parent = by_pid.get(process.ppid)

            if (
                parent is not None
                and parent.name.casefold() in expected_names
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
