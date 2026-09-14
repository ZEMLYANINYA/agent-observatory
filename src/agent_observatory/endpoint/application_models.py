from __future__ import annotations

from dataclasses import dataclass

from .models import ProcessSnapshot


@dataclass(frozen=True, slots=True)
class ApplicationProfile:
    """Declarative evidence used to identify an application root process."""

    name: str
    process_names: tuple[str, ...]
    executable_path_contains: tuple[str, ...] = ()
    command_line_contains: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DiscoveredApplication:
    profile: ApplicationProfile
    root_process: ProcessSnapshot


@dataclass(frozen=True, slots=True)
class ApplicationSnapshot:
    application: DiscoveredApplication
    processes: tuple[ProcessSnapshot, ...]
