from __future__ import annotations

from dataclasses import dataclass

from .models import ProcessSnapshot


@dataclass(frozen=True, slots=True)
class ApplicationProfile:
    name: str
    process_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiscoveredApplication:
    profile: ApplicationProfile
    root_process: ProcessSnapshot


@dataclass(frozen=True, slots=True)
class ApplicationSnapshot:
    application: DiscoveredApplication
    processes: tuple[ProcessSnapshot, ...]