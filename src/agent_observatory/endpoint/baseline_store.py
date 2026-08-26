from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .fingerprint import ProcessFingerprint
from .roles import ProcessRole


BASELINE_SCHEMA_VERSION = 1


def save_process_baseline(
    path: str | Path,
    fingerprints: Iterable[ProcessFingerprint],
) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    records = [
        {
            "name": item.name,
            "role": item.role.value,
            "markers": list(item.markers),
        }
        for item in sorted(
            set(fingerprints),
            key=lambda item: (
                item.name,
                item.role.value,
                item.markers,
            ),
        )
    ]

    payload = {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "process_fingerprints": records,
    }

    target.write_text(
        json.dumps(
            payload,
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


def load_process_baseline(
    path: str | Path,
) -> tuple[ProcessFingerprint, ...]:
    source = Path(path)

    payload = json.loads(
        source.read_text(encoding="utf-8")
    )

    schema_version = payload.get("schema_version")

    if schema_version != BASELINE_SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported baseline schema version: "
            f"{schema_version!r}"
        )

    fingerprints: list[ProcessFingerprint] = []

    for record in payload.get("process_fingerprints", []):
        fingerprints.append(
            ProcessFingerprint(
                name=str(record["name"]),
                role=ProcessRole(record["role"]),
                markers=tuple(record.get("markers", ())),
            )
        )

    return tuple(fingerprints)