from __future__ import annotations

import argparse
import time
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Harmless long-lived child used by EXP-003 Fixture C."
    )
    parser.add_argument(
        "--stop-file",
        type=Path,
        required=True,
        help="Exit early when this file appears.",
    )
    parser.add_argument(
        "--seconds",
        type=float,
        default=60.0,
        help="Maximum lifetime in seconds (default: 60).",
    )
    args = parser.parse_args(argv)

    if args.seconds <= 0:
        parser.error("--seconds must be greater than zero")

    deadline = time.monotonic() + args.seconds
    while time.monotonic() < deadline:
        if args.stop_file.exists():
            return 0
        time.sleep(0.05)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
