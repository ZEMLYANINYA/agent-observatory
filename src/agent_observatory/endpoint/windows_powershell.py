from __future__ import annotations

import subprocess


_UTF8_PREAMBLE = (
    "[Console]::OutputEncoding = "
    "[System.Text.UTF8Encoding]::new($false)"
)


def run_powershell_text(command: str) -> str:
    """Run Windows PowerShell with an explicit UTF-8 stdout contract.

    Agent Observatory treats PowerShell output as evidence. Silent replacement
    of undecodable bytes can corrupt paths and command lines, so stdout is
    emitted as UTF-8 by PowerShell and decoded strictly by Python.
    """

    script = f"{_UTF8_PREAMBLE}\n{command}"

    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    return result.stdout
