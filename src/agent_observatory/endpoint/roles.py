from __future__ import annotations

from enum import Enum


class ProcessRole(str, Enum):
    MAIN = "main"
    RENDERER = "renderer"
    NETWORK = "network"
    GPU = "gpu"
    CRASHPAD = "crashpad"
    AUDIO = "audio"
    VIDEO_CAPTURE = "video-capture"
    UNKNOWN = "unknown"


def classify_process_role(
    command_line: str | None,
    *,
    is_root: bool = False,
) -> ProcessRole:
    """
    Classify an Electron/Chromium process using observable command-line
    metadata.

    Classification is intentionally conservative. Unknown or unsupported
    process types remain UNKNOWN rather than being guessed.
    """

    if is_root:
        return ProcessRole.MAIN

    if not command_line:
        return ProcessRole.UNKNOWN

    command = command_line.casefold()

    if "--type=crashpad-handler" in command:
        return ProcessRole.CRASHPAD

    if "--type=gpu-process" in command:
        return ProcessRole.GPU

    if "--type=renderer" in command:
        return ProcessRole.RENDERER

    if (
        "--type=utility" in command
        and "network.mojom.networkservice" in command
    ):
        return ProcessRole.NETWORK

    if (
        "--type=utility" in command
        and "audio.mojom.audioservice" in command
    ):
        return ProcessRole.AUDIO

    if (
        "--type=utility" in command
        and "video_capture.mojom.videocaptureservice" in command
    ):
        return ProcessRole.VIDEO_CAPTURE

    return ProcessRole.UNKNOWN