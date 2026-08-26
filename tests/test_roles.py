import unittest

from agent_observatory.endpoint.roles import (
    ProcessRole,
    classify_process_role,
)


class ProcessRoleTests(unittest.TestCase):
    def test_root_is_main(self) -> None:
        role = classify_process_role(
            None,
            is_root=True,
        )

        self.assertEqual(role, ProcessRole.MAIN)

    def test_renderer(self) -> None:
        role = classify_process_role(
            '"client.exe" --type=renderer --lang=ru'
        )

        self.assertEqual(role, ProcessRole.RENDERER)

    def test_network_service(self) -> None:
        role = classify_process_role(
            '"client.exe" --type=utility '
            '--utility-sub-type=network.mojom.NetworkService'
        )

        self.assertEqual(role, ProcessRole.NETWORK)

    def test_gpu_process(self) -> None:
        role = classify_process_role(
            '"client.exe" --type=gpu-process'
        )

        self.assertEqual(role, ProcessRole.GPU)

    def test_crashpad_handler(self) -> None:
        role = classify_process_role(
            '"client.exe" --type=crashpad-handler'
        )

        self.assertEqual(role, ProcessRole.CRASHPAD)

    def test_audio_service(self) -> None:
        role = classify_process_role(
            '"client.exe" --type=utility '
            '--utility-sub-type=audio.mojom.AudioService'
        )

        self.assertEqual(role, ProcessRole.AUDIO)

    def test_video_capture_service(self) -> None:
        role = classify_process_role(
            '"client.exe" --type=utility '
            '--utility-sub-type=video_capture.mojom.VideoCaptureService'
        )

        self.assertEqual(role, ProcessRole.VIDEO_CAPTURE)

    def test_unknown_utility_is_not_guessed(self) -> None:
        role = classify_process_role(
            '"client.exe" --type=utility '
            '--utility-sub-type=example.mojom.UnknownService'
        )

        self.assertEqual(role, ProcessRole.UNKNOWN)

    def test_missing_command_line_is_unknown(self) -> None:
        role = classify_process_role(None)

        self.assertEqual(role, ProcessRole.UNKNOWN)

    def test_matching_is_case_insensitive(self) -> None:
        role = classify_process_role(
            '"CLIENT.EXE" --TYPE=RENDERER'
        )

        self.assertEqual(role, ProcessRole.RENDERER)


if __name__ == "__main__":
    unittest.main()