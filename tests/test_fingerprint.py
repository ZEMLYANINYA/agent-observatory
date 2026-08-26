import unittest

from agent_observatory.endpoint.fingerprint import (
    fingerprint_process,
)
from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.roles import ProcessRole


class ProcessFingerprintTests(unittest.TestCase):
    def test_root_process_fingerprint(self) -> None:
        process = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="Claude.exe",
            started_at=100.0,
        )

        fingerprint = fingerprint_process(
            process,
            is_root=True,
        )

        self.assertEqual(
            fingerprint.name,
            "claude.exe",
        )
        self.assertEqual(
            fingerprint.role,
            ProcessRole.MAIN,
        )
        self.assertEqual(
            fingerprint.markers,
            (),
        )

    def test_renderer_fingerprint_keeps_stable_type(self) -> None:
        process = ProcessSnapshot(
            pid=101,
            ppid=100,
            name="client.exe",
            started_at=101.0,
            command_line=(
                '"client.exe" '
                '--type=renderer '
                '--renderer-client-id=123 '
                '--launch-time-ticks=999'
            ),
        )

        fingerprint = fingerprint_process(process)

        self.assertEqual(
            fingerprint.role,
            ProcessRole.RENDERER,
        )
        self.assertEqual(
            fingerprint.markers,
            ("--type=renderer",),
        )

    def test_network_service_keeps_utility_role_markers(self) -> None:
        process = ProcessSnapshot(
            pid=102,
            ppid=100,
            name="client.exe",
            started_at=102.0,
            command_line=(
                '"client.exe" '
                '--type=utility '
                '--utility-sub-type=network.mojom.NetworkService '
                '--trace-process-track-uuid=12345 '
                '--mojo-platform-channel-handle=888'
            ),
        )

        fingerprint = fingerprint_process(process)

        self.assertEqual(
            fingerprint.role,
            ProcessRole.NETWORK,
        )
        self.assertEqual(
            fingerprint.markers,
            (
                "--type=utility",
                "--utility-sub-type=network.mojom.networkservice",
            ),
        )

    def test_dynamic_values_do_not_change_fingerprint(self) -> None:
        first = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="client.exe",
            started_at=100.0,
            command_line=(
                '"client.exe" '
                '--type=renderer '
                '--renderer-client-id=1 '
                '--trace-process-track-uuid=111'
            ),
        )

        second = ProcessSnapshot(
            pid=200,
            ppid=20,
            name="client.exe",
            started_at=200.0,
            command_line=(
                '"client.exe" '
                '--type=renderer '
                '--renderer-client-id=999 '
                '--trace-process-track-uuid=999999'
            ),
        )

        self.assertEqual(
            fingerprint_process(first),
            fingerprint_process(second),
        )

    def test_different_stable_roles_produce_different_fingerprints(self) -> None:
        renderer = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="client.exe",
            started_at=100.0,
            command_line='"client.exe" --type=renderer',
        )

        gpu = ProcessSnapshot(
            pid=200,
            ppid=10,
            name="client.exe",
            started_at=100.0,
            command_line='"client.exe" --type=gpu-process',
        )

        self.assertNotEqual(
            fingerprint_process(renderer),
            fingerprint_process(gpu),
        )

    def test_process_name_matching_is_case_insensitive(self) -> None:
        first = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="Helper.EXE",
            started_at=100.0,
        )

        second = ProcessSnapshot(
            pid=200,
            ppid=20,
            name="helper.exe",
            started_at=200.0,
        )

        self.assertEqual(
            fingerprint_process(first),
            fingerprint_process(second),
        )


if __name__ == "__main__":
    unittest.main()