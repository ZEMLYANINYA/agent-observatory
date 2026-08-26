import unittest

from agent_observatory.endpoint.correlation import (
    correlate_application_network,
    format_network_snapshot,
)
from agent_observatory.endpoint.discovery import (
    ApplicationProfile,
    DiscoveredApplication,
)
from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.windows_snapshot import (
    ApplicationSnapshot,
)


class CorrelationTests(unittest.TestCase):
    def test_correlates_connections_by_process_pid(self) -> None:
        root = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="ai-client.exe",
            started_at=100.0,
        )

        network_process = ProcessSnapshot(
            pid=101,
            ppid=100,
            name="ai-client.exe",
            started_at=101.0,
            command_line=(
                '"ai-client.exe" '
                '--type=utility '
                '--utility-sub-type=network.mojom.NetworkService'
            ),
        )

        application = DiscoveredApplication(
            profile=ApplicationProfile(
                name="ExampleAI",
                process_names=("ai-client.exe",),
            ),
            root_process=root,
        )

        snapshot = ApplicationSnapshot(
            application=application,
            processes=(root, network_process),
        )

        connections = (
            TcpConnection(
                pid=101,
                state="Established",
                local_address="192.0.2.10",
                local_port=50000,
                remote_address="198.51.100.20",
                remote_port=443,
            ),
        )

        correlated = correlate_application_network(
            (snapshot,),
            connections,
        )

        self.assertEqual(len(correlated), 1)
        self.assertEqual(
            len(correlated[0].processes[1].connections),
            1,
        )
        self.assertEqual(
            correlated[0].processes[1].connections[0].remote_port,
            443,
        )

    def test_ignores_connections_owned_by_unrelated_processes(self) -> None:
        root = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="ai-client.exe",
            started_at=100.0,
        )

        application = DiscoveredApplication(
            profile=ApplicationProfile(
                name="ExampleAI",
                process_names=("ai-client.exe",),
            ),
            root_process=root,
        )

        snapshot = ApplicationSnapshot(
            application=application,
            processes=(root,),
        )

        unrelated_connection = TcpConnection(
            pid=999,
            state="Established",
            local_address="192.0.2.10",
            local_port=50000,
            remote_address="198.51.100.20",
            remote_port=443,
        )

        correlated = correlate_application_network(
            (snapshot,),
            (unrelated_connection,),
        )

        self.assertEqual(
            correlated[0].processes[0].connections,
            (),
        )

    def test_formatter_hides_non_established_by_default(self) -> None:
        root = ProcessSnapshot(
            pid=100,
            ppid=10,
            name="ai-client.exe",
            started_at=100.0,
        )

        application = DiscoveredApplication(
            profile=ApplicationProfile(
                name="ExampleAI",
                process_names=("ai-client.exe",),
            ),
            root_process=root,
        )

        snapshot = ApplicationSnapshot(
            application=application,
            processes=(root,),
        )

        connections = (
            TcpConnection(
                pid=100,
                state="Bound",
                local_address="0.0.0.0",
                local_port=50000,
                remote_address="0.0.0.0",
                remote_port=0,
            ),
            TcpConnection(
                pid=100,
                state="Established",
                local_address="192.0.2.10",
                local_port=50001,
                remote_address="198.51.100.20",
                remote_port=443,
            ),
        )

        correlated = correlate_application_network(
            (snapshot,),
            connections,
        )

        output = format_network_snapshot(correlated)

        self.assertIn("198.51.100.20:443", output)
        self.assertNotIn("0.0.0.0:0", output)


if __name__ == "__main__":
    unittest.main()