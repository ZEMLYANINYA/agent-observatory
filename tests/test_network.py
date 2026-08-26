import unittest

from agent_observatory.endpoint.network import (
    TcpConnection,
    connections_by_pid,
    connections_for_processes,
)


class TcpConnectionTests(unittest.TestCase):
    def test_established_state_is_case_insensitive(self) -> None:
        connection = TcpConnection(
            pid=100,
            state="Established",
            local_address="192.0.2.10",
            local_port=50000,
            remote_address="198.51.100.20",
            remote_port=443,
        )

        self.assertTrue(connection.is_established)

    def test_non_established_connection(self) -> None:
        connection = TcpConnection(
            pid=100,
            state="Bound",
            local_address="0.0.0.0",
            local_port=50000,
            remote_address="0.0.0.0",
            remote_port=0,
        )

        self.assertFalse(connection.is_established)

    def test_groups_connections_by_pid(self) -> None:
        connections = (
            TcpConnection(
                pid=100,
                state="Established",
                local_address="192.0.2.10",
                local_port=50000,
                remote_address="198.51.100.20",
                remote_port=443,
            ),
            TcpConnection(
                pid=100,
                state="Established",
                local_address="192.0.2.10",
                local_port=50001,
                remote_address="198.51.100.30",
                remote_port=443,
            ),
            TcpConnection(
                pid=200,
                state="Listen",
                local_address="127.0.0.1",
                local_port=8000,
                remote_address="0.0.0.0",
                remote_port=0,
            ),
        )

        grouped = connections_by_pid(connections)

        self.assertEqual(len(grouped[100]), 2)
        self.assertEqual(len(grouped[200]), 1)

    def test_filters_connections_for_process_set(self) -> None:
        connections = (
            TcpConnection(
                pid=100,
                state="Established",
                local_address="192.0.2.10",
                local_port=50000,
                remote_address="198.51.100.20",
                remote_port=443,
            ),
            TcpConnection(
                pid=200,
                state="Established",
                local_address="192.0.2.10",
                local_port=50001,
                remote_address="198.51.100.30",
                remote_port=443,
            ),
        )

        selected = connections_for_processes(
            connections,
            process_ids=(100,),
        )

        self.assertEqual(len(selected), 1)
        self.assertEqual(selected[0].pid, 100)


if __name__ == "__main__":
    unittest.main()