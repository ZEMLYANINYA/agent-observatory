import unittest

from agent_observatory.endpoint.windows_network import (
    parse_tcp_inventory,
)


class WindowsTcpInventoryTests(unittest.TestCase):
    def test_empty_inventory(self) -> None:
        self.assertEqual(
            parse_tcp_inventory(""),
            (),
        )

    def test_single_record(self) -> None:
        raw = """
        {
            "pid": 100,
            "state": "Established",
            "local_address": "192.0.2.10",
            "local_port": 50000,
            "remote_address": "198.51.100.20",
            "remote_port": 443
        }
        """

        connections = parse_tcp_inventory(raw)

        self.assertEqual(len(connections), 1)
        self.assertEqual(connections[0].pid, 100)
        self.assertEqual(connections[0].remote_port, 443)

    def test_multiple_records(self) -> None:
        raw = """
        [
            {
                "pid": 100,
                "state": "Established",
                "local_address": "192.0.2.10",
                "local_port": 50000,
                "remote_address": "198.51.100.20",
                "remote_port": 443
            },
            {
                "pid": 200,
                "state": "Listen",
                "local_address": "127.0.0.1",
                "local_port": 8000,
                "remote_address": "0.0.0.0",
                "remote_port": 0
            }
        ]
        """

        connections = parse_tcp_inventory(raw)

        self.assertEqual(len(connections), 2)
        self.assertEqual(
            [connection.pid for connection in connections],
            [100, 200],
        )


if __name__ == "__main__":
    unittest.main()