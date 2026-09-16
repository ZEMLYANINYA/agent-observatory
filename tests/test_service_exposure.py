import unittest

from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.service_exposure import (
    BindScope,
    DockerPublishedPort,
    HostTcpListener,
    classify_bind_scope,
    listeners_from_tcp_connections,
)


class ServiceExposureModelTests(unittest.TestCase):
    def test_bind_scope_classifies_wildcard_addresses(self) -> None:
        for address in ("0.0.0.0", "::", "::0", "*"):
            with self.subTest(address=address):
                self.assertEqual(classify_bind_scope(address), BindScope.WILDCARD)

    def test_bind_scope_classifies_loopback_addresses(self) -> None:
        self.assertEqual(classify_bind_scope("127.0.0.1"), BindScope.LOOPBACK)
        self.assertEqual(classify_bind_scope("127.12.34.56"), BindScope.LOOPBACK)
        self.assertEqual(classify_bind_scope("::1"), BindScope.LOOPBACK)

    def test_bind_scope_classifies_specific_and_unknown_addresses(self) -> None:
        self.assertEqual(classify_bind_scope("10.87.23.44"), BindScope.SPECIFIC)
        self.assertEqual(classify_bind_scope("2001:db8::10"), BindScope.SPECIFIC)
        self.assertEqual(classify_bind_scope("not-an-ip"), BindScope.UNKNOWN)

    def test_listener_projection_filters_non_listening_connections(self) -> None:
        connections = (
            TcpConnection(20, "Established", "10.0.0.5", 50000, "198.51.100.10", 443),
            TcpConnection(30, "Listen", "0.0.0.0", 11434, "0.0.0.0", 0),
            TcpConnection(10, "Listening", "127.0.0.1", 6379, "0.0.0.0", 0),
        )

        listeners = listeners_from_tcp_connections(connections)

        self.assertEqual(len(listeners), 2)
        self.assertEqual(
            tuple((item.local_address, item.local_port, item.owner_pid) for item in listeners),
            (("0.0.0.0", 11434, 30), ("127.0.0.1", 6379, 10)),
        )
        self.assertEqual(listeners[0].bind_scope, BindScope.WILDCARD)
        self.assertEqual(listeners[1].bind_scope, BindScope.LOOPBACK)
        self.assertTrue(all(item.owner_identity_basis == "pid_only_snapshot" for item in listeners))

    def test_listener_rejects_invalid_port(self) -> None:
        with self.assertRaises(ValueError):
            HostTcpListener(owner_pid=1, local_address="127.0.0.1", local_port=0)
        with self.assertRaises(ValueError):
            HostTcpListener(owner_pid=1, local_address="127.0.0.1", local_port=65536)

    def test_docker_publication_bind_scope_is_topological_only(self) -> None:
        published = DockerPublishedPort(
            container_id="abc123",
            container_name="ollama",
            image="ollama/ollama:latest",
            protocol="tcp",
            container_port=11434,
            host_address="0.0.0.0",
            host_port=11434,
        )

        self.assertEqual(published.bind_scope, BindScope.WILDCARD)
        self.assertEqual(published.observation_basis, "docker_inspect_running_container")
        self.assertFalse(hasattr(published, "reachable"))
        self.assertFalse(hasattr(published, "exploitable"))


if __name__ == "__main__":
    unittest.main()
