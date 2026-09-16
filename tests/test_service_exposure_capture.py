import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.service_exposure import DockerPublishedPort
from agent_observatory.evidence import (
    append_service_exposure_batch,
    service_exposure_event_batch,
)
from agent_observatory.storage import EventStore, EventType


class ServiceExposureCaptureTests(unittest.TestCase):
    @staticmethod
    def _tcp_connections():
        return (
            TcpConnection(30, "Established", "10.0.0.5", 50000, "198.51.100.1", 443),
            TcpConnection(20, "Listen", "127.0.0.1", 6379, "0.0.0.0", 0),
            TcpConnection(10, "Listen", "0.0.0.0", 11434, "0.0.0.0", 0),
        )

    @staticmethod
    def _docker_ports():
        return (
            DockerPublishedPort(
                container_id="z",
                container_name="zeta",
                image="zeta:latest",
                protocol="tcp",
                container_port=9000,
                host_address="127.0.0.1",
                host_port=9000,
            ),
            DockerPublishedPort(
                container_id="a",
                container_name="alpha",
                image="alpha:latest",
                protocol="tcp",
                container_port=8000,
                host_address="0.0.0.0",
                host_port=8000,
            ),
        )

    def test_batch_filters_connections_and_preserves_separate_time_anchors(self) -> None:
        batch = service_exposure_event_batch(
            self._tcp_connections(),
            self._docker_ports(),
            tcp_observed_at=10.0,
            docker_observed_at=20.0,
            source="service-exposure-test",
            stream_id="exposure:1",
        )

        self.assertEqual(len(batch), 4)
        self.assertEqual(
            tuple(event.event_type for event in batch),
            (
                EventType.TCP_LISTENER_OBSERVED,
                EventType.TCP_LISTENER_OBSERVED,
                EventType.DOCKER_PORT_PUBLISHED,
                EventType.DOCKER_PORT_PUBLISHED,
            ),
        )
        self.assertEqual(tuple(event.observed_at for event in batch[:2]), (10.0, 10.0))
        self.assertEqual(tuple(event.observed_at for event in batch[2:]), (20.0, 20.0))
        self.assertEqual(
            tuple(event.payload["local_port"] for event in batch[:2]),
            (11434, 6379),
        )
        self.assertEqual(
            tuple(event.payload["container"]["name"] for event in batch[2:]),
            ("alpha", "zeta"),
        )

    def test_batch_is_deterministic_for_input_order(self) -> None:
        first = service_exposure_event_batch(
            self._tcp_connections(),
            self._docker_ports(),
            tcp_observed_at=10.0,
            docker_observed_at=20.0,
            source="service-exposure-test",
            stream_id="exposure:1",
        )
        second = service_exposure_event_batch(
            reversed(self._tcp_connections()),
            reversed(self._docker_ports()),
            tcp_observed_at=10.0,
            docker_observed_at=20.0,
            source="service-exposure-test",
            stream_id="exposure:1",
        )

        self.assertEqual(first, second)

    def test_append_service_exposure_batch_is_atomic_eventstore_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = append_service_exposure_batch(
                store,
                self._tcp_connections(),
                self._docker_ports(),
                tcp_observed_at=10.0,
                docker_observed_at=20.0,
                source="service-exposure-test",
                stream_id="exposure:atomic",
            )
            loaded = store.read_events(stream_id="exposure:atomic")

        self.assertEqual(len(stored), 4)
        self.assertEqual(tuple(event.event_id for event in stored), (1, 2, 3, 4))
        self.assertEqual(tuple(event.event_id for event in loaded), (1, 2, 3, 4))

    def test_batch_rejects_empty_source_and_stream(self) -> None:
        with self.assertRaises(ValueError):
            service_exposure_event_batch(
                (),
                (),
                tcp_observed_at=1.0,
                docker_observed_at=2.0,
                source="",
                stream_id="exposure:1",
            )
        with self.assertRaises(ValueError):
            service_exposure_event_batch(
                (),
                (),
                tcp_observed_at=1.0,
                docker_observed_at=2.0,
                source="service-exposure-test",
                stream_id="",
            )


if __name__ == "__main__":
    unittest.main()
