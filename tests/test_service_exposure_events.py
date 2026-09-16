import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.service_exposure import (
    DockerPublishedPort,
    HostTcpListener,
    ListenerAttributionState,
)
from agent_observatory.evidence import (
    docker_published_port_event,
    tcp_listener_event,
)
from agent_observatory.storage import EventStore, EventType


class ServiceExposureEventTests(unittest.TestCase):
    def test_tcp_listener_event_preserves_pid_only_attribution(self) -> None:
        listener = HostTcpListener(
            owner_pid=1234,
            local_address="0.0.0.0",
            local_port=11434,
            state="Listen",
        )

        event = tcp_listener_event(
            listener,
            observed_at=10.5,
            source="service-exposure-test",
            stream_id="exposure:1",
        )

        self.assertEqual(event.event_type, EventType.TCP_LISTENER_OBSERVED)
        self.assertEqual(event.payload["protocol"], "tcp")
        self.assertEqual(event.payload["owner_pid"], 1234)
        self.assertEqual(event.payload["owner_identity_basis"], "pid_only_snapshot")
        self.assertEqual(event.payload["attribution_state"], "unresolved")
        self.assertEqual(
            event.payload["attribution_reason"],
            "process_instance_not_bracket_validated",
        )
        self.assertIsNone(event.payload["process"])
        self.assertIsNone(event.payload["process_name"])
        self.assertIsNone(event.payload["executable_path"])
        self.assertEqual(event.payload["bind_scope"], "wildcard")
        self.assertEqual(event.payload["observation_basis"], "windows_get_nettcpconnection_snapshot")
        self.assertNotIn("reachable", event.payload)
        self.assertNotIn("exploitable", event.payload)

    def test_tcp_listener_event_preserves_bracketed_process_identity(self) -> None:
        listener = HostTcpListener(
            owner_pid=4321,
            local_address="127.0.0.1",
            local_port=8000,
            owner_identity_basis="stable_process_instance",
            attribution_state=ListenerAttributionState.ATTRIBUTED,
            process_started_at=123.5,
            process_name="service.exe",
            executable_path=r"C:\Service\service.exe",
            attribution_reason=None,
        )

        event = tcp_listener_event(
            listener,
            observed_at=20.0,
            source="service-exposure-test",
            stream_id="exposure:2",
            observation_basis="windows_bracketed_process_tcp_capture",
        )

        self.assertEqual(event.payload["attribution_state"], "attributed")
        self.assertEqual(event.payload["owner_identity_basis"], "stable_process_instance")
        self.assertEqual(event.payload["process"], {"pid": 4321, "started_at": 123.5})
        self.assertEqual(event.payload["process_name"], "service.exe")
        self.assertEqual(event.payload["executable_path"], r"C:\Service\service.exe")
        self.assertIsNone(event.payload["attribution_reason"])
        self.assertEqual(
            event.payload["observation_basis"],
            "windows_bracketed_process_tcp_capture",
        )

    def test_docker_published_port_event_preserves_mapping_without_verdict(self) -> None:
        published = DockerPublishedPort(
            container_id="container-123",
            container_name="redis",
            image="redis:7",
            protocol="tcp",
            container_port=6379,
            host_address="127.0.0.1",
            host_port=16379,
        )

        event = docker_published_port_event(
            published,
            observed_at=20.0,
            source="service-exposure-test",
            stream_id="exposure:1",
        )

        self.assertEqual(event.event_type, EventType.DOCKER_PORT_PUBLISHED)
        self.assertEqual(
            event.payload["container"],
            {"id": "container-123", "name": "redis", "image": "redis:7"},
        )
        self.assertEqual(event.payload["container_port"], 6379)
        self.assertEqual(event.payload["host_address"], "127.0.0.1")
        self.assertEqual(event.payload["host_port"], 16379)
        self.assertEqual(event.payload["bind_scope"], "loopback")
        self.assertNotIn("reachable", event.payload)
        self.assertNotIn("authenticated", event.payload)
        self.assertNotIn("vulnerable", event.payload)

    def test_service_exposure_events_round_trip_through_event_store(self) -> None:
        listener_event = tcp_listener_event(
            HostTcpListener(
                owner_pid=200,
                local_address="127.0.0.1",
                local_port=8000,
            ),
            observed_at=1.0,
            source="service-exposure-test",
            stream_id="exposure:roundtrip",
        )
        docker_event = docker_published_port_event(
            DockerPublishedPort(
                container_id="abc",
                container_name="n8n",
                image="n8nio/n8n:latest",
                protocol="tcp",
                container_port=5678,
                host_address="0.0.0.0",
                host_port=5678,
            ),
            observed_at=2.0,
            source="service-exposure-test",
            stream_id="exposure:roundtrip",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = store.append_many((listener_event, docker_event))
            loaded = store.read_events(stream_id="exposure:roundtrip")

        self.assertEqual(len(stored), 2)
        self.assertEqual(
            tuple(event.event_type for event in loaded),
            (EventType.TCP_LISTENER_OBSERVED, EventType.DOCKER_PORT_PUBLISHED),
        )
        self.assertEqual(loaded[0].payload["local_port"], 8000)
        self.assertEqual(loaded[1].payload["host_port"], 5678)


if __name__ == "__main__":
    unittest.main()
