import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.service_exposure import (
    DockerPublishedPort,
    HostTcpListener,
    ListenerAttributionState,
)
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.evidence import (
    CollectorStatus,
    ServiceExposureCapture,
    ServiceExposureCollectorReport,
    append_service_exposure_batch,
    append_service_exposure_capture,
    collect_service_exposure_capture,
    service_exposure_capture_event_batch,
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

    @classmethod
    def _windows_capture(cls):
        stable_before = ProcessSnapshot(
            pid=10,
            ppid=1,
            name="ollama.exe",
            started_at=5.0,
            command_line="ollama serve",
            executable_path=r"C:\Apps\ollama.exe",
        )
        stable_after = ProcessSnapshot(
            pid=10,
            ppid=1,
            name="ollama.exe",
            started_at=5.0,
            command_line="ollama serve",
            executable_path=r"C:\Apps\ollama.exe",
        )
        reused_before = ProcessSnapshot(
            pid=20,
            ppid=1,
            name="redis-server.exe",
            started_at=6.0,
            command_line="redis-server.exe",
            executable_path=r"C:\Redis\redis-server.exe",
        )
        reused_after = ProcessSnapshot(
            pid=20,
            ppid=1,
            name="other.exe",
            started_at=7.0,
            command_line="other.exe",
            executable_path=r"C:\Temp\other.exe",
        )
        return WindowsCapture(
            processes_before=(stable_before, reused_before),
            tcp_connections=cls._tcp_connections(),
            processes_after=(stable_after, reused_after),
            process_before_interval=CaptureInterval(1.0, 2.0),
            network_interval=CaptureInterval(3.0, 4.0),
            process_after_interval=CaptureInterval(5.0, 6.0),
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

    @staticmethod
    def _clock(*values):
        iterator = iter(values)
        return lambda: next(iterator)

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

    def test_live_capture_uses_bracketed_listener_attribution(self) -> None:
        capture = collect_service_exposure_capture(
            windows_capture_provider=self._windows_capture,
            docker_provider=lambda: (),
            clock=self._clock(20.0, 30.0),
        )

        self.assertFalse(capture.has_failures)
        self.assertEqual(len(capture.listeners), 2)
        self.assertEqual(capture.docker_ports, ())
        self.assertEqual(capture.listener_observed_at, 4.0)
        self.assertEqual(capture.docker_observed_at, 20.0)
        self.assertEqual(capture.manifest_observed_at, 30.0)

        by_pid = {listener.owner_pid: listener for listener in capture.listeners}
        attributed = by_pid[10]
        unresolved = by_pid[20]
        self.assertEqual(attributed.attribution_state, ListenerAttributionState.ATTRIBUTED)
        self.assertEqual(attributed.process_started_at, 5.0)
        self.assertEqual(attributed.process_name, "ollama.exe")
        self.assertEqual(attributed.owner_identity_basis, "stable_process_instance")
        self.assertEqual(unresolved.attribution_state, ListenerAttributionState.UNRESOLVED)
        self.assertEqual(
            unresolved.attribution_reason,
            "owner_pid_not_stable_across_process_bracket",
        )

        windows_report = capture.collector_reports[0]
        self.assertEqual(windows_report.status, CollectorStatus.SUCCEEDED)
        self.assertEqual(windows_report.record_count, 2)
        self.assertEqual(
            windows_report.observation_basis,
            "windows_bracketed_get_nettcpconnection_snapshot",
        )
        self.assertEqual(
            (capture.collector_reports[1].status, capture.collector_reports[1].record_count),
            (CollectorStatus.SUCCEEDED, 0),
        )

    def test_live_capture_preserves_docker_failure_in_manifest_state(self) -> None:
        def fail_docker():
            raise RuntimeError("docker daemon unavailable")

        capture = collect_service_exposure_capture(
            windows_capture_provider=self._windows_capture,
            docker_provider=fail_docker,
            clock=self._clock(20.0),
        )

        self.assertTrue(capture.has_failures)
        self.assertEqual(len(capture.listeners), 2)
        self.assertEqual(capture.docker_ports, ())
        docker_report = capture.collector_reports[1]
        self.assertEqual(docker_report.status, CollectorStatus.FAILED)
        self.assertIsNone(docker_report.record_count)
        self.assertEqual(docker_report.error_type, "RuntimeError")
        self.assertEqual(docker_report.error_message, "docker daemon unavailable")

    def test_live_capture_explicit_docker_skip_is_not_failure(self) -> None:
        def docker_must_not_run():
            raise AssertionError("docker provider should not run")

        capture = collect_service_exposure_capture(
            include_docker=False,
            windows_capture_provider=self._windows_capture,
            docker_provider=docker_must_not_run,
            clock=self._clock(20.0),
        )

        self.assertFalse(capture.has_failures)
        report = capture.collector_reports[1]
        self.assertEqual(report.status, CollectorStatus.SKIPPED)
        self.assertIsNone(report.record_count)
        self.assertIsNone(capture.docker_observed_at)

    def test_zero_record_live_capture_still_emits_one_manifest(self) -> None:
        capture = ServiceExposureCapture(
            listeners=(),
            docker_ports=(),
            listener_observed_at=10.0,
            docker_observed_at=20.0,
            manifest_observed_at=30.0,
            collector_reports=(
                ServiceExposureCollectorReport(
                    collector="windows_tcp_listeners",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=0,
                    observation_basis="windows_bracketed_get_nettcpconnection_snapshot",
                ),
                ServiceExposureCollectorReport(
                    collector="docker_published_ports",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=0,
                    observation_basis="docker_inspect_running_container",
                ),
            ),
        )

        batch = service_exposure_capture_event_batch(
            capture,
            source="service-exposure-test",
            stream_id="exposure:zero",
        )

        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0].event_type, EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST)
        self.assertFalse(batch[0].payload["partial"])
        self.assertEqual(
            [item["record_count"] for item in batch[0].payload["collectors"]],
            [0, 0],
        )

    def test_append_live_capture_persists_facts_and_manifest_atomically(self) -> None:
        capture = ServiceExposureCapture(
            listeners=(HostTcpListener(10, "0.0.0.0", 11434),),
            docker_ports=(self._docker_ports()[1],),
            listener_observed_at=10.0,
            docker_observed_at=20.0,
            manifest_observed_at=30.0,
            collector_reports=(
                ServiceExposureCollectorReport(
                    collector="windows_tcp_listeners",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=1,
                    observation_basis="windows_bracketed_get_nettcpconnection_snapshot",
                ),
                ServiceExposureCollectorReport(
                    collector="docker_published_ports",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=1,
                    observation_basis="docker_inspect_running_container",
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = append_service_exposure_capture(
                store,
                capture,
                source="service-exposure-test",
                stream_id="exposure:live",
            )
            loaded = store.read_events(stream_id="exposure:live")

        self.assertEqual(
            tuple(event.event_type for event in stored),
            (
                EventType.TCP_LISTENER_OBSERVED,
                EventType.DOCKER_PORT_PUBLISHED,
                EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
            ),
        )
        self.assertEqual(tuple(event.event_id for event in loaded), (1, 2, 3))
        self.assertEqual(loaded[-1].payload["capture_kind"], "service_exposure")

    def test_failed_collector_cannot_claim_zero_records(self) -> None:
        with self.assertRaises(ValueError):
            ServiceExposureCollectorReport(
                collector="docker_published_ports",
                status=CollectorStatus.FAILED,
                record_count=0,
                error_type="RuntimeError",
                error_message="failed",
            )


if __name__ == "__main__":
    unittest.main()
