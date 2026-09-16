import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_observatory.endpoint.service_exposure import (
    DockerPublishedPort,
    HostTcpListener,
)
from agent_observatory.evidence import (
    CollectorStatus,
    ServiceExposureCapture,
    ServiceExposureCollectorReport,
    append_service_exposure_capture,
)
from agent_observatory.storage import EventStore, EventType
from tools import service_exposure_capture as tool


class ServiceExposureCaptureToolTests(unittest.TestCase):
    @staticmethod
    def _report(
        collector: str,
        status: CollectorStatus,
        record_count,
        *,
        observation_basis=None,
        error_type=None,
        error_message=None,
    ) -> ServiceExposureCollectorReport:
        return ServiceExposureCollectorReport(
            collector=collector,
            status=status,
            record_count=record_count,
            observation_basis=observation_basis,
            error_type=error_type,
            error_message=error_message,
        )

    def _success_capture(self, *, docker_status=CollectorStatus.SUCCEEDED):
        docker_ports = ()
        docker_observed_at = 20.0 if docker_status is CollectorStatus.SUCCEEDED else None
        docker_count = 0 if docker_status is CollectorStatus.SUCCEEDED else None
        return ServiceExposureCapture(
            listeners=(HostTcpListener(101, "0.0.0.0", 11434),),
            docker_ports=docker_ports,
            listener_observed_at=10.0,
            docker_observed_at=docker_observed_at,
            manifest_observed_at=30.0,
            collector_reports=(
                self._report(
                    "windows_tcp_listeners",
                    CollectorStatus.SUCCEEDED,
                    1,
                    observation_basis="windows_get_nettcpconnection_snapshot",
                ),
                self._report(
                    "docker_published_ports",
                    docker_status,
                    docker_count,
                    observation_basis=(
                        "docker_inspect_running_container"
                        if docker_status is CollectorStatus.SUCCEEDED
                        else None
                    ),
                ),
            ),
        )

    def _partial_capture(self):
        return ServiceExposureCapture(
            listeners=(HostTcpListener(101, "127.0.0.1", 6379),),
            docker_ports=(),
            listener_observed_at=10.0,
            docker_observed_at=None,
            manifest_observed_at=20.0,
            collector_reports=(
                self._report(
                    "windows_tcp_listeners",
                    CollectorStatus.SUCCEEDED,
                    1,
                    observation_basis="windows_get_nettcpconnection_snapshot",
                ),
                self._report(
                    "docker_published_ports",
                    CollectorStatus.FAILED,
                    None,
                    error_type="DockerCollectionError",
                    error_message="docker executable was not found",
                ),
            ),
        )

    @staticmethod
    def _patched_capture_into_store(capture, observed_include_docker=None):
        def implementation(store, *, source, stream_id, include_docker=True):
            if observed_include_docker is not None:
                observed_include_docker.append(include_docker)
            appended = append_service_exposure_capture(
                store,
                capture,
                source=source,
                stream_id=stream_id,
            )
            return capture, appended

        return implementation

    def test_capture_into_store_uses_real_eventstore_and_manifest(self) -> None:
        capture = self._success_capture()

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")

            def provider(*, include_docker):
                self.assertTrue(include_docker)
                return capture

            returned, appended = tool.capture_into_store(
                store,
                source="tool-test",
                stream_id="service-exposure:test",
                capture_provider=provider,
            )
            loaded = store.read_events(stream_id="service-exposure:test")

        self.assertIs(returned, capture)
        self.assertEqual(tuple(event.event_id for event in appended), (1, 2))
        self.assertEqual(tuple(event.event_id for event in loaded), (1, 2))
        self.assertEqual(
            tuple(event.event_type for event in loaded),
            (
                EventType.TCP_LISTENER_OBSERVED,
                EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
            ),
        )

    def test_main_success_distinguishes_zero_docker_publications(self) -> None:
        capture = self._success_capture()
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "events.sqlite3"
            stdout = io.StringIO()
            with patch.object(
                tool,
                "capture_into_store",
                side_effect=self._patched_capture_into_store(capture),
            ), redirect_stdout(stdout):
                code = tool.main(
                    [
                        "--db",
                        str(db_path),
                        "--stream-id",
                        "service-exposure:success",
                        "--details",
                    ]
                )

            store = EventStore(db_path)
            persisted = store.read_events(stream_id="service-exposure:success")

        output = stdout.getvalue()
        self.assertEqual(code, 0)
        self.assertIn("docker_published_ports     status=succeeded records=0", output)
        self.assertIn("0.0.0.0:11434", output)
        self.assertIn("scope=wildcard", output)
        self.assertIn("no remote reachability", output)
        self.assertEqual(len(persisted), 2)

    def test_main_partial_collector_failure_persists_manifest_and_returns_two(self) -> None:
        capture = self._partial_capture()
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "events.sqlite3"
            stdout = io.StringIO()
            stderr = io.StringIO()
            with patch.object(
                tool,
                "capture_into_store",
                side_effect=self._patched_capture_into_store(capture),
            ), redirect_stdout(stdout), redirect_stderr(stderr):
                code = tool.main(
                    [
                        "--db",
                        str(db_path),
                        "--stream-id",
                        "service-exposure:partial",
                    ]
                )

            store = EventStore(db_path)
            persisted = store.read_events(stream_id="service-exposure:partial")

        self.assertEqual(code, 2)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("status=failed", stdout.getvalue())
        self.assertIn("capture is partial", stdout.getvalue())
        self.assertEqual(
            persisted[-1].event_type,
            EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
        )
        self.assertTrue(persisted[-1].payload["partial"])

    def test_main_skip_docker_is_explicit_and_successful(self) -> None:
        capture = self._success_capture(docker_status=CollectorStatus.SKIPPED)
        observed_include_docker = []
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "events.sqlite3"
            stdout = io.StringIO()
            with patch.object(
                tool,
                "capture_into_store",
                side_effect=self._patched_capture_into_store(
                    capture,
                    observed_include_docker,
                ),
            ), redirect_stdout(stdout):
                code = tool.main(
                    [
                        "--db",
                        str(db_path),
                        "--stream-id",
                        "service-exposure:skip",
                        "--skip-docker",
                    ]
                )

        self.assertEqual(code, 0)
        self.assertEqual(observed_include_docker, [False])
        self.assertIn("status=skipped", stdout.getvalue())

    def test_stream_id_is_service_exposure_namespaced(self) -> None:
        stream_id = tool._stream_id()
        self.assertTrue(stream_id.startswith("service-exposure:"))
        self.assertEqual(len(stream_id.rsplit(":", 1)[-1]), 8)


if __name__ == "__main__":
    unittest.main()
