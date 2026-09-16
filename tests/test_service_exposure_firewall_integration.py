import unittest
from unittest.mock import patch

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.endpoint.windows_firewall import (
    WindowsFirewallContext,
    WindowsFirewallProfileSnapshot,
    WindowsNetworkProfileSnapshot,
)
from agent_observatory.evidence import (
    CollectorStatus,
    collect_service_exposure_capture,
    service_exposure_capture_event_batch,
)
from agent_observatory.storage import EventType
from tools import service_exposure_capture as tool


class ServiceExposureFirewallIntegrationTests(unittest.TestCase):
    @staticmethod
    def _empty_windows_capture() -> WindowsCapture:
        return WindowsCapture(
            processes_before=(),
            tcp_connections=(),
            processes_after=(),
            process_before_interval=CaptureInterval(1.0, 2.0),
            network_interval=CaptureInterval(3.0, 4.0),
            process_after_interval=CaptureInterval(5.0, 6.0),
        )

    @staticmethod
    def _listener_windows_capture() -> WindowsCapture:
        process = ProcessSnapshot(
            pid=101,
            ppid=1,
            name="service.exe",
            started_at=5.0,
            command_line="service.exe",
            executable_path=r"C:\Apps\service.exe",
        )
        return WindowsCapture(
            processes_before=(process,),
            tcp_connections=(
                TcpConnection(
                    101,
                    "Listen",
                    "0.0.0.0",
                    8000,
                    "0.0.0.0",
                    0,
                ),
            ),
            processes_after=(process,),
            process_before_interval=CaptureInterval(1.0, 2.0),
            network_interval=CaptureInterval(3.0, 4.0),
            process_after_interval=CaptureInterval(5.0, 6.0),
        )

    @staticmethod
    def _firewall_context() -> WindowsFirewallContext:
        return WindowsFirewallContext(
            firewall_profiles=(
                WindowsFirewallProfileSnapshot(
                    name="Private",
                    enabled=True,
                    default_inbound_action="Block",
                    default_outbound_action="Allow",
                    allow_inbound_rules="True",
                    allow_local_firewall_rules="True",
                ),
            ),
            network_profiles=(
                WindowsNetworkProfileSnapshot(
                    name="Home",
                    interface_alias="Wi-Fi",
                    interface_index=17,
                    network_category="Private",
                    ipv4_connectivity="Internet",
                    ipv6_connectivity="NoTraffic",
                ),
            ),
            capture_started_at=10.0,
            capture_finished_at=11.0,
        )

    def test_firewall_context_is_persistable_in_same_capture_batch(self) -> None:
        capture = collect_service_exposure_capture(
            include_docker=False,
            include_firewall=True,
            windows_capture_provider=self._empty_windows_capture,
            firewall_context_provider=self._firewall_context,
            clock=lambda: 20.0,
        )

        self.assertFalse(capture.has_failures)
        self.assertIsNotNone(capture.firewall_context)
        self.assertEqual(
            tuple(
                (report.collector, report.status, report.record_count)
                for report in capture.collector_reports
            ),
            (
                ("windows_tcp_listeners", CollectorStatus.SUCCEEDED, 0),
                ("windows_listener_services", CollectorStatus.SKIPPED, None),
                ("windows_firewall_context", CollectorStatus.SUCCEEDED, 2),
                ("docker_published_ports", CollectorStatus.SKIPPED, None),
            ),
        )

        batch = service_exposure_capture_event_batch(
            capture,
            source="firewall-integration-test",
            stream_id="service-exposure:firewall",
        )
        self.assertEqual(
            tuple(event.event_type for event in batch),
            (
                EventType.WINDOWS_FIREWALL_PROFILE_OBSERVED,
                EventType.WINDOWS_NETWORK_PROFILE_OBSERVED,
                EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
            ),
        )
        self.assertEqual(batch[0].payload["default_inbound_action"], "Block")
        self.assertEqual(batch[1].payload["network_category"], "Private")
        self.assertNotIn("reachable", batch[0].payload)
        self.assertNotIn("allowed", batch[0].payload)

    def test_firewall_failure_preserves_listener_evidence_and_marks_partial(self) -> None:
        def fail_firewall():
            raise RuntimeError("firewall context unavailable")

        capture = collect_service_exposure_capture(
            include_docker=False,
            include_firewall=True,
            windows_capture_provider=self._listener_windows_capture,
            windows_service_provider=lambda: (),
            process_verification_provider=lambda: (
                self._listener_windows_capture().processes_after[0],
            ),
            firewall_context_provider=fail_firewall,
            clock=iter((10.0, 20.0)).__next__,
        )

        self.assertTrue(capture.has_failures)
        self.assertEqual(len(capture.listeners), 1)
        self.assertIsNone(capture.firewall_context)
        firewall_report = next(
            report
            for report in capture.collector_reports
            if report.collector == "windows_firewall_context"
        )
        self.assertEqual(firewall_report.status, CollectorStatus.FAILED)
        self.assertEqual(firewall_report.error_type, "RuntimeError")

        batch = service_exposure_capture_event_batch(
            capture,
            source="firewall-integration-test",
            stream_id="service-exposure:partial-firewall",
        )
        self.assertEqual(batch[0].event_type, EventType.TCP_LISTENER_OBSERVED)
        self.assertEqual(
            batch[-1].event_type,
            EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
        )
        self.assertTrue(batch[-1].payload["partial"])

    def test_cli_production_provider_enables_firewall_context(self) -> None:
        sentinel = object()
        with patch.object(
            tool,
            "collect_service_exposure_capture",
            return_value=sentinel,
        ) as collector:
            result = tool._collect_live_service_exposure_capture(include_docker=False)

        self.assertIs(result, sentinel)
        collector.assert_called_once_with(
            include_docker=False,
            include_firewall=True,
            include_firewall_rules=True,
        )


if __name__ == "__main__":
    unittest.main()
