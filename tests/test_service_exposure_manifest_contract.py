import unittest

from agent_observatory.endpoint.windows_process_principals import (
    ProcessPrincipalResolutionState,
    WindowsProcessPrincipalObservation,
)
from agent_observatory.evidence import (
    CollectorStatus,
    ServiceExposureCapture,
    ServiceExposureCollectorReport,
    service_exposure_capture_event_batch,
)


class ServiceExposureManifestContractTests(unittest.TestCase):
    @staticmethod
    def _principal():
        return WindowsProcessPrincipalObservation(
            process_id=10,
            resolution_state=ProcessPrincipalResolutionState.RESOLVED,
            process_identity_basis="stable_process_instance",
            owner_sid="S-1-5-21-user",
            return_value=0,
            process_started_at=5.0,
            process_name="svc.exe",
            resolution_reason=None,
        )

    @staticmethod
    def _capture(*, reports, principals=(), principal_observed_at=None):
        return ServiceExposureCapture(
            listeners=(),
            docker_ports=(),
            listener_observed_at=None,
            docker_observed_at=None,
            manifest_observed_at=20.0,
            collector_reports=tuple(reports),
            windows_process_principals=tuple(principals),
            principal_observed_at=principal_observed_at,
        )

    def test_principal_facts_require_principal_collector_report(self) -> None:
        capture = self._capture(
            reports=(),
            principals=(self._principal(),),
            principal_observed_at=10.0,
        )
        with self.assertRaisesRegex(ValueError, "principal collector report"):
            service_exposure_capture_event_batch(
                capture,
                source="manifest-test",
                stream_id="service-exposure:test",
            )

    def test_principal_report_count_must_match_persisted_facts(self) -> None:
        capture = self._capture(
            reports=(
                ServiceExposureCollectorReport(
                    collector="windows_listener_process_principals",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=2,
                    observation_basis="test",
                ),
            ),
            principals=(self._principal(),),
            principal_observed_at=10.0,
        )
        with self.assertRaisesRegex(ValueError, "record_count"):
            service_exposure_capture_event_batch(
                capture,
                source="manifest-test",
                stream_id="service-exposure:test",
            )

    def test_failed_principal_report_cannot_carry_principal_facts(self) -> None:
        capture = self._capture(
            reports=(
                ServiceExposureCollectorReport(
                    collector="windows_listener_process_principals",
                    status=CollectorStatus.FAILED,
                    record_count=None,
                    error_type="RuntimeError",
                    error_message="query failed",
                ),
            ),
            principals=(self._principal(),),
            principal_observed_at=10.0,
        )
        with self.assertRaisesRegex(ValueError, "cannot carry principal observations"):
            service_exposure_capture_event_batch(
                capture,
                source="manifest-test",
                stream_id="service-exposure:test",
            )

    def test_duplicate_collector_names_are_rejected(self) -> None:
        report = ServiceExposureCollectorReport(
            collector="docker_published_ports",
            status=CollectorStatus.SKIPPED,
            record_count=None,
        )
        capture = self._capture(reports=(report, report))
        with self.assertRaisesRegex(ValueError, "must be unique"):
            service_exposure_capture_event_batch(
                capture,
                source="manifest-test",
                stream_id="service-exposure:test",
            )


if __name__ == "__main__":
    unittest.main()
