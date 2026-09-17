import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.endpoint.windows_process_principals import (
    ProcessPrincipalResolutionState,
    WindowsProcessPrincipalSnapshot,
    parse_windows_process_principal_inventory,
    principal_observations_for_processes,
)
from agent_observatory.evidence import (
    collect_service_exposure_capture,
    service_exposure_capture_event_batch,
    windows_process_principal_event,
)
from agent_observatory.storage import EventStore, EventType


class WindowsProcessPrincipalTests(unittest.TestCase):
    @staticmethod
    def _process(*, started_at=5.0, name="svc.exe") -> ProcessSnapshot:
        return ProcessSnapshot(
            pid=10,
            ppid=1,
            name=name,
            started_at=started_at,
            command_line="svc.exe",
            executable_path=r"C:\Apps\svc.exe",
        )

    def test_parser_preserves_get_owner_sid_access_denied(self) -> None:
        snapshots = parse_windows_process_principal_inventory(
            '{"process_id":10,"observed_started_at":"1970-01-01T00:00:05Z",'
            '"process_name":"svc.exe","owner_sid":null,"return_value":2,'
            '"query_error":null}'
        )

        self.assertEqual(len(snapshots), 1)
        snapshot = snapshots[0]
        self.assertEqual(snapshot.process_id, 10)
        self.assertEqual(snapshot.observed_started_at, 5.0)
        self.assertIsNone(snapshot.owner_sid)
        self.assertEqual(snapshot.return_value, 2)

    def test_resolved_sid_is_tied_to_same_stable_process_instance(self) -> None:
        process = self._process()
        raw = WindowsProcessPrincipalSnapshot(
            process_id=10,
            observed_started_at=5.0,
            process_name="svc.exe",
            owner_sid="S-1-5-21-user",
            return_value=0,
        )

        observation = principal_observations_for_processes(
            (raw,),
            (process,),
            (self._process(),),
        )[0]

        self.assertEqual(
            observation.resolution_state,
            ProcessPrincipalResolutionState.RESOLVED,
        )
        self.assertEqual(observation.owner_sid, "S-1-5-21-user")
        self.assertEqual(observation.process_ref, {"pid": 10, "started_at": 5.0})
        self.assertEqual(observation.process_identity_basis, "stable_process_instance")
        self.assertIsNone(observation.resolution_reason)

    def test_access_denied_is_unresolved_not_invented_sid(self) -> None:
        process = self._process()
        raw = WindowsProcessPrincipalSnapshot(
            process_id=10,
            observed_started_at=5.0,
            process_name="svc.exe",
            owner_sid=None,
            return_value=2,
        )

        observation = principal_observations_for_processes(
            (raw,),
            (process,),
            (self._process(),),
        )[0]

        self.assertEqual(
            observation.resolution_state,
            ProcessPrincipalResolutionState.UNRESOLVED,
        )
        self.assertIsNone(observation.owner_sid)
        self.assertEqual(observation.return_value, 2)
        self.assertEqual(observation.resolution_reason, "access_denied")
        self.assertEqual(observation.process_ref, {"pid": 10, "started_at": 5.0})

    def test_pid_reuse_drops_principal_identity(self) -> None:
        expected = self._process(started_at=5.0, name="svc.exe")
        verified = self._process(started_at=6.0, name="other.exe")
        raw = WindowsProcessPrincipalSnapshot(
            process_id=10,
            observed_started_at=5.0,
            process_name="svc.exe",
            owner_sid="S-1-5-21-user",
            return_value=0,
        )

        observation = principal_observations_for_processes(
            (raw,),
            (expected,),
            (verified,),
        )[0]

        self.assertEqual(
            observation.resolution_state,
            ProcessPrincipalResolutionState.UNRESOLVED,
        )
        self.assertIsNone(observation.owner_sid)
        self.assertIsNone(observation.process_ref)
        self.assertEqual(
            observation.resolution_reason,
            "process_not_stable_across_principal_query",
        )

    def test_process_principal_event_round_trips_through_event_store(self) -> None:
        process = self._process()
        raw = WindowsProcessPrincipalSnapshot(
            process_id=10,
            observed_started_at=5.0,
            process_name="svc.exe",
            owner_sid="S-1-5-21-user",
            return_value=0,
        )
        observation = principal_observations_for_processes(
            (raw,),
            (process,),
            (self._process(),),
        )[0]
        event = windows_process_principal_event(
            observation,
            observed_at=10.0,
            source="principal-test",
            stream_id="principal:1",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = store.append(event)
            loaded = store.read_events(stream_id="principal:1")

        self.assertEqual(stored.event_type, EventType.WINDOWS_PROCESS_PRINCIPAL_OBSERVED)
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].payload["owner_sid"], "S-1-5-21-user")
        self.assertEqual(loaded[0].payload["process"], {"pid": 10, "started_at": 5.0})
        self.assertEqual(loaded[0].payload["resolution_state"], "resolved")

    def test_live_capture_queries_only_stable_listener_processes(self) -> None:
        process = self._process()
        windows_capture = WindowsCapture(
            processes_before=(process,),
            tcp_connections=(
                TcpConnection(10, "Listen", "0.0.0.0", 8000, "0.0.0.0", 0),
            ),
            processes_after=(self._process(),),
            process_before_interval=CaptureInterval(1.0, 2.0),
            network_interval=CaptureInterval(3.0, 4.0),
            process_after_interval=CaptureInterval(5.0, 6.0),
        )
        queried_pids = []

        def principal_provider(process_ids):
            queried_pids.append(tuple(process_ids))
            return (
                WindowsProcessPrincipalSnapshot(
                    process_id=10,
                    observed_started_at=5.0,
                    process_name="svc.exe",
                    owner_sid="S-1-5-21-user",
                    return_value=0,
                ),
            )

        times = iter((10.0, 20.0, 30.0))
        capture = collect_service_exposure_capture(
            include_docker=False,
            include_process_principals=True,
            windows_capture_provider=lambda: windows_capture,
            process_principal_provider=principal_provider,
            process_verification_provider=lambda: (self._process(),),
            windows_service_provider=lambda: (),
            clock=lambda: next(times),
        )
        batch = service_exposure_capture_event_batch(
            capture,
            source="principal-test",
            stream_id="principal:capture",
        )

        self.assertEqual(queried_pids, [(10,)])
        self.assertEqual(len(capture.windows_process_principals), 1)
        self.assertEqual(capture.windows_process_principals[0].owner_sid, "S-1-5-21-user")
        reports = {report.collector: report for report in capture.collector_reports}
        self.assertEqual(
            reports["windows_listener_process_principals"].record_count,
            1,
        )
        self.assertEqual(
            tuple(event.event_type for event in batch),
            (
                EventType.TCP_LISTENER_OBSERVED,
                EventType.WINDOWS_PROCESS_PRINCIPAL_OBSERVED,
                EventType.SERVICE_EXPOSURE_CAPTURE_MANIFEST,
            ),
        )


if __name__ == "__main__":
    unittest.main()
