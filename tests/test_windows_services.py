import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.service_exposure import (
    HostTcpListener,
    ListenerAttributionState,
)
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.endpoint.windows_services import (
    ServiceProcessAttributionState,
    parse_windows_service_inventory,
    service_observations_for_listeners,
    service_processes_stable_across_inventory,
)
from agent_observatory.evidence import windows_service_event
from agent_observatory.storage import EventStore, EventType


class WindowsServiceInventoryTests(unittest.TestCase):
    @staticmethod
    def _process(
        *,
        pid: int = 3000,
        started_at: float = 100.5,
        name: str = "svchost.exe",
        path: str = r"C:\Windows\System32\svchost.exe",
        command_line: str = "svchost.exe -k Example",
    ) -> ProcessSnapshot:
        return ProcessSnapshot(
            pid=pid,
            ppid=1,
            name=name,
            started_at=started_at,
            command_line=command_line,
            executable_path=path,
        )

    @classmethod
    def _capture_with_process(cls, process: ProcessSnapshot) -> WindowsCapture:
        return WindowsCapture(
            processes_before=(process,),
            tcp_connections=(),
            processes_after=(process,),
            process_before_interval=CaptureInterval(1.0, 2.0),
            network_interval=CaptureInterval(3.0, 4.0),
            process_after_interval=CaptureInterval(5.0, 6.0),
        )

    def test_empty_inventory(self) -> None:
        self.assertEqual(parse_windows_service_inventory(""), ())

    def test_single_record(self) -> None:
        raw = r'''
        {
          "name": "vmms",
          "display_name": "Hyper-V Virtual Machine Management",
          "state": "Running",
          "start_mode": "Auto",
          "process_id": 4472,
          "service_type": "Own Process"
        }
        '''

        services = parse_windows_service_inventory(raw)

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0].name, "vmms")
        self.assertEqual(services[0].process_id, 4472)
        self.assertEqual(services[0].service_type, "Own Process")

    def test_multiple_services_same_pid_are_all_preserved(self) -> None:
        raw = r'''
        [
          {
            "name": "ServiceB",
            "display_name": "Service B",
            "state": "Running",
            "start_mode": "Auto",
            "process_id": 3000,
            "service_type": "Share Process"
          },
          {
            "name": "ServiceA",
            "display_name": "Service A",
            "state": "Running",
            "start_mode": "Manual",
            "process_id": 3000,
            "service_type": "Share Process"
          },
          {
            "name": "Unrelated",
            "display_name": "Unrelated",
            "state": "Running",
            "start_mode": "Auto",
            "process_id": 9000,
            "service_type": "Own Process"
          }
        ]
        '''
        services = parse_windows_service_inventory(raw)
        listener = HostTcpListener(
            owner_pid=3000,
            local_address="0.0.0.0",
            local_port=5000,
            owner_identity_basis="stable_process_instance",
            attribution_state=ListenerAttributionState.ATTRIBUTED,
            process_started_at=100.5,
            process_name="svchost.exe",
            executable_path=r"C:\Windows\System32\svchost.exe",
            attribution_reason=None,
        )

        observations = service_observations_for_listeners(services, (listener,))

        self.assertEqual(
            tuple(item.service.name for item in observations),
            ("ServiceA", "ServiceB"),
        )
        self.assertTrue(
            all(
                item.attribution_state is ServiceProcessAttributionState.ATTRIBUTED
                for item in observations
            )
        )
        self.assertTrue(
            all(
                item.process_ref == {"pid": 3000, "started_at": 100.5}
                for item in observations
            )
        )

    def test_service_process_verification_keeps_same_instance(self) -> None:
        process = self._process()
        capture = self._capture_with_process(process)

        stable = service_processes_stable_across_inventory(capture, (process,))

        self.assertEqual(stable, (process,))

    def test_post_service_pid_reuse_downgrades_attribution(self) -> None:
        services = parse_windows_service_inventory(
            r'''
            {
              "name": "ExampleSvc",
              "display_name": "Example Service",
              "state": "Running",
              "start_mode": "Auto",
              "process_id": 3000,
              "service_type": "Share Process"
            }
            '''
        )
        listener = HostTcpListener(
            owner_pid=3000,
            local_address="0.0.0.0",
            local_port=5000,
            owner_identity_basis="stable_process_instance",
            attribution_state=ListenerAttributionState.ATTRIBUTED,
            process_started_at=100.5,
            process_name="svchost.exe",
            executable_path=r"C:\Windows\System32\svchost.exe",
            attribution_reason=None,
        )
        reused = self._process(
            started_at=101.0,
            name="other.exe",
            path=r"C:\Temp\other.exe",
            command_line="other.exe",
        )

        observations = service_observations_for_listeners(
            services,
            (listener,),
            verified_processes=(reused,),
        )

        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(
            observation.attribution_state,
            ServiceProcessAttributionState.UNRESOLVED,
        )
        self.assertIsNone(observation.process_ref)
        self.assertEqual(
            observation.attribution_reason,
            "service_process_not_stable_across_post_service_snapshot",
        )

    def test_unresolved_listener_does_not_upgrade_pid_to_process_identity(self) -> None:
        services = parse_windows_service_inventory(
            r'''
            {
              "name": "ExampleSvc",
              "display_name": "Example Service",
              "state": "Running",
              "start_mode": "Auto",
              "process_id": 1234,
              "service_type": "Own Process"
            }
            '''
        )
        listener = HostTcpListener(
            owner_pid=1234,
            local_address="127.0.0.1",
            local_port=7000,
        )

        observations = service_observations_for_listeners(services, (listener,))

        self.assertEqual(len(observations), 1)
        observation = observations[0]
        self.assertEqual(
            observation.attribution_state,
            ServiceProcessAttributionState.UNRESOLVED,
        )
        self.assertIsNone(observation.process_ref)
        self.assertEqual(observation.attribution_basis, "pid_only_snapshot")
        self.assertEqual(
            observation.attribution_reason,
            "listener_process_not_bracket_attributed",
        )

    def test_windows_service_event_preserves_attribution_without_service_verdict(self) -> None:
        services = parse_windows_service_inventory(
            r'''
            {
              "name": "vmms",
              "display_name": "Hyper-V Virtual Machine Management",
              "state": "Running",
              "start_mode": "Auto",
              "process_id": 4472,
              "service_type": "Own Process"
            }
            '''
        )
        listener = HostTcpListener(
            owner_pid=4472,
            local_address="0.0.0.0",
            local_port=2179,
            owner_identity_basis="stable_process_instance",
            attribution_state=ListenerAttributionState.ATTRIBUTED,
            process_started_at=200.0,
            process_name="vmms.exe",
            executable_path=None,
            attribution_reason=None,
        )
        observation = service_observations_for_listeners(services, (listener,))[0]

        event = windows_service_event(
            observation,
            observed_at=300.0,
            source="service-exposure-test",
            stream_id="service-exposure:service-test",
        )

        self.assertEqual(event.event_type, EventType.WINDOWS_SERVICE_OBSERVED)
        self.assertEqual(event.payload["service_name"], "vmms")
        self.assertEqual(event.payload["process_id"], 4472)
        self.assertEqual(event.payload["process"], {"pid": 4472, "started_at": 200.0})
        self.assertEqual(event.payload["process_attribution_state"], "attributed")
        self.assertEqual(event.payload["process_attribution_basis"], "stable_process_instance")
        self.assertNotIn("reachable", event.payload)
        self.assertNotIn("vulnerable", event.payload)

    def test_windows_service_event_round_trips_through_event_store(self) -> None:
        services = parse_windows_service_inventory(
            r'''
            {
              "name": "ExampleSvc",
              "display_name": "Example Service",
              "state": "Running",
              "start_mode": "Manual",
              "process_id": 2222,
              "service_type": "Own Process"
            }
            '''
        )
        listener = HostTcpListener(
            owner_pid=2222,
            local_address="127.0.0.1",
            local_port=8080,
        )
        observation = service_observations_for_listeners(services, (listener,))[0]
        event = windows_service_event(
            observation,
            observed_at=1.0,
            source="service-exposure-test",
            stream_id="service-exposure:roundtrip",
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            stored = store.append(event)
            loaded = store.get_event(stored.event_id)

        self.assertIsNotNone(loaded)
        assert loaded is not None
        self.assertEqual(loaded.event_type, EventType.WINDOWS_SERVICE_OBSERVED)
        self.assertEqual(loaded.payload["service_name"], "ExampleSvc")
        self.assertIsNone(loaded.payload["process"])


if __name__ == "__main__":
    unittest.main()
