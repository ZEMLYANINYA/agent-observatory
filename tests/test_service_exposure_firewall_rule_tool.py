import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_observatory.endpoint.windows_firewall_rules import (
    WindowsFirewallRuleInventory,
    WindowsFirewallRuleSnapshot,
)
from agent_observatory.evidence import (
    CollectorStatus,
    ServiceExposureCapture,
    ServiceExposureCollectorReport,
    append_service_exposure_capture,
)
from agent_observatory.storage import EventStore, EventType
from tools import service_exposure_capture as tool


class ServiceExposureFirewallRuleToolTests(unittest.TestCase):
    @staticmethod
    def _inventory() -> WindowsFirewallRuleInventory:
        rule = WindowsFirewallRuleSnapshot(
            name="Synthetic-Allow-5985",
            display_name="Synthetic Allow WinRM",
            enabled=True,
            direction="Inbound",
            action="Allow",
            profile="Public",
            edge_traversal_policy="Block",
            policy_store_source_type="Local",
            policy_store_source="PersistentStore",
            owner=None,
            primary_status=None,
            status=None,
            loose_source_mapping=False,
            local_only_mapping=False,
            protocol=("TCP",),
            local_ports=("5985",),
            remote_ports=("Any",),
            icmp_types=(),
            dynamic_targets=("Any",),
            local_addresses=("Any",),
            remote_addresses=("Any",),
            programs=("Any",),
            packages=("Any",),
            services=("Any",),
            interface_types=("Any",),
            interface_aliases=("Any",),
            authentication=("Any",),
            encryption=("Any",),
            override_block_rules=("Any",),
            local_users=("Any",),
            remote_users=("Any",),
            remote_machines=("Any",),
        )
        return WindowsFirewallRuleInventory(
            rules=(rule,),
            capture_started_at=10.0,
            capture_finished_at=11.0,
        )

    def test_production_wrapper_requests_firewall_context_and_rules(self) -> None:
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
            include_process_principals=True,
        )

    def test_summary_counts_rules_but_details_do_not_dump_rule_names(self) -> None:
        capture = ServiceExposureCapture(
            listeners=(),
            docker_ports=(),
            listener_observed_at=None,
            docker_observed_at=None,
            manifest_observed_at=20.0,
            collector_reports=(
                ServiceExposureCollectorReport(
                    collector="windows_firewall_rules",
                    status=CollectorStatus.SUCCEEDED,
                    record_count=1,
                    observation_basis=(
                        "windows_get_netfirewallrule_active_store_inbound_with_filters"
                    ),
                ),
                ServiceExposureCollectorReport(
                    collector="docker_published_ports",
                    status=CollectorStatus.SKIPPED,
                    record_count=None,
                ),
            ),
            firewall_rule_inventory=self._inventory(),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = EventStore(Path(temp_dir) / "events.sqlite3")
            append_service_exposure_capture(
                store,
                capture,
                source="rule-tool-test",
                stream_id="rule-tool:1",
            )
            events = store.read_events(stream_id="rule-tool:1")

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                tool._print_summary(
                    store,
                    events,
                    capture,
                    stream_id="rule-tool:1",
                )
                tool._print_details(events)

        output = stdout.getvalue()
        self.assertEqual(
            sum(
                event.event_type is EventType.WINDOWS_FIREWALL_RULE_OBSERVED
                for event in events
            ),
            1,
        )
        self.assertIn("WINDOWS_FIREWALL_RULE_OBSERVED", output)
        self.assertIn("enabled", output)
        self.assertIn("Allow", output)
        self.assertIn("Public", output)
        self.assertIn("1 rule facts persisted", output)
        self.assertNotIn("Synthetic Allow WinRM", output)
        self.assertNotIn("Synthetic-Allow-5985", output)


if __name__ == "__main__":
    unittest.main()
