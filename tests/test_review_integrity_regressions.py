import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_observatory.analysis.graph_drift import compare_graphs
from agent_observatory.analysis.pass_framework import (
    AnalysisContext,
    AnalysisContractError,
)
from agent_observatory.endpoint.models import ProcessSnapshot
from agent_observatory.endpoint.network import TcpConnection
from agent_observatory.endpoint.windows_capture import CaptureInterval, WindowsCapture
from agent_observatory.graph import (
    EvidenceGraph,
    EvidenceRef,
    GraphNode,
    GraphNodeType,
)
from agent_observatory.storage import EventType
from tools import exp002_capture


class Exp002TreePreservationRegressionTests(unittest.TestCase):
    @staticmethod
    def _capture() -> WindowsCapture:
        root = ProcessSnapshot(
            pid=100,
            ppid=1,
            name="root.exe",
            started_at=10.0,
            command_line="root.exe",
            executable_path=r"C:\\Apps\\root.exe",
        )
        child_before = ProcessSnapshot(
            pid=101,
            ppid=100,
            name="child.exe",
            started_at=11.0,
            command_line="child.exe",
            executable_path=r"C:\\Apps\\child.exe",
        )
        root_after = ProcessSnapshot(
            pid=100,
            ppid=1,
            name="root.exe",
            started_at=10.0,
            command_line="root.exe",
            executable_path=r"C:\\Apps\\root.exe",
        )
        return WindowsCapture(
            processes_before=(root, child_before),
            tcp_connections=(
                TcpConnection(
                    pid=101,
                    state="Established",
                    local_address="10.0.0.5",
                    local_port=50000,
                    remote_address="203.0.113.10",
                    remote_port=443,
                ),
            ),
            processes_after=(root_after,),
            process_before_interval=CaptureInterval(1.0, 2.0),
            network_interval=CaptureInterval(3.0, 4.0),
            process_after_interval=CaptureInterval(5.0, 6.0),
        )

    @staticmethod
    def _identity(process: ProcessSnapshot):
        hash_state = SimpleNamespace(value="missing-path")
        return SimpleNamespace(
            pid=process.pid,
            command_line_sha256=f"cmd-{process.pid}",
            executable=SimpleNamespace(
                path=process.executable_path,
                file_identity=None,
                hash_observation=SimpleNamespace(
                    sha256=None,
                    state=hash_state,
                    observed_at=None,
                    hash_gap_ms=None,
                ),
            ),
        )

    def test_pre_capture_tree_membership_survives_tcp_attribution_rejection(self) -> None:
        capture = self._capture()
        root, child = capture.processes_before
        snapshot = SimpleNamespace(
            application=SimpleNamespace(
                profile=SimpleNamespace(name="TestApp"),
                root_process=root,
            ),
            processes=(root, child),
        )

        with patch.object(
            exp002_capture,
            "collect_windows_capture",
            return_value=capture,
        ), patch.object(
            exp002_capture,
            "collect_application_snapshots",
            return_value=(snapshot,),
        ) as snapshot_provider, patch.object(
            exp002_capture,
            "build_process_identities",
            return_value=(self._identity(root), self._identity(child)),
        ):
            evidence = exp002_capture.build_evidence("all", "IDLE")

        snapshot_provider.assert_called_once_with(capture.processes_before)
        application = evidence["applications"][0]
        self.assertEqual(application["process_count"], 2)
        self.assertEqual(
            tuple(process["pid"] for process in application["processes"]),
            (100, 101),
        )
        self.assertEqual(application["attribution_guard_rejected_tcp_count"], 1)
        child_payload = next(
            process
            for process in application["processes"]
            if process["pid"] == 101
        )
        self.assertEqual(child_payload["tcp_connections"], [])


class Exp002InterruptRecoveryRegressionTests(unittest.TestCase):
    @staticmethod
    def _load_only_session(directory: Path) -> dict[str, object]:
        files = tuple(directory.glob("*-transition-query.json"))
        if len(files) != 1:
            raise AssertionError(f"expected one session file, got {len(files)}")
        return json.loads(files[0].read_text(encoding="utf-8"))

    def test_interrupt_at_initial_prompt_persists_interrupted_terminal_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            with patch.object(exp002_capture, "OUTPUT_DIR", output_dir), patch(
                "builtins.input",
                side_effect=KeyboardInterrupt,
            ):
                code = exp002_capture.run_transition_query(
                    "Gemini",
                    interval_seconds=1.0,
                    post_delays_seconds=(2.0,),
                )

            session = self._load_only_session(output_dir)

        self.assertEqual(code, 130)
        self.assertEqual(session["status"], "interrupted")
        self.assertIn("finished_at", session)
        self.assertEqual(session["events"][-1]["type"], "INTERRUPTED")
        self.assertIsNone(session["events"][-1]["t_relative_ms"])

    def test_interrupt_during_pre_query_capture_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            with patch.object(exp002_capture, "OUTPUT_DIR", output_dir), patch(
                "builtins.input",
                return_value="",
            ), patch.object(
                exp002_capture,
                "_append_observation",
                side_effect=KeyboardInterrupt,
            ):
                code = exp002_capture.run_transition_query(
                    "Gemini",
                    interval_seconds=1.0,
                    post_delays_seconds=(2.0,),
                )

            session = self._load_only_session(output_dir)

        self.assertEqual(code, 130)
        self.assertEqual(session["status"], "interrupted")
        self.assertIn("finished_at", session)
        self.assertEqual(session["events"][-1]["type"], "INTERRUPTED")


class AnalysisContextIntegrityRegressionTests(unittest.TestCase):
    @staticmethod
    def _graph(stream_id: str, *, event_id: int, name: str) -> EvidenceGraph:
        reference = EvidenceRef(
            event_id=event_id,
            event_type=EventType.PROCESS_OBSERVED,
            observed_at=float(event_id),
            source="analysis-context-regression",
            stream_id=stream_id,
        )
        node = GraphNode(
            node_id="process:10@1.0",
            node_type=GraphNodeType.PROCESS_INSTANCE,
            attributes={
                "pid": 10,
                "started_at": 1.0,
                "name": name,
            },
            evidence=(reference,),
        )
        return EvidenceGraph(
            stream_id=stream_id,
            nodes=(node,),
            edges=(),
            projection_notes=(),
        )

    def test_same_stream_ids_do_not_make_stale_drift_valid(self) -> None:
        before_graph = self._graph("before", event_id=1, name="before.exe")
        after_graph = self._graph("after", event_id=2, name="after.exe")
        stale_after = self._graph("after", event_id=3, name="before.exe")
        stale_drift = compare_graphs(before_graph, stale_after)

        with self.assertRaisesRegex(
            AnalysisContractError,
            "content does not match supplied graph projections",
        ):
            AnalysisContext(
                before_graph=before_graph,
                after_graph=after_graph,
                graph_drift=stale_drift,
            )

    def test_matching_drift_is_accepted(self) -> None:
        before_graph = self._graph("before", event_id=1, name="before.exe")
        after_graph = self._graph("after", event_id=2, name="after.exe")
        drift = compare_graphs(before_graph, after_graph)

        context = AnalysisContext(
            before_graph=before_graph,
            after_graph=after_graph,
            graph_drift=drift,
        )

        self.assertEqual(context.graph_drift, drift)


if __name__ == "__main__":
    unittest.main()
