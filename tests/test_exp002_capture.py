import unittest

from agent_observatory.endpoint.identity import (
    ExecutableHashState,
    FileHashObservation,
    FileIdentity,
)
from tools.exp002_capture import (
    _capture_summary,
    _file_identity_payload,
    _hash_observation_payload,
    _next_schedule_slot,
)


class Exp002EvidenceSerializationTests(unittest.TestCase):
    def test_file_identity_payload(self) -> None:
        payload = _file_identity_payload(
            FileIdentity(volume_serial=123, file_id=456)
        )

        self.assertEqual(
            payload,
            {
                "volume_serial": 123,
                "file_id": 456,
            },
        )

    def test_missing_file_identity_payload(self) -> None:
        self.assertIsNone(_file_identity_payload(None))

    def test_hash_observation_payload_preserves_timing(self) -> None:
        payload = _hash_observation_payload(
            FileHashObservation(
                sha256="abc123",
                state=ExecutableHashState.HASHED,
                observed_at=0.0,
                hash_gap_ms=12.5,
            )
        )

        self.assertEqual(payload["sha256"], "abc123")
        self.assertEqual(payload["state"], "hashed")
        self.assertEqual(payload["observed_at"], "1970-01-01T00:00:00+00:00")
        self.assertEqual(payload["hash_gap_ms"], 12.5)

    def test_hash_observation_payload_preserves_missing_timing(self) -> None:
        payload = _hash_observation_payload(
            FileHashObservation(
                sha256=None,
                state=ExecutableHashState.MISSING_PATH,
                observed_at=None,
                hash_gap_ms=None,
            )
        )

        self.assertIsNone(payload["sha256"])
        self.assertEqual(payload["state"], "missing-path")
        self.assertIsNone(payload["observed_at"])
        self.assertIsNone(payload["hash_gap_ms"])


class Exp002SummaryTests(unittest.TestCase):
    def test_tcp_states_are_reported_separately(self) -> None:
        evidence = {
            "applications": [
                {
                    "process_count": 2,
                    "attribution_guard_rejected_tcp_count": 0,
                    "processes": [
                        {
                            "role": "main",
                            "executable": {
                                "hash_observation": {"state": "hashed"},
                            },
                            "tcp_connections": [
                                {"state": "Bound"},
                                {"state": "Established"},
                                {"state": "Listen"},
                            ],
                        },
                        {
                            "role": "unknown",
                            "executable": {
                                "hash_observation": {"state": "hashed"},
                            },
                            "tcp_connections": [
                                {"state": "ESTABLISHED"},
                            ],
                        },
                    ],
                }
            ]
        }

        summary = _capture_summary(evidence)

        self.assertEqual(summary["process_count"], 2)
        self.assertEqual(summary["tcp_count"], 4)
        self.assertEqual(summary["tcp_established_count"], 2)
        self.assertEqual(summary["tcp_bound_count"], 1)
        self.assertEqual(summary["tcp_other_count"], 1)
        self.assertEqual(summary["unknown_count"], 1)
        self.assertEqual(summary["non_hashed_count"], 0)
        self.assertEqual(summary["guard_rejected_tcp_count"], 0)

    def test_tcp_count_remains_backward_compatible_total(self) -> None:
        evidence = {
            "applications": [
                {
                    "process_count": 1,
                    "attribution_guard_rejected_tcp_count": 0,
                    "processes": [
                        {
                            "role": "main",
                            "executable": {
                                "hash_observation": {"state": "hashed"},
                            },
                            "tcp_connections": [
                                {"state": "Bound"},
                                {"state": "Bound"},
                            ],
                        }
                    ],
                }
            ]
        }

        summary = _capture_summary(evidence)

        self.assertEqual(summary["tcp_count"], 2)
        self.assertEqual(summary["tcp_bound_count"], 2)
        self.assertEqual(summary["tcp_established_count"], 0)
        self.assertEqual(summary["tcp_other_count"], 0)


class Exp002ScheduleTests(unittest.TestCase):
    def test_next_slot_keeps_future_grid_point(self) -> None:
        self.assertEqual(
            _next_schedule_slot(
                origin_ns=0,
                interval_ns=1_000,
                completed_slot=0,
                now_ns=500,
            ),
            1,
        )

    def test_next_slot_skips_missed_slot_without_extra_interval(self) -> None:
        self.assertEqual(
            _next_schedule_slot(
                origin_ns=0,
                interval_ns=1_000,
                completed_slot=0,
                now_ns=1_400,
            ),
            2,
        )

    def test_next_slot_allows_current_grid_point(self) -> None:
        self.assertEqual(
            _next_schedule_slot(
                origin_ns=0,
                interval_ns=1_000,
                completed_slot=0,
                now_ns=2_000,
            ),
            2,
        )


if __name__ == "__main__":
    unittest.main()
