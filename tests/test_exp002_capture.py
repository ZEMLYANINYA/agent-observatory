import unittest

from agent_observatory.endpoint.identity import (
    ExecutableHashState,
    FileHashObservation,
    FileIdentity,
)
from tools.exp002_capture import (
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
