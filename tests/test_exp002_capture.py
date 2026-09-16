import unittest

from agent_observatory.endpoint.identity import (
    ExecutableHashState,
    FileHashObservation,
    FileIdentity,
)
from tools.exp002_capture import (
    _file_identity_payload,
    _hash_observation_payload,
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


if __name__ == "__main__":
    unittest.main()
