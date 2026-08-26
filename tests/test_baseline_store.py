import json
import tempfile
import unittest
from pathlib import Path

from agent_observatory.endpoint.baseline_store import (
    BASELINE_SCHEMA_VERSION,
    load_process_baseline,
    save_process_baseline,
)
from agent_observatory.endpoint.fingerprint import ProcessFingerprint
from agent_observatory.endpoint.roles import ProcessRole


class BaselineStoreTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        fingerprints = (
            ProcessFingerprint(
                name="claude.exe",
                role=ProcessRole.MAIN,
                markers=(),
            ),
            ProcessFingerprint(
                name="claude.exe",
                role=ProcessRole.NETWORK,
                markers=(
                    "--type=utility",
                    "--utility-sub-type=network.mojom.networkservice",
                ),
            ),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "baseline.json"

            save_process_baseline(path, fingerprints)
            loaded = load_process_baseline(path)

        self.assertEqual(
            set(loaded),
            set(fingerprints),
        )

    def test_saved_json_contains_schema_version(self) -> None:
        fingerprint = ProcessFingerprint(
            name="client.exe",
            role=ProcessRole.RENDERER,
            markers=("--type=renderer",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "baseline.json"

            save_process_baseline(
                path,
                (fingerprint,),
            )

            payload = json.loads(
                path.read_text(encoding="utf-8")
            )

        self.assertEqual(
            payload["schema_version"],
            BASELINE_SCHEMA_VERSION,
        )

    def test_duplicate_fingerprints_are_deduplicated(self) -> None:
        fingerprint = ProcessFingerprint(
            name="client.exe",
            role=ProcessRole.GPU,
            markers=("--type=gpu-process",),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "baseline.json"

            save_process_baseline(
                path,
                (
                    fingerprint,
                    fingerprint,
                ),
            )

            loaded = load_process_baseline(path)

        self.assertEqual(len(loaded), 1)

    def test_rejects_unknown_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "baseline.json"

            path.write_text(
                json.dumps(
                    {
                        "schema_version": 999,
                        "process_fingerprints": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_process_baseline(path)


if __name__ == "__main__":
    unittest.main()