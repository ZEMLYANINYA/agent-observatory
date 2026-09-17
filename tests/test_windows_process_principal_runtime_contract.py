import unittest
from unittest.mock import patch

from agent_observatory.endpoint import windows_process_principals as principals


class WindowsProcessPrincipalRuntimeContractTests(unittest.TestCase):
    @staticmethod
    def _record(pid: int) -> str:
        return (
            '{'
            f'"process_id":{pid},'
            '"observed_started_at":null,'
            f'"process_name":"p{pid}.exe",'
            '"owner_sid":null,'
            '"return_value":2,'
            '"query_error":null'
            '}'
        )

    def test_powershell_does_not_shadow_automatic_pid_variable(self) -> None:
        captured = {}

        def fake_runner(command: str) -> str:
            captured["command"] = command
            return "[" + self._record(10) + "," + self._record(20) + "]"

        with patch.object(principals, "run_powershell_text", side_effect=fake_runner):
            snapshots = principals.collect_windows_process_principals((20, 10))

        command = captured["command"]
        self.assertIn("$ErrorActionPreference = 'Stop'", command)
        self.assertIn("foreach ($processId in $targetPids)", command)
        self.assertNotIn("foreach ($pid in $targetPids)", command)
        self.assertIn('ProcessId = $processId', command)
        self.assertEqual(tuple(item.process_id for item in snapshots), (10, 20))

    def test_incomplete_raw_inventory_is_failure_not_silent_missing_record(self) -> None:
        raw = self._record(10)

        with patch.object(principals, "run_powershell_text", return_value=raw):
            with self.assertRaisesRegex(ValueError, "exactly one record"):
                principals.collect_windows_process_principals((10, 20))


if __name__ == "__main__":
    unittest.main()
