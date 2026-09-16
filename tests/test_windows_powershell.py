import unittest
from types import SimpleNamespace
from unittest.mock import patch

from agent_observatory.endpoint.windows_powershell import run_powershell_text


class WindowsPowerShellTests(unittest.TestCase):
    @patch("agent_observatory.endpoint.windows_powershell.subprocess.run")
    def test_forces_utf8_stdout_and_preserves_unicode(self, run_mock) -> None:
        expected = '{"path":"C:\\\\Users\\\\САНТЕР\\\\App.exe"}'
        run_mock.return_value = SimpleNamespace(stdout=expected)

        result = run_powershell_text("Write-Output 'test'")

        self.assertEqual(result, expected)

        args, kwargs = run_mock.call_args
        argv = args[0]
        script = argv[-1]

        self.assertEqual(argv[0], "powershell.exe")
        self.assertIn(
            "[Console]::OutputEncoding = "
            "[System.Text.UTF8Encoding]::new($false)",
            script,
        )
        self.assertTrue(script.endswith("Write-Output 'test'"))
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertTrue(kwargs["text"])
        self.assertNotIn("errors", kwargs)


if __name__ == "__main__":
    unittest.main()
