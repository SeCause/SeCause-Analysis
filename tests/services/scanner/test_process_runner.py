import subprocess
import unittest
from unittest.mock import patch

from app.services.scanner.base import AnalyzerError
from app.services.scanner.process_runner import execute_command, truncate_output


class ProcessRunnerTest(unittest.TestCase):
    def test_execute_command_returns_stdout_on_success(self):
        completed = subprocess.CompletedProcess(
            args=["tool"],
            returncode=0,
            stdout="ok",
            stderr="",
        )

        with patch("app.services.scanner.process_runner.subprocess.run") as run:
            run.return_value = completed

            result = execute_command(["tool"], "Tool stage", 3, "Tool")

        self.assertEqual(result, "ok")
        run.assert_called_once_with(
            ["tool"],
            capture_output=True,
            check=False,
            text=True,
            timeout=3,
        )

    def test_execute_command_raises_analyzer_error_on_non_zero_exit(self):
        completed = subprocess.CompletedProcess(
            args=["tool"],
            returncode=2,
            stdout="",
            stderr="x" * 30,
        )

        with patch("app.services.scanner.process_runner.subprocess.run") as run:
            run.return_value = completed

            with self.assertRaisesRegex(AnalyzerError, "Tool stage failed"):
                execute_command(["tool"], "Tool stage", 3, "Tool", max_output_chars=10)

    def test_execute_command_raises_analyzer_error_on_timeout(self):
        with patch("app.services.scanner.process_runner.subprocess.run") as run:
            run.side_effect = subprocess.TimeoutExpired(["tool"], 3)

            with self.assertRaisesRegex(AnalyzerError, "Tool stage timed out"):
                execute_command(["tool"], "Tool stage", 3, "Tool")

    def test_truncate_output_limits_long_output(self):
        self.assertEqual(truncate_output("abcdef", max_chars=3), "abc...(truncated)")


if __name__ == "__main__":
    unittest.main()
