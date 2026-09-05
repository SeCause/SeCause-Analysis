import sys
import unittest

from app.services.scanner.base import AnalyzerError
from app.services.scanner.process_runner import execute_command, truncate_output


class ProcessRunnerTest(unittest.TestCase):
    def test_execute_command_returns_stdout_on_success(self):
        result = execute_command(
            [sys.executable, "-c", "print('ok', end='')"],
            "Tool stage",
            3,
            "Tool",
            max_stdout_chars=10,
        )

        self.assertEqual(result, "ok")

    def test_execute_command_raises_analyzer_error_on_non_zero_exit(self):
        with self.assertRaisesRegex(AnalyzerError, "Tool stage failed"):
            execute_command(
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stderr.write('x' * 30); sys.exit(2)",
                ],
                "Tool stage",
                3,
                "Tool",
                max_stdout_chars=10,
                max_error_chars=10,
            )

    def test_execute_command_raises_analyzer_error_on_timeout(self):
        with self.assertRaisesRegex(AnalyzerError, "Tool stage timed out"):
            execute_command(
                [sys.executable, "-c", "import time; time.sleep(1)"],
                "Tool stage",
                0.01,
                "Tool",
                max_stdout_chars=10,
            )

    def test_execute_command_limits_success_stdout(self):
        with self.assertRaisesRegex(AnalyzerError, "stdout exceeded"):
            execute_command(
                [sys.executable, "-c", "print('x' * 20, end='')"],
                "Tool stage",
                3,
                "Tool",
                max_stdout_chars=10,
            )

    def test_execute_command_reports_missing_executable_clearly(self):
        with self.assertRaisesRegex(AnalyzerError, "Install MissingTool CLI"):
            execute_command(
                ["missing-tool-for-secause-test"],
                "Missing stage",
                3,
                "MissingTool",
                max_stdout_chars=10,
            )

    def test_truncate_output_limits_long_output(self):
        self.assertEqual(truncate_output("abcdef", max_chars=3), "abc...(truncated)")


if __name__ == "__main__":
    unittest.main()
