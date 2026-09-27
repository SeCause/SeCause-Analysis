import unittest
from contextlib import ExitStack
from unittest.mock import Mock, patch

from app.jobs.analysis_job import (
    AllAnalyzersFailedError,
    get_analyzer_runners,
    run_analysis_job,
)
from app.schemas.finding import FindingSeverity, FindingTool
from app.services.scanner.base import AnalyzerError, RawFinding


class AnalysisJobTest(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "analysis_id": 11,
            "repository_id": 22,
            "repository_url": "https://github.com/example/repository.git",
            "branch": "main",
            "github_token_reference": "token-reference",
        }

    def test_one_missing_scanner_executable_continues_and_sends_success(self):
        failed_runner = Mock(tool=FindingTool.CODEQL)
        failed_runner.run.side_effect = AnalyzerError("CodeQL executable was not found")
        successful_runner = Mock(tool=FindingTool.SEMGREP)
        successful_runner.run.return_value = []

        with self.pipeline_patches([failed_runner, successful_runner]) as callback:
            result = run_analysis_job(self.payload)

        self.assertEqual(result["status"], "COMPLETED")
        callback.send_success.assert_called_once()
        callback.send_failure.assert_not_called()
        success_payload = callback.send_success.call_args.args[0]
        self.assertEqual(len(success_payload.failed_scanners), 1)
        self.assertIn("CODEQL", success_payload.failed_scanners[0])
        self.assertEqual(
            success_payload.model_dump(by_alias=True)["failedScanners"],
            success_payload.failed_scanners,
        )

    def test_all_scanners_failed_sends_failure_only(self):
        semgrep_runner = Mock(tool=FindingTool.SEMGREP)
        semgrep_runner.run.side_effect = AnalyzerError("Semgrep executable was not found")
        codeql_runner = Mock(tool=FindingTool.CODEQL)
        codeql_runner.run.side_effect = AnalyzerError("CodeQL executable was not found")

        with self.pipeline_patches([semgrep_runner, codeql_runner]) as callback:
            with self.assertRaises(AllAnalyzersFailedError):
                run_analysis_job(self.payload)

        callback.send_success.assert_not_called()
        callback.send_failure.assert_called_once()
        failure_payload = callback.send_failure.call_args.args[0]
        self.assertIn("SEMGREP", failure_payload.error_message)
        self.assertIn("CODEQL", failure_payload.error_message)

    def test_stub_infra_runner_is_not_registered(self):
        registered_tools = [runner.tool for runner in get_analyzer_runners()]

        self.assertEqual(
            registered_tools,
            [FindingTool.SEMGREP, FindingTool.CODEQL],
        )

    def test_multiple_findings_log_enrichment_progress(self):
        runner = Mock(tool=FindingTool.SEMGREP)
        runner.run.return_value = [
            build_raw_finding("FIRST", 10),
            build_raw_finding("SECOND", 20),
        ]

        with self.pipeline_patches([runner]), patch(
            "app.jobs.analysis_job.search_evidence_for_findings",
            return_value=[[], []],
        ), patch(
            "app.jobs.analysis_job.enrich_finding_with_explanation",
            side_effect=lambda finding, _evidence: finding,
        ), self.assertLogs(
            "app.jobs.analysis_job",
            level="INFO",
        ) as logs:
            result = run_analysis_job(self.payload)

        self.assertEqual(result["finding_count"], 2)
        output = "\n".join(logs.output)
        self.assertIn("finding_index=1 finding_total=2", output)
        self.assertIn("finding_index=2 finding_total=2", output)
        self.assertIn("Finding enrichment completed", output)

    def test_missing_analysis_id_skips_failure_callback(self):
        callback = Mock()

        with patch(
            "app.jobs.analysis_job.SpringCallbackClient",
            return_value=callback,
        ), patch(
            "app.jobs.analysis_job.cleanup_repository"
        ), self.assertLogs(
            "app.jobs.analysis_job",
            level="ERROR",
        ) as logs:
            with self.assertRaises(Exception):
                run_analysis_job({})

        callback.send_failure.assert_not_called()
        self.assertIn("analysis_id is missing", logs.output[0])

    def pipeline_patches(self, runners):
        stack = ExitStack()
        callback = Mock()
        stack.enter_context(
            patch("app.jobs.analysis_job.SpringCallbackClient", return_value=callback)
        )
        stack.enter_context(
            patch("app.jobs.analysis_job.resolve_github_token_reference", return_value="token")
        )
        stack.enter_context(
            patch("app.jobs.analysis_job.shallow_clone_repository", return_value="/tmp/repository")
        )
        stack.enter_context(patch("app.jobs.analysis_job.cleanup_repository"))
        stack.enter_context(patch("app.jobs.analysis_job.delete_github_token_reference"))
        stack.enter_context(
            patch("app.jobs.analysis_job.get_analyzer_runners", return_value=runners)
        )
        return _CallbackPatchContext(stack, callback)


class _CallbackPatchContext:
    def __init__(self, stack: ExitStack, callback: Mock):
        self.stack = stack
        self.callback = callback

    def __enter__(self):
        self.stack.__enter__()
        return self.callback

    def __exit__(self, exc_type, exc_value, traceback):
        return self.stack.__exit__(exc_type, exc_value, traceback)


def build_raw_finding(finding_type: str, line_start: int) -> RawFinding:
    return RawFinding(
        tool=FindingTool.SEMGREP,
        type=finding_type,
        severity=FindingSeverity.HIGH,
        file_path="src/example.py",
        message="example finding",
        line_start=line_start,
    )


if __name__ == "__main__":
    unittest.main()
