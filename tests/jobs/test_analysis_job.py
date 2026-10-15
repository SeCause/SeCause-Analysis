import unittest

import httpx
from contextlib import ExitStack
from unittest.mock import AsyncMock, Mock, patch

from app.jobs.analysis_job import (
    AllAnalyzersFailedError,
    AnalysisProgressReporter,
    get_analyzer_runners,
    run_analysis_job,
)
from app.schemas.finding import FindingSeverity, FindingTool
from app.services.callback.spring_client import SpringCallbackError
from app.services.scanner.base import AnalyzerError, RawFinding


class AnalysisJobTest(unittest.TestCase):
    def test_callback_contains_relative_deduplicated_paths_only(self):
        runner = Mock(tool=FindingTool.SEMGREP)
        relative = build_raw_finding("FIRST", 10)
        absolute = relative.model_copy(update={"file_path": "/tmp/repository/src/example.py"})
        invalid = relative.model_copy(update={"file_path": "/tmp/outside.py"})
        runner.run.return_value = [absolute, relative, invalid]
        with self.pipeline_patches([runner]) as callback, patch(
            "app.jobs.analysis_job.search_evidence_for_findings", return_value=[[]],
        ) as search, patch(
            "app.jobs.analysis_job.enrich_finding_with_explanation", side_effect=lambda finding, _: finding,
        ), self.assertLogs("app.services.normalizer.finding_normalizer", level="WARNING"):
            result = run_analysis_job(self.payload)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(len(search.call_args.args[0]), 1)
        payload = callback.send_success.call_args.args[0].model_dump(by_alias=True)
        self.assertEqual(payload["findings"][0]["filePath"], "src/example.py")
        self.assertNotIn("/tmp/repository", str(payload))

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
        self.assertEqual([call.args[1] for call in callback.send_progress.call_args_list], [10, 30, 50])
        failure_payload = callback.send_failure.call_args.args[0]
        self.assertIn("SEMGREP", failure_payload.error_message)
        self.assertIn("CODEQL", failure_payload.error_message)

    def test_progress_failure_does_not_fail_analysis(self):
        runner = Mock(tool=FindingTool.SEMGREP)
        runner.run.return_value = []
        with self.pipeline_patches([runner]) as callback:
            callback.send_progress.side_effect = SpringCallbackError("offline")
            result = run_analysis_job(self.payload)
        self.assertEqual(result["status"], "COMPLETED")
        callback.send_success.assert_called_once()
        callback.send_failure.assert_not_called()

    def test_empty_findings_still_report_stages_before_result(self):
        runner = Mock(tool=FindingTool.SEMGREP)
        runner.run.return_value = []
        with self.pipeline_patches([runner]) as callback:
            run_analysis_job(self.payload)
        values = [call.args[1] for call in callback.send_progress.call_args_list]
        self.assertEqual(values, [10, 50, 55, 65, 95])
        self.assertEqual(callback.method_calls[-1][0], "send_success")

    def test_progress_reporter_skips_duplicates_and_regressions(self):
        callback = Mock()
        reporter = AnalysisProgressReporter(callback, 11)
        for value in [10, 10, 5, 30]:
            reporter.report(value)
        self.assertEqual([call.args for call in callback.send_progress.call_args_list], [(11, 10), (11, 30)])

    def test_http_progress_errors_preserve_success_and_failure_callbacks(self):
        from tests.services.callback.test_spring_client import SpringCallbackClientTest

        for failure in [httpx.ReadTimeout("timeout"), 401, 503]:
            for all_failed in [False, True]:
                with self.subTest(failure=failure, all_failed=all_failed):
                    runner = Mock(tool=FindingTool.SEMGREP)
                    if all_failed:
                        runner.run.side_effect = AnalyzerError("scanner failed")
                    else:
                        runner.run.return_value = []
                    client = SpringCallbackClientTest().make_client()
                    with self.pipeline_patches([runner]) as callback, patch(
                        "app.services.callback.spring_client.httpx.Client"
                    ) as transport, patch("app.services.callback.spring_client.time.sleep"):
                        post = transport.return_value.__enter__.return_value.post
                        if isinstance(failure, Exception):
                            post.side_effect = failure
                        else:
                            post.return_value = httpx.Response(
                                failure, request=httpx.Request("POST", "https://example.test")
                            )
                        callback.send_progress.side_effect = client.send_progress
                        if all_failed:
                            with self.assertRaises(AllAnalyzersFailedError):
                                run_analysis_job(self.payload)
                            callback.send_failure.assert_called_once()
                        else:
                            self.assertEqual(run_analysis_job(self.payload)["status"], "COMPLETED")
                            callback.send_success.assert_called_once()
                        values = [call.args[1] for call in callback.send_progress.call_args_list]
                        self.assertEqual(values, sorted(set(values)))
                        self.assertTrue(all(0 <= value < 100 for value in values))

    def test_rag_and_llm_progress_use_deduplicated_finding_count(self):
        runner = Mock(tool=FindingTool.SEMGREP)
        runner.run.return_value = [
            build_raw_finding("FIRST", 10), build_raw_finding("FIRST", 10),
            build_raw_finding("SECOND", 20),
        ]
        with self.pipeline_patches([runner]) as callback, patch(
            "app.services.rag.hybrid_search.search_evidence_async",
            new_callable=AsyncMock,
            return_value=[],
        ) as search, patch(
            "app.jobs.analysis_job.enrich_finding_with_explanation",
            side_effect=lambda finding, evidence: finding,
        ):
            result = run_analysis_job(self.payload)
        self.assertEqual(result["finding_count"], 2)
        self.assertEqual(search.await_count, 2)
        self.assertEqual(
            [call.args[1] for call in callback.send_progress.call_args_list],
            [10, 50, 55, 60, 65, 80, 95],
        )
        self.assertEqual(callback.method_calls[-1][0], "send_success")

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

        with self.pipeline_patches([runner]) as callback, patch(
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
        self.assertEqual(
            [call.args[1] for call in callback.send_progress.call_args_list],
            [10, 50, 55, 65, 80, 95],
        )
        output = "\n".join(logs.output)
        self.assertIn("finding_index=1 finding_total=2", output)
        self.assertIn("finding_index=2 finding_total=2", output)
        self.assertIn("Finding enrichment completed", output)

    def test_llm_failure_keeps_finding_and_sends_success_without_fix_code(self):
        from app.services.llm.claude_client import ClaudeClientError

        runner = Mock(tool=FindingTool.SEMGREP)
        runner.run.return_value = [build_raw_finding("SQL_INJECTION", 10)]
        with self.pipeline_patches([runner]) as callback, patch(
            "app.jobs.analysis_job.search_evidence_for_findings", return_value=[[]]
        ), patch(
            "app.services.llm.explanation_generator.ClaudeExplanationClient",
            side_effect=ClaudeClientError("mock LLM failure"),
        ):
            result = run_analysis_job(self.payload)

        self.assertEqual(result["status"], "COMPLETED")
        callback.send_failure.assert_not_called()
        body = callback.send_success.call_args.args[0].model_dump(by_alias=True)
        self.assertEqual(body["summary"]["totalCount"], 1)
        self.assertEqual(body["findings"][0]["fixExamples"], [])
        self.assertTrue(body["findings"][0]["recommendation"])

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
