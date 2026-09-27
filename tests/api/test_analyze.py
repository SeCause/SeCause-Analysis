import unittest
from unittest.mock import Mock, patch

from app.api.routes.analyze import analyze
from app.jobs.analysis_job import run_analysis_job
from app.schemas.analyze import AnalyzeRequest


class AnalyzeRouteTest(unittest.IsolatedAsyncioTestCase):
    async def test_enqueue_uses_configured_job_timeout(self):
        queue = Mock()
        queue.enqueue.return_value = Mock(id="job-id")
        request = AnalyzeRequest(
            analysis_id=11,
            repository_id=22,
            repository_url="https://github.com/example/repository.git",
            branch="main",
            github_token="github-token",
        )

        with patch(
            "app.api.routes.analyze.get_analysis_queue",
            return_value=queue,
        ), patch(
            "app.api.routes.analyze.store_github_token",
            return_value="token-reference",
        ), patch(
            "app.api.routes.analyze.settings.ANALYSIS_JOB_TIMEOUT_SECONDS",
            1800,
        ):
            response = await analyze(request)

        self.assertTrue(response.accepted)
        queue.enqueue.assert_called_once_with(
            run_analysis_job,
            request.to_job_payload("token-reference"),
            job_timeout=1800,
        )


if __name__ == "__main__":
    unittest.main()
