import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
from uuid import uuid4

from rq.exceptions import NoSuchJobError

from app.jobs.verification_job import VerificationJobError, run_verification_job
from app.services.verification import tasks
from app.services.verification.service import verify_answer
from tests.services.verification.test_schemas import sample_request


def no_evidence_result():
    request = sample_request()
    request.evidence = []
    return verify_answer(request)


class VerificationJobTest(unittest.TestCase):
    def test_worker_failure_log_excludes_arguments_and_traceback(self):
        from app.jobs.verification_worker import VerificationWorker

        worker = object.__new__(VerificationWorker)
        worker.log = Mock()
        job = Mock(id="safe-id", args=("private-code",))
        worker.handle_exception(job, ValueError, ValueError("private-code"), None)
        worker.log.error.assert_called_once_with("Verification job failed. job_id=%s", "safe-id")

    def test_enqueue_has_safe_description_and_bounded_retention(self):
        queue = Mock()
        with patch.object(tasks, "get_verification_queue", return_value=queue):
            accepted = tasks.enqueue_verification(sample_request())
        kwargs = queue.enqueue_call.call_args.kwargs
        self.assertEqual(kwargs["job_id"], tasks.JOB_PREFIX + str(accepted.verification_id))
        self.assertNotIn("query", kwargs["description"])
        for key in ("ttl", "result_ttl", "failure_ttl", "timeout"):
            self.assertGreater(kwargs[key], 0)

    def test_success_serializes_result(self):
        result = no_evidence_result()
        with patch("app.jobs.verification_job.verify_answer", return_value=result):
            self.assertEqual(run_verification_job(sample_request().model_dump(), "id"),
                             result.model_dump(by_alias=True, mode="json"))

    def test_failure_does_not_log_or_persist_private_details(self):
        with patch("app.jobs.verification_job.verify_answer", side_effect=ValueError("private-code")):
            with self.assertLogs("app.jobs.verification_job", level="WARNING") as logs:
                with self.assertRaises(VerificationJobError) as error:
                    run_verification_job(sample_request().model_dump(), "id")
        self.assertNotIn("private-code", str(error.exception) + str(logs.output))
        self.assertTrue(error.exception.__suppress_context__)

    def fetch(self, job):
        with patch.object(tasks, "get_verification_redis"), patch.object(tasks.Job, "fetch", return_value=job):
            return tasks.get_verification(uuid4())

    def job(self, status):
        return Mock(origin="answer-verification", started_at=None, timeout=360,
                    get_status=Mock(return_value=status))

    def test_rq_statuses_are_reflected(self):
        for rq_status, expected in [("queued", "QUEUED"), ("started", "RUNNING"),
                                    ("failed", "FAILED"), ("stopped", "FAILED"), ("canceled", "FAILED")]:
            with self.subTest(status=rq_status):
                self.assertEqual(self.fetch(self.job(rq_status)).status, expected)

    def test_finished_result_is_validated(self):
        job = self.job("finished")
        job.return_value.return_value = no_evidence_result().model_dump(by_alias=True, mode="json")
        self.assertEqual(self.fetch(job).status, "COMPLETED")
        job.return_value.return_value = None
        self.assertEqual(self.fetch(job).error.code, "INVALID_RESULT")

    def test_abandoned_started_job_does_not_stay_running(self):
        job = self.job("started")
        job.started_at = datetime.now(timezone.utc) - timedelta(seconds=500)
        self.assertEqual(self.fetch(job).error.code, "JOB_TIMEOUT")

    def test_expired_or_unrelated_job_is_not_found(self):
        with patch.object(tasks, "get_verification_redis"), patch.object(
            tasks.Job, "fetch", side_effect=NoSuchJobError
        ), self.assertRaises(tasks.VerificationNotFoundError):
            tasks.get_verification(uuid4())
        job = self.job("finished")
        job.origin = "analysis"
        with self.assertRaises(tasks.VerificationNotFoundError):
            self.fetch(job)
