"""Run separately: python -m app.jobs.verification_worker."""

import logging

from rq import Worker
from rq.job import Job
from rq.serializers import JSONSerializer

from app.jobs.verification_queue import get_verification_queue, get_verification_redis


class VerificationWorker(Worker):
    def handle_exception(self, job: Job, *exc_info) -> None:
        # RQ's default logger attaches job.args to LogRecord.extra. Those args
        # contain private evidence; failure persistence is handled by RQ separately.
        self.log.error("Verification job failed. job_id=%s", job.id)


def run_worker() -> None:
    logging.basicConfig(level=logging.INFO)
    worker = VerificationWorker(
        [get_verification_queue()],
        connection=get_verification_redis(),
        serializer=JSONSerializer,
        log_job_description=False,
    )
    worker.work()


if __name__ == "__main__":
    run_worker()
