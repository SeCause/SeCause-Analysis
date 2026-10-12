"""Task lifecycle using RQ as the single source of truth for state and retention."""

from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import ValidationError
from rq.exceptions import NoSuchJobError
from rq.job import Job
from rq.serializers import JSONSerializer

from app.jobs.verification_job import run_verification_job
from app.jobs.verification_queue import (
    VERIFICATION_QUEUE_NAME,
    get_verification_queue,
    get_verification_redis,
)
from app.schemas.verification import (
    VerificationAccepted,
    VerificationError,
    VerificationRequest,
    VerificationResponse,
    VerificationResult,
    VerificationStatus,
)
from app.services.verification.config import get_verification_settings
from app.services.verification.rules import validate_verification_request

JOB_PREFIX = "answer-verification-"
WORKER_SHUTDOWN_GRACE_SECONDS = 60


class VerificationNotFoundError(LookupError):
    """Unknown, expired or unrelated job ID."""


def enqueue_verification(request: VerificationRequest) -> VerificationAccepted:
    validate_verification_request(request)
    settings = get_verification_settings()
    verification_id = uuid4()
    get_verification_queue().enqueue_call(
        func=run_verification_job,
        args=(request.model_dump(by_alias=True, mode="json"), str(verification_id)),
        job_id=JOB_PREFIX + str(verification_id),
        description=f"Answer verification {verification_id}",
        timeout=settings.VERIFICATION_JOB_TIMEOUT_SECONDS,
        ttl=settings.VERIFICATION_QUEUE_TTL_SECONDS,
        result_ttl=settings.VERIFICATION_RESULT_TTL_SECONDS,
        failure_ttl=settings.VERIFICATION_FAILURE_TTL_SECONDS,
    )
    return VerificationAccepted(verification_id=verification_id)


def get_verification(verification_id: UUID) -> VerificationResponse:
    try:
        job = Job.fetch(
            JOB_PREFIX + str(verification_id),
            connection=get_verification_redis(),
            serializer=JSONSerializer,
        )
    except NoSuchJobError:
        raise VerificationNotFoundError from None
    if job.origin != VERIFICATION_QUEUE_NAME:
        raise VerificationNotFoundError

    status = job.get_status(refresh=True)
    if status is None:
        raise VerificationNotFoundError
    if status == "finished":
        try:
            result = VerificationResult.model_validate(job.return_value(refresh=True))
        except (ValidationError, ValueError, TypeError):
            return failed_response(verification_id, "INVALID_RESULT", "Verification result is unavailable")
        return VerificationResponse(
            verification_id=verification_id, status=VerificationStatus.COMPLETED, result=result,
        )
    if status == "started":
        if exceeded_execution_deadline(job):
            return failed_response(verification_id, "JOB_TIMEOUT", "Verification execution deadline exceeded")
        return VerificationResponse(verification_id=verification_id, status=VerificationStatus.RUNNING)
    if status in {"queued", "deferred", "scheduled"}:
        return VerificationResponse(verification_id=verification_id, status=VerificationStatus.QUEUED)
    # Failed, stopped, canceled or unknown RQ states must never look completed.
    return failed_response(verification_id, "VERIFICATION_FAILED", "Verification job did not complete")


def exceeded_execution_deadline(job: Job) -> bool:
    if job.started_at is None or job.timeout is None:
        return False
    started_at = job.started_at.replace(tzinfo=timezone.utc) if job.started_at.tzinfo is None else job.started_at
    elapsed_seconds = (datetime.now(timezone.utc) - started_at).total_seconds()
    return elapsed_seconds > job.timeout + WORKER_SHUTDOWN_GRACE_SECONDS


def failed_response(verification_id: UUID, code: str, message: str) -> VerificationResponse:
    return VerificationResponse(
        verification_id=verification_id,
        status=VerificationStatus.FAILED,
        error=VerificationError(code=code, message=message),
    )
