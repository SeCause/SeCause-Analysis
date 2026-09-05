import logging

from fastapi import APIRouter, HTTPException, status
from redis.exceptions import RedisError

from app.jobs.analysis_job import run_analysis_job
from app.jobs.queue import get_analysis_queue
from app.jobs.secret_store import delete_github_token_reference, store_github_token
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse

router = APIRouter()
logger = logging.getLogger(__name__)


def cleanup_token_reference(token_reference: str | None, analysis_id: int) -> None:
    if token_reference is None:
        return

    try:
        delete_github_token_reference(token_reference)
    except RedisError:
        logger.warning(
            "Failed to delete GitHub token reference after enqueue error. analysis_id=%s",
            analysis_id,
        )


@router.post(
    "/internal/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def analyze(request: AnalyzeRequest):
    """
    분석 요청을 수신하고 RQ job으로 등록.
    Spring Boot는 이 응답을 받으면 즉시 클라이언트에게 analysis_id 반환
    """
    github_token_reference = None

    try:
        queue = get_analysis_queue()
        github_token_reference = store_github_token(request.github_token)
        job = queue.enqueue(
            run_analysis_job,
            request.to_job_payload(github_token_reference),
        )
    except RedisError as exc:
        cleanup_token_reference(github_token_reference, request.analysis_id)
        logger.exception(
            "Failed to enqueue analysis job. analysis_id=%s repository_id=%s",
            request.analysis_id,
            request.repository_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analysis queue is unavailable",
        ) from exc
    except Exception as exc:
        cleanup_token_reference(github_token_reference, request.analysis_id)
        logger.exception(
            "Unexpected error while enqueueing analysis job. analysis_id=%s repository_id=%s",
            request.analysis_id,
            request.repository_id,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Analysis queue is unavailable",
        ) from exc

    return AnalyzeResponse(
        accepted=True,
        analysis_id=request.analysis_id,
        job_id=job.id,
        message="Analysis queued for processing",
    )
