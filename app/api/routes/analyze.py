import logging

from fastapi import APIRouter, HTTPException, status
from redis.exceptions import RedisError

from app.jobs.analysis_job import run_analysis_job
from app.jobs.queue import get_analysis_queue
from app.schemas.analyze import AnalyzeRequest, AnalyzeResponse

router = APIRouter()
logger = logging.getLogger(__name__)


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
    try:
        queue = get_analysis_queue()
        job = queue.enqueue(run_analysis_job, request.to_job_payload())
    except RedisError as exc:
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
