"""Internal verification endpoints, intentionally separate from analysis routes."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from redis.exceptions import RedisError

from app.api.token_auth import internal_token_matches
from app.schemas.verification import VerificationAccepted, VerificationRequest, VerificationResponse
from app.services.verification.config import get_verification_settings
from app.services.verification.rules import VerificationInputError
from app.services.verification.tasks import VerificationNotFoundError, enqueue_verification, get_verification


def require_verification_token(
    x_internal_token: Annotated[str | None, Header(alias="X-Internal-Token")] = None,
) -> None:
    """Require configured verification credentials; missing configuration returns 503."""
    configured = get_verification_settings().ANALYSIS_CALLBACK_INTERNAL_TOKEN
    if not configured or not configured.strip():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Verification authentication is not configured")
    if not internal_token_matches(x_internal_token, configured):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")


router = APIRouter(
    prefix="/internal/answer-verifications",
    dependencies=[Depends(require_verification_token)],
)


@router.post("", response_model=VerificationAccepted, status_code=status.HTTP_202_ACCEPTED)
def create_verification(request: VerificationRequest) -> VerificationAccepted:
    # Sync endpoints run blocking Redis calls in FastAPI's thread pool.
    try:
        # 입력 검사 및 검증 작업 등록, 조회용 ID 반환
        return enqueue_verification(request)
    except VerificationInputError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    except RedisError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Verification queue is unavailable") from None


@router.get("/{verification_id}", response_model=VerificationResponse, response_model_exclude_none=True)
def read_verification(verification_id: UUID) -> VerificationResponse:
    try:
        # RQ 상태·저장 결과 조회 및 API 응답 변환
        return get_verification(verification_id)
    except VerificationNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Verification not found or expired") from None
    except RedisError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Verification store is unavailable") from None
