"""Internal verification endpoints, intentionally separate from analysis routes."""

import hmac
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from redis.exceptions import RedisError

from app.schemas.verification import VerificationAccepted, VerificationRequest, VerificationResponse
from app.services.verification.config import get_verification_settings
from app.services.verification.rules import VerificationInputError
from app.services.verification.tasks import VerificationNotFoundError, enqueue_verification, get_verification


def require_verification_token(
    x_internal_token: Annotated[str | None, Header(alias="X-Internal-Token")] = None,
) -> None:
    configured = get_verification_settings().ANALYSIS_CALLBACK_INTERNAL_TOKEN
    if not configured or not configured.strip():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Verification authentication is not configured")
    if x_internal_token is None or not hmac.compare_digest(
        x_internal_token.encode("utf-8"), configured.encode("utf-8"),
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")


router = APIRouter(
    prefix="/internal/answer-verifications",
    dependencies=[Depends(require_verification_token)],
)


@router.post("", response_model=VerificationAccepted, status_code=status.HTTP_202_ACCEPTED)
def create_verification(request: VerificationRequest) -> VerificationAccepted:
    # Sync endpoints run blocking Redis calls in FastAPI's thread pool.
    try:
        return enqueue_verification(request)
    except VerificationInputError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from None
    except RedisError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Verification queue is unavailable") from None


@router.get("/{verification_id}", response_model=VerificationResponse, response_model_exclude_none=True)
def read_verification(verification_id: UUID) -> VerificationResponse:
    try:
        return get_verification(verification_id)
    except VerificationNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Verification not found or expired") from None
    except RedisError:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Verification store is unavailable") from None
