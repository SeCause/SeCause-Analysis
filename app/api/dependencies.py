import hmac
import logging
from typing import Annotated

from fastapi import Header, HTTPException, status

from app.core.config import settings

logger = logging.getLogger(__name__)


def verify_internal_token(
    x_internal_token: Annotated[
        str | None,
        Header(alias="X-Internal-Token"),
    ] = None,
) -> None:
    configured_token = settings.ANALYSIS_CALLBACK_INTERNAL_TOKEN
    if configured_token is None or not configured_token.strip():
        logger.warning(
            "Internal API authentication is disabled because ANALYSIS_CALLBACK_INTERNAL_TOKEN is empty"
        )
        return

    if x_internal_token is None or not hmac.compare_digest(
        x_internal_token,
        configured_token,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )
