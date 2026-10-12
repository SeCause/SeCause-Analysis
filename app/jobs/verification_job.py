"""RQ adapter for the independent verification service."""

import logging
from time import monotonic

from app.schemas.verification import VerificationRequest
from app.services.verification.service import verify_answer

logger = logging.getLogger(__name__)


class VerificationJobError(RuntimeError):
    """Sanitized failure persisted by RQ, without request or model contents."""


def run_verification_job(payload: dict, verification_id: str) -> dict:
    started_at = monotonic()
    logger.info("Verification started. verification_id=%s", verification_id)
    try:
        request = VerificationRequest.model_validate(payload)
        result = verify_answer(request)
    except Exception:
        logger.warning(
            "Verification failed. verification_id=%s duration_ms=%s",
            verification_id, round((monotonic() - started_at) * 1000),
        )
        raise VerificationJobError("Answer verification could not be completed") from None

    logger.info(
        "Verification completed. verification_id=%s duration_ms=%s input_tokens=%s output_tokens=%s",
        verification_id, result.duration_ms, result.usage.input_tokens, result.usage.output_tokens,
    )
    return result.model_dump(by_alias=True, mode="json")
