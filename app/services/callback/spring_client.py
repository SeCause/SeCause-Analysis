import logging
import time
from enum import Enum
from urllib.parse import urljoin

import httpx

from pydantic import ConfigDict, Field

from app.schemas.base import CamelModel, to_camel
from app.schemas.finding import Finding

logger = logging.getLogger(__name__)


class AnalysisStatus(str, Enum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class CallbackPayload(CamelModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=True,
    )


class AnalysisSummary(CallbackPayload):
    total_count: int = 0


class AnalysisSuccessCallbackPayload(CallbackPayload):
    analysis_id: int
    repository_id: int
    status: AnalysisStatus = AnalysisStatus.COMPLETED
    findings: list[Finding] = Field(default_factory=list)
    summary: AnalysisSummary


class AnalysisFailureCallbackPayload(CallbackPayload):
    analysis_id: int | None = None
    repository_id: int | None = None
    status: AnalysisStatus = AnalysisStatus.FAILED
    error_code: str
    error_message: str
    failed_stage: str


class SpringCallbackError(RuntimeError):
    pass


class SpringCallbackClient:
    def __init__(self) -> None:
        from app.core.config import settings

        self.base_url = settings.SPRING_CALLBACK_BASE_URL.rstrip("/") + "/"
        self.success_path = settings.SPRING_SUCCESS_CALLBACK_PATH.lstrip("/")
        self.failure_path = settings.SPRING_FAILURE_CALLBACK_PATH.lstrip("/")
        self.timeout_seconds = settings.SPRING_CALLBACK_TIMEOUT_SECONDS
        self.max_retries = settings.SPRING_CALLBACK_MAX_RETRIES

    # 분석 성공 payload를 Spring callback API로 전송
    def send_success(self, payload: AnalysisSuccessCallbackPayload) -> None:
        logger.info(
            "Sending Spring success callback. analysis_id=%s repository_id=%s finding_count=%s",
            payload.analysis_id,
            payload.repository_id,
            len(payload.findings),
        )
        self._post_callback(self.success_path, payload)

    # 분석 실패 payload를 Spring callback API로 전송
    def send_failure(self, payload: AnalysisFailureCallbackPayload) -> None:
        logger.error(
            "Sending Spring failure callback. analysis_id=%s repository_id=%s failed_stage=%s error_code=%s",
            payload.analysis_id,
            payload.repository_id,
            payload.failed_stage,
            payload.error_code,
        )
        self._post_callback(self.failure_path, payload)

    # callback HTTP POST 수행
    def _post_callback(self, path: str, payload: CallbackPayload) -> None:
        url = urljoin(self.base_url, path)
        body = payload.model_dump(by_alias=True, mode="json")
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    response = client.post(url, json=body)
                    response.raise_for_status()

                logger.info(
                    "Spring callback sent. url=%s status_code=%s",
                    url,
                    response.status_code,
                )
                return
            except Exception as exc:
                last_error = exc
                if not _is_retryable_callback_error(exc) or attempt >= self.max_retries:
                    break

                sleep_seconds = min(2 ** attempt, 8)
                logger.warning(
                    "Spring callback failed. retrying url=%s attempt=%s sleep_seconds=%s error=%s",
                    url,
                    attempt + 1,
                    sleep_seconds,
                    exc.__class__.__name__,
                )
                time.sleep(sleep_seconds)

        raise SpringCallbackError(f"Spring callback request failed. url={url}") from last_error


# 네트워크 오류, timeout, rate limit, 5xx만 재시도
def _is_retryable_callback_error(exc: Exception) -> bool:
    if isinstance(exc, httpx.TimeoutException | httpx.NetworkError):
        return True

    if isinstance(exc, httpx.HTTPStatusError):
        status_code = exc.response.status_code
        return status_code == 429 or status_code >= 500

    return False
