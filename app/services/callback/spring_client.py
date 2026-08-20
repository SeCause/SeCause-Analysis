import logging
from enum import Enum

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


class SpringCallbackClient:
    # Spring callback HTTP 호출 전까지 payload 구조와 호출 지점을 고정하는 stub
    def send_success(self, payload: AnalysisSuccessCallbackPayload) -> None:
        logger.info(
            "Spring success callback stub. analysis_id=%s repository_id=%s finding_count=%s",
            payload.analysis_id,
            payload.repository_id,
            len(payload.findings),
        )

    # Spring callback HTTP 호출 전까지 실패 payload 구조와 호출 지점을 고정하는 stub
    def send_failure(self, payload: AnalysisFailureCallbackPayload) -> None:
        logger.error(
            "Spring failure callback stub. analysis_id=%s repository_id=%s failed_stage=%s error_code=%s",
            payload.analysis_id,
            payload.repository_id,
            payload.failed_stage,
            payload.error_code,
        )
