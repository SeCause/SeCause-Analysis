"""Contracts for evidence-grounded verification, independent of analysis DTOs."""

from enum import Enum
from typing import Annotated
from uuid import UUID

from pydantic import ConfigDict, Field, StringConstraints

from app.schemas.base import CamelModel

NonBlankText = Annotated[str, StringConstraints(min_length=1, pattern=r"\S")]
AnswerText = Annotated[NonBlankText, Field(max_length=4000)]


class VerificationModel(CamelModel):
    model_config = ConfigDict(extra="forbid")


class AnswerField(str, Enum):
    SUMMARY = "summary"
    ROOT_CAUSE = "rootCause"
    IMPACT = "impact"


class Verdict(str, Enum):
    SUPPORTED = "SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class VerificationStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class EvidenceKind(str, Enum):
    CODE = "CODE"
    SCANNER = "SCANNER"
    DOCUMENT = "DOCUMENT"


class VerificationAnswer(VerificationModel):
    summary: AnswerText
    root_cause: AnswerText
    impact: AnswerText


class VerificationEvidence(VerificationModel):
    evidence_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9_-]+$")
    kind: EvidenceKind
    content: Annotated[NonBlankText, Field(max_length=12000)]
    file_path: Annotated[NonBlankText, Field(max_length=500)] | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    title: Annotated[NonBlankText, Field(max_length=500)] | None = None
    url: str | None = Field(default=None, max_length=2000)


class VerificationContext(VerificationModel):
    analysis_id: int | None = Field(default=None, gt=0)
    finding_id: str | None = Field(default=None, max_length=100)
    vulnerability_type: str | None = Field(default=None, max_length=200)
    cwe_id: str | None = Field(default=None, pattern=r"^CWE-\d+$")


class VerificationRequest(VerificationModel):
    answer: VerificationAnswer
    evidence: list[VerificationEvidence] = Field(default_factory=list, max_length=30)
    context: VerificationContext | None = None


class EvidenceCitation(VerificationModel):
    evidence_id: str = Field(min_length=1, max_length=80)
    quote: Annotated[NonBlankText, Field(max_length=2000)]


class ClaimVerification(VerificationModel):
    field: AnswerField
    source_text: AnswerText
    claim: AnswerText
    verdict: Verdict
    reason: Annotated[NonBlankText, Field(max_length=2000)]
    citations: list[EvidenceCitation] = Field(default_factory=list, max_length=10)


class VerificationJudgment(VerificationModel):
    results: list[ClaimVerification] = Field(min_length=1, max_length=60)


class VerificationUsage(VerificationModel):
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)


class VerificationResult(VerificationJudgment):
    model: str
    prompt_version: str
    duration_ms: int = Field(ge=0)
    usage: VerificationUsage


class VerificationAccepted(VerificationModel):
    verification_id: UUID
    status: VerificationStatus = VerificationStatus.QUEUED


class VerificationError(VerificationModel):
    code: str
    message: str


class VerificationResponse(VerificationModel):
    verification_id: UUID
    status: VerificationStatus
    result: VerificationResult | None = None
    error: VerificationError | None = None
