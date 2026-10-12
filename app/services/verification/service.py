"""Verification orchestration, with no HTTP, Redis or analysis-pipeline coupling."""

from time import monotonic
from typing import Protocol

from app.schemas.verification import (
    AnswerField,
    ClaimVerification,
    VerificationJudgment,
    VerificationRequest,
    VerificationResult,
    VerificationUsage,
    Verdict,
)
from app.services.verification.claude_client import ClaudeVerificationClient, ModelJudgment
from app.services.verification.prompt import PROMPT_VERSION
from app.services.verification.rules import validate_verification_request


class VerificationIntegrityError(RuntimeError):
    """Model output omitted answer text or supplied unverifiable citations."""


class VerificationClient(Protocol):
    def verify(self, request: VerificationRequest) -> ModelJudgment: ...


def validate_judgment(request: VerificationRequest, judgment: VerificationJudgment) -> None:
    answer = request.answer.model_dump(by_alias=True)
    evidence = {item.evidence_id: item.content for item in request.evidence}
    coverage = {field: [False] * len(text) for field, text in answer.items()}

    for result in judgment.results:
        field = result.field.value
        source = answer[field]
        start = source.find(result.source_text)
        if start < 0:
            raise VerificationIntegrityError("Claim sourceText is not in the answer field")
        # Mark every occurrence, allowing identical repeated statements.
        while start >= 0:
            end = start + len(result.source_text)
            coverage[field][start:end] = [True] * len(result.source_text)
            start = source.find(result.source_text, start + 1)

        if result.verdict != Verdict.INSUFFICIENT_EVIDENCE and not result.citations:
            raise VerificationIntegrityError("Supported or contradicted claims require citations")
        for citation in result.citations:
            content = evidence.get(citation.evidence_id)
            if content is None or citation.quote not in content:
                raise VerificationIntegrityError("Citation ID or quote does not match the evidence")

    for field, text in answer.items():
        if any(not covered and not char.isspace() for char, covered in zip(text, coverage[field])):
            raise VerificationIntegrityError("Judgment does not cover every answer field completely")


def verify_answer(
    request: VerificationRequest,
    client: VerificationClient | None = None,
) -> VerificationResult:
    started_at = monotonic()
    validate_verification_request(request)

    if request.evidence:
        generated = (client or ClaudeVerificationClient()).verify(request)
    else:
        # Without evidence, no model call can establish support or contradiction.
        generated = ModelJudgment(
            judgment=VerificationJudgment(results=[
                ClaimVerification(
                    field=AnswerField(field), source_text=text, claim=text,
                    verdict=Verdict.INSUFFICIENT_EVIDENCE,
                    reason="분석 당시 근거가 제공되지 않아 설명을 검증할 수 없습니다.",
                )
                for field, text in request.answer.model_dump(by_alias=True).items()
            ]),
            model="not-invoked",
            usage=VerificationUsage(),
        )

    validate_judgment(request, generated.judgment)
    return VerificationResult(
        results=generated.judgment.results,
        model=generated.model,
        prompt_version=PROMPT_VERSION,
        duration_ms=round((monotonic() - started_at) * 1000),
        usage=generated.usage,
    )
