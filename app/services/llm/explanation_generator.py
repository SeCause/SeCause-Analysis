from pydantic import Field

from app.schemas.base import CamelModel
from app.schemas.finding import Finding
from app.services.llm.prompt_builder import build_explanation_prompt
from app.services.rag.hybrid_search import EvidenceDocument


class ReferenceDocument(CamelModel):
    title: str
    url: str | None = None


class FixExample(CamelModel):
    language: str | None = None
    vulnerable_code: str | None = None
    fixed_code: str
    explanation: str


class ExplanationResult(CamelModel):
    summary: str
    root_cause: str
    impact: str
    recommendation: str
    fix_examples: list[FixExample] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    reference_documents: list[ReferenceDocument] = Field(default_factory=list)


# 비어 있지 않은 참고 URL을 기존 순서대로 중복 없이 병합
def merge_references(*reference_groups: list[str]) -> list[str]:
    references = [
        reference
        for group in reference_groups
        for reference in group
        if reference
    ]
    return list(dict.fromkeys(references))


# Claude API 없이 Finding에 넣을 mock 설명과 수정 가이드를 생성
def generate_explanation(
    finding: Finding,
    evidence_documents: list[EvidenceDocument],
) -> ExplanationResult:
    build_explanation_prompt(finding, evidence_documents)

    references = [
        document.url for document in evidence_documents if document.url is not None
    ]
    cwe_text = f" ({finding.cwe_id})" if finding.cwe_id else ""

    return ExplanationResult(
        summary=f"{finding.type}{cwe_text} finding was detected in {finding.file_path}.",
        root_cause="The vulnerable code path appears to handle untrusted input without a sufficient security control.",
        impact="An attacker may abuse this weakness depending on the affected code path and runtime privileges.",
        recommendation=(
            "Review the vulnerable code path, apply the framework-recommended "
            "secure pattern, and add a regression test for this case."
        ),
        fix_examples=[],
        references=references,
        reference_documents=[
            ReferenceDocument(title=document.title, url=document.url)
            for document in evidence_documents
        ],
    )


# 생성된 설명 결과를 기존 Finding에 반영한 enriched Finding을 반환
def enrich_finding_with_explanation(
    finding: Finding,
    evidence_documents: list[EvidenceDocument],
) -> Finding:
    explanation = generate_explanation(finding, evidence_documents)

    return finding.model_copy(
        update={
            "recommendation": explanation.recommendation,
            "references": merge_references(
                finding.references,
                explanation.references,
            ),
        }
    )
