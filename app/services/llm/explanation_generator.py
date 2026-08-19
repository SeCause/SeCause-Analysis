from app.schemas.base import CamelModel
from app.schemas.finding import Finding
from app.services.llm.prompt_builder import build_explanation_prompt
from app.services.rag.hybrid_search import EvidenceDocument


class ExplanationResult(CamelModel):
    summary: str
    recommendation: str
    references: list[str]


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
        recommendation=(
            "Review the vulnerable code path, apply the framework-recommended "
            "secure pattern, and add a regression test for this case."
        ),
        references=references,
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
