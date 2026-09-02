import logging

from app.schemas.finding import Finding
from app.schemas.explanation import ExplanationResult, FixExample, ReferenceDocument
from app.services.llm.claude_client import ClaudeClientError, ClaudeExplanationClient
from app.services.llm.prompt_builder import build_explanation_prompt
from app.services.rag.hybrid_search import EvidenceDocument

logger = logging.getLogger(__name__)


# 비어 있지 않은 참고 URL을 기존 순서대로 중복 없이 병합
def merge_references(*reference_groups: list[str]) -> list[str]:
    references = [
        reference
        for group in reference_groups
        for reference in group
        if reference
    ]
    return list(dict.fromkeys(references))


# Claude API로 Finding 설명과 수정 가이드를 생성
def generate_explanation(
    finding: Finding,
    evidence_documents: list[EvidenceDocument],
) -> ExplanationResult:
    prompt = build_explanation_prompt(finding, evidence_documents)
    try:
        explanation = ClaudeExplanationClient().generate_explanation(prompt)
    except ClaudeClientError:
        logger.exception(
            "Claude explanation generation failed. using fallback. type=%s cwe_id=%s file_path=%s",
            finding.type,
            finding.cwe_id,
            finding.file_path,
        )
        return build_fallback_explanation(finding, evidence_documents)

    references = [
        document.url for document in evidence_documents if document.url is not None
    ]

    return explanation.model_copy(
        update={
            "references": merge_references(explanation.references, references),
            "fix_examples": ensure_fix_examples(finding, explanation.fix_examples),
            "reference_documents": [
                ReferenceDocument(title=document.title, url=document.url)
                for document in evidence_documents
            ],
        }
    )


# LLM이 수정 예시를 비워 둔 경우 최소 수정 예시 보정
def ensure_fix_examples(
    finding: Finding,
    fix_examples: list[FixExample],
) -> list[FixExample]:
    if fix_examples:
        return fix_examples

    if "SQL_INJECTION" in finding.type or finding.cwe_id == "CWE-89":
        return [
            FixExample(
                language="Java" if finding.file_path.endswith(".java") else None,
                vulnerable_code=finding.evidence,
                fixed_code=(
                    'String sql = "SELECT * FROM users WHERE id = ?";\n'
                    "PreparedStatement statement = connection.prepareStatement(sql);\n"
                    "statement.setString(1, userId);\n"
                    "ResultSet resultSet = statement.executeQuery();"
                ),
                explanation=(
                    "PreparedStatement를 사용하면 SQL 구조와 사용자 입력값이 분리되어 "
                    "입력값이 SQL 명령으로 해석되는 것을 방지할 수 있습니다."
                ),
            )
        ]

    return [
        FixExample(
            language=None,
            vulnerable_code=finding.evidence,
            fixed_code="취약한 API 사용을 안전한 API 또는 검증된 보안 패턴으로 교체해야 합니다.",
            explanation=(
                "탐지된 취약점 유형과 참조 문서를 기준으로 입력 검증, 출력 인코딩, "
                "권한 제한, 안전한 라이브러리 사용 등 적절한 보안 조치를 적용해야 합니다."
            ),
        )
    ]


# Claude 호출 실패 시 분석 전체 중단 방지 기본 설명 생성
def build_fallback_explanation(
    finding: Finding,
    evidence_documents: list[EvidenceDocument],
) -> ExplanationResult:
    references = [
        document.url for document in evidence_documents if document.url is not None
    ]
    cwe_text = f" ({finding.cwe_id})" if finding.cwe_id else ""

    return ExplanationResult(
        summary=f"{finding.type}{cwe_text} 취약점이 {finding.file_path}에서 탐지되었습니다.",
        root_cause=(
            "LLM 기반 상세 원인 분석을 생성하지 못했습니다. "
            "탐지 메시지와 코드 evidence를 기준으로 취약한 코드 경로를 확인해야 합니다."
        ),
        impact=(
            "해당 취약점이 악용될 경우 기밀성, 무결성, 가용성에 영향을 줄 수 있습니다. "
            "정확한 영향도는 탐지 위치와 실행 권한을 함께 검토해야 합니다."
        ),
        recommendation=(
            "탐지된 코드 위치를 확인하고 관련 CWE/OWASP 보안 가이드에 따라 "
            "검증, 이스케이프, 권한 제한, 안전한 API 사용 등 적절한 보안 조치를 적용해야 합니다."
        ),
        fix_examples=ensure_fix_examples(finding, []),
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
            "summary": explanation.summary,
            "root_cause": explanation.root_cause,
            "impact": explanation.impact,
            "recommendation": explanation.recommendation,
            "fix_examples": explanation.fix_examples,
            "references": merge_references(
                finding.references,
                explanation.references,
            ),
            "reference_documents": explanation.reference_documents,
        }
    )
