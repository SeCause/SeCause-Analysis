from app.schemas.base import CamelModel
from app.schemas.finding import Finding
from app.services.rag.query_builder import RagQuery, build_rag_query


class EvidenceDocument(CamelModel):
    title: str
    source: str
    url: str | None = None
    content: str
    score: float = 0.0


# Hybrid search 결과 형태를 고정하기 위한 stub 검색 함수
def search_evidence(query: RagQuery) -> list[EvidenceDocument]:
    if not query.cwe_id:
        return []

    return [
        EvidenceDocument(
            title=f"{query.cwe_id} security guidance",
            source="MVP_STUB",
            url=None,
            content=(
                f"Review trusted security references for {query.cwe_id} "
                f"and apply a fix for {query.vulnerability_type}."
            ),
            score=1.0,
        )
    ]


# Finding에서 query를 만들고 Hybrid search stub까지 한 번에 수행
def search_evidence_for_finding(finding: Finding) -> list[EvidenceDocument]:
    return search_evidence(build_rag_query(finding))
