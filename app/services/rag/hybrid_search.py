import asyncio
import logging
from dataclasses import dataclass

from app.schemas.base import CamelModel
from app.schemas.finding import Finding
from app.services.rag.embedder import OpenAIEmbedder
from app.services.rag.query_builder import RagQuery, build_rag_query
from app.services.rag.vector_store import (
    SecurityDocumentSearchResult,
    SecurityDocumentVectorStore,
)

logger = logging.getLogger(__name__)


class EvidenceDocument(CamelModel):
    title: str
    source: str
    url: str | None = None
    content: str
    score: float = 0.0


@dataclass(frozen=True)
class RankedSearchResult:
    result: SecurityDocumentSearchResult
    score: float


# Finding에서 query를 만들고 Hybrid search 수행
def search_evidence_for_finding(finding: Finding) -> list[EvidenceDocument]:
    return search_evidence(build_rag_query(finding))


# 동기 분석 job에서 호출하기 위한 검색 진입점
def search_evidence(query: RagQuery) -> list[EvidenceDocument]:
    try:
        return asyncio.run(search_evidence_async(query))
    except Exception:
        logger.exception(
            "RAG search failed. cwe_id=%s type=%s",
            query.cwe_id,
            query.vulnerability_type,
        )
        return []


# pgvector 검색과 FTS 검색을 실행한 뒤 RRF로 병합
async def search_evidence_async(query: RagQuery) -> list[EvidenceDocument]:
    from app.core.config import settings
    from app.core.database import AsyncSessionLocal

    query_embedding = OpenAIEmbedder().embed_query(query.query_text)

    async with AsyncSessionLocal() as session:
        store = SecurityDocumentVectorStore(session)
        vector_results, fts_results = await asyncio.gather(
            store.search_by_vector(query_embedding, settings.RAG_VECTOR_TOP_K),
            store.search_by_fts(query.query_text, settings.RAG_FTS_TOP_K),
        )

    ranked_results = _merge_results_by_rrf(
        vector_results=vector_results,
        fts_results=fts_results,
        rrf_k=settings.RAG_RRF_K,
    )

    return [
        _to_evidence_document(ranked_result)
        for ranked_result in ranked_results[: settings.RAG_RESULT_TOP_K]
    ]


# RRF 방식으로 vector/FTS 결과 병합
def _merge_results_by_rrf(
    vector_results: list[SecurityDocumentSearchResult],
    fts_results: list[SecurityDocumentSearchResult],
    rrf_k: int,
) -> list[RankedSearchResult]:
    if rrf_k < 0:
        raise ValueError("rrf_k must be greater than or equal to 0")

    results_by_id: dict[int, SecurityDocumentSearchResult] = {}
    scores_by_id: dict[int, float] = {}

    _add_rrf_scores(vector_results, rrf_k, results_by_id, scores_by_id)
    _add_rrf_scores(fts_results, rrf_k, results_by_id, scores_by_id)

    return [
        RankedSearchResult(result=results_by_id[document_id], score=score)
        for document_id, score in sorted(
            scores_by_id.items(),
            key=lambda item: item[1],
            reverse=True,
        )
    ]


# 검색 순위를 RRF 점수로 누적
def _add_rrf_scores(
    results: list[SecurityDocumentSearchResult],
    rrf_k: int,
    results_by_id: dict[int, SecurityDocumentSearchResult],
    scores_by_id: dict[int, float],
) -> None:
    for rank, result in enumerate(results, start=1):
        results_by_id.setdefault(result.security_document_id, result)
        scores_by_id[result.security_document_id] = (
            scores_by_id.get(result.security_document_id, 0.0)
            + _calculate_rrf_score(rank, rrf_k)
        )


# RRF 점수 계산
def _calculate_rrf_score(rank: int, rrf_k: int) -> float:
    if rank <= 0:
        raise ValueError("rank must be positive")

    return 1 / (rrf_k + rank)


# 내부 검색 결과를 LLM 입력용 evidence 문서로 변환
def _to_evidence_document(ranked_result: RankedSearchResult) -> EvidenceDocument:
    result = ranked_result.result

    return EvidenceDocument(
        title=result.title,
        source=result.source_type.value,
        url=result.url,
        content=result.content,
        score=ranked_result.score,
    )
