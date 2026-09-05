import asyncio
import logging
import re
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

    async with AsyncSessionLocal() as session:
        store = SecurityDocumentVectorStore(session)
        vector_results = await _search_by_vector_safely(
            store,
            query,
            settings.RAG_VECTOR_TOP_K,
        )
        fts_results = await _search_by_fts_safely(
            store,
            query,
            settings.RAG_FTS_TOP_K,
        )
        exact_cwe_results = await _search_by_cwe_id_safely(
            store,
            query,
            EXACT_CWE_TOP_K,
        )

    ranked_results = _merge_results_by_rrf(
        vector_results=vector_results,
        fts_results=fts_results,
        rrf_k=settings.RAG_RRF_K,
    )
    ranked_results = _merge_exact_cwe_matches(
        ranked_results,
        exact_cwe_results,
        query.cwe_id,
        settings.RAG_RRF_K,
    )

    return [
        _to_evidence_document(ranked_result)
        for ranked_result in ranked_results[: settings.RAG_RESULT_TOP_K]
    ]


# CWE ID 정확 매칭 문서 조회 실패 시 기존 검색 결과만 유지
async def _search_by_cwe_id_safely(
    store: SecurityDocumentVectorStore,
    query: RagQuery,
    limit: int,
) -> list[SecurityDocumentSearchResult]:
    if not query.cwe_id:
        return []

    try:
        return await store.search_by_cwe_id(query.cwe_id, limit, query.source_types)
    except Exception:
        logger.exception(
            "RAG exact CWE search failed. cwe_id=%s type=%s",
            query.cwe_id,
            query.vulnerability_type,
        )
        return []


# vector 검색 실패 시 FTS fallback을 막지 않도록 빈 결과 반환
async def _search_by_vector_safely(
    store: SecurityDocumentVectorStore,
    query: RagQuery,
    limit: int,
) -> list[SecurityDocumentSearchResult]:
    try:
        query_embedding = OpenAIEmbedder().embed_query(query.query_text)
        return await store.search_by_vector(query_embedding, limit, query.source_types)
    except Exception:
        logger.exception(
            "RAG vector search failed. cwe_id=%s type=%s",
            query.cwe_id,
            query.vulnerability_type,
        )
        return []


# FTS 검색 실패 시 vector 결과를 유지하도록 빈 결과 반환
async def _search_by_fts_safely(
    store: SecurityDocumentVectorStore,
    query: RagQuery,
    limit: int,
) -> list[SecurityDocumentSearchResult]:
    try:
        return await store.search_by_fts(query.query_text, limit, query.source_types)
    except Exception:
        logger.exception(
            "RAG FTS search failed. cwe_id=%s type=%s",
            query.cwe_id,
            query.vulnerability_type,
        )
        return []


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


# 정확한 CWE ID 후보를 병합하고 상위로 올리기 위한 점수 보정
def _merge_exact_cwe_matches(
    ranked_results: list[RankedSearchResult],
    exact_cwe_results: list[SecurityDocumentSearchResult],
    cwe_id: str | None,
    rrf_k: int,
) -> list[RankedSearchResult]:
    if not cwe_id:
        return ranked_results

    ranked_results_by_id = {
        ranked_result.result.security_document_id: ranked_result
        for ranked_result in ranked_results
    }

    for rank, result in enumerate(exact_cwe_results, start=1):
        existing_result = ranked_results_by_id.get(result.security_document_id)
        if existing_result:
            ranked_results_by_id[result.security_document_id] = RankedSearchResult(
                result=existing_result.result,
                score=existing_result.score
                + EXACT_CWE_MATCH_BOOST
                + _calculate_rrf_score(rank, rrf_k),
            )
            continue

        ranked_results_by_id[result.security_document_id] = RankedSearchResult(
            result=result,
            score=EXACT_CWE_MATCH_BOOST + _calculate_rrf_score(rank, rrf_k),
        )

    boosted_results = [
        RankedSearchResult(
            result=ranked_result.result,
            score=ranked_result.score
            + (
                EXACT_CWE_MATCH_BOOST
                if _contains_exact_cwe_id(ranked_result.result, cwe_id)
                else 0
            ),
        )
        for ranked_result in ranked_results_by_id.values()
    ]

    return sorted(boosted_results, key=lambda item: item.score, reverse=True)


# 검색 결과 본문/제목/URL의 정확한 CWE ID 포함 여부 확인
def _contains_exact_cwe_id(
    result: SecurityDocumentSearchResult,
    cwe_id: str,
) -> bool:
    haystack = " ".join(
        value
        for value in [result.title, result.content, result.url]
        if value
    )
    return re.search(rf"(?<![A-Za-z0-9-]){re.escape(cwe_id)}(?![A-Za-z0-9-])", haystack) is not None


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


EXACT_CWE_MATCH_BOOST = 0.02
EXACT_CWE_TOP_K = 1
