import argparse
import asyncio
import json
import time
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas.finding import Finding, FindingSeverity, FindingTool
from app.services.rag.embedder import OpenAIEmbedder
from app.services.rag.hybrid_search import EvidenceDocument
from app.services.rag.query_builder import build_rag_query
from app.services.rag.vector_store import (
    SecurityDocumentSearchResult,
    SecurityDocumentVectorStore,
)

DEFAULT_DATASET_PATH = Path("rag_eval/security_findings.json")
SEARCH_MODES = ("vector", "fts", "hybrid")


@dataclass(frozen=True)
class EvaluationCase:
    name: str
    finding: Finding
    expected_terms: list[str]


@dataclass(frozen=True)
class CaseResult:
    name: str
    first_match_rank: int | None
    latency_ms: float
    matched_term: str | None
    top_titles: list[str]


# RAG 검색 품질 평가 실행
def main() -> None:
    args = parse_args()
    asyncio.run(async_main(args))


# 단일 이벤트 루프에서 전체 평가 실행
async def async_main(args: argparse.Namespace) -> None:
    cases = load_evaluation_cases(args.dataset)

    if args.limit_cases is not None:
        cases = cases[: args.limit_cases]

    modes = SEARCH_MODES if args.mode == "all" else (args.mode,)
    for mode in modes:
        print(f"\nmode={mode}")
        results = await evaluate_cases(cases, mode, args.top_k)
        print_summary(results, args.top_k)

        if args.show_failures:
            print_failures(results)


# CLI 옵션 정의
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate RAG search quality with a small labeled dataset.",
    )
    parser.add_argument("--dataset", type=Path, default=DEFAULT_DATASET_PATH)
    parser.add_argument(
        "--mode",
        choices=[*SEARCH_MODES, "all"],
        default="all",
        help="Search mode to evaluate.",
    )
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--limit-cases", type=int, default=None)
    parser.add_argument("--show-failures", action="store_true")
    return parser.parse_args()


# 평가셋 로딩
def load_evaluation_cases(path: Path) -> list[EvaluationCase]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [_build_evaluation_case(item) for item in data]


# JSON 데이터를 평가 케이스로 변환
def _build_evaluation_case(item: dict[str, Any]) -> EvaluationCase:
    finding_data = item["finding"]
    return EvaluationCase(
        name=item["name"],
        finding=Finding(
            tool=FindingTool.SEMGREP,
            type=finding_data["type"],
            cwe_id=finding_data.get("cwe_id"),
            severity=FindingSeverity(finding_data["severity"]),
            file_path=finding_data["file_path"],
            line_start=1,
            message=finding_data["message"],
            evidence=finding_data.get("evidence"),
        ),
        expected_terms=item["expected_terms"],
    )


# 전체 케이스 평가
async def evaluate_cases(
    cases: list[EvaluationCase],
    mode: str,
    top_k: int,
) -> list[CaseResult]:
    if top_k <= 0:
        raise ValueError("--top-k must be positive")

    from app.core.config import settings
    from app.core.database import AsyncSessionLocal

    embedder = OpenAIEmbedder()
    async with AsyncSessionLocal() as session:
        store = SecurityDocumentVectorStore(session)
        results: list[CaseResult] = []

        for case in cases:
            started_at = time.perf_counter()
            query = build_rag_query(case.finding)
            query_embedding = embedder.embed_query(query.query_text)
            search_results = await search_by_mode(
                store=store,
                query_text=query.query_text,
                query_embedding=query_embedding,
                mode=mode,
                top_k=top_k,
                vector_top_k=settings.RAG_VECTOR_TOP_K,
                fts_top_k=settings.RAG_FTS_TOP_K,
                rrf_k=settings.RAG_RRF_K,
            )
            latency_ms = (time.perf_counter() - started_at) * 1000
            results.append(build_case_result(case, search_results, latency_ms))

    return results


# mode별 검색 실행
async def search_by_mode(
    store: SecurityDocumentVectorStore,
    query_text: str,
    query_embedding: list[float],
    mode: str,
    top_k: int,
    vector_top_k: int,
    fts_top_k: int,
    rrf_k: int,
) -> list[EvidenceDocument]:
    if mode == "vector":
        results = await store.search_by_vector(query_embedding, top_k)
        return [_to_evidence_document(result, 1 / (rank + 1)) for rank, result in enumerate(results)]

    if mode == "fts":
        results = await store.search_by_fts(query_text, top_k)
        return [_to_evidence_document(result, result.fts_rank or 0.0) for result in results]

    vector_results = await store.search_by_vector(query_embedding, vector_top_k)
    fts_results = await store.search_by_fts(query_text, fts_top_k)
    return merge_hybrid_results(vector_results, fts_results, rrf_k)[:top_k]


# RRF 기반 hybrid 결과 병합
def merge_hybrid_results(
    vector_results: list[SecurityDocumentSearchResult],
    fts_results: list[SecurityDocumentSearchResult],
    rrf_k: int,
) -> list[EvidenceDocument]:
    results_by_id: dict[int, SecurityDocumentSearchResult] = {}
    scores_by_id: dict[int, float] = {}

    _add_rrf_scores(vector_results, rrf_k, results_by_id, scores_by_id)
    _add_rrf_scores(fts_results, rrf_k, results_by_id, scores_by_id)

    return [
        _to_evidence_document(results_by_id[document_id], score)
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
            + 1 / (rrf_k + rank)
        )


# 내부 검색 결과를 평가용 evidence로 변환
def _to_evidence_document(
    result: SecurityDocumentSearchResult,
    score: float,
) -> EvidenceDocument:
    return EvidenceDocument(
        title=result.title,
        source=result.source_type.value,
        url=result.url,
        content=result.content,
        score=score,
    )


# 단일 케이스 결과 계산
def build_case_result(
    case: EvaluationCase,
    search_results: list[EvidenceDocument],
    latency_ms: float,
) -> CaseResult:
    first_match_rank: int | None = None
    matched_term: str | None = None

    for rank, result in enumerate(search_results, start=1):
        matched_term = find_matched_term(result, case.expected_terms)
        if matched_term:
            first_match_rank = rank
            break

    return CaseResult(
        name=case.name,
        first_match_rank=first_match_rank,
        latency_ms=latency_ms,
        matched_term=matched_term,
        top_titles=[result.title for result in search_results],
    )


# 기대 키워드 포함 여부 확인
def find_matched_term(
    result: EvidenceDocument,
    expected_terms: list[str],
) -> str | None:
    haystack = " ".join(
        value
        for value in [result.title, result.content, result.url]
        if value
    ).lower()

    for term in expected_terms:
        if term.lower() in haystack:
            return term

    return None


# 평가 요약 출력
def print_summary(results: list[CaseResult], top_k: int) -> None:
    recall = sum(result.first_match_rank is not None for result in results) / len(results)
    reciprocal_ranks = [
        1 / result.first_match_rank
        for result in results
        if result.first_match_rank is not None
    ]
    mrr = sum(reciprocal_ranks) / len(results)
    avg_latency_ms = sum(result.latency_ms for result in results) / len(results)

    print(f"cases={len(results)}")
    print(f"recall@{top_k}={recall:.3f}")
    print(f"mrr@{top_k}={mrr:.3f}")
    print(f"avg_latency_ms={avg_latency_ms:.1f}")


# 실패 케이스 출력
def print_failures(results: list[CaseResult]) -> None:
    failures = [result for result in results if result.first_match_rank is None]
    if not failures:
        print("failed_cases=[]")
        return

    print("failed_cases=")
    for result in failures:
        print(f"- {result.name}: {result.top_titles}")


if __name__ == "__main__":
    main()
