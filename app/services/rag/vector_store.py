from collections import defaultdict
from dataclasses import dataclass
import re

from app.services.rag.documents import RagDocumentChunk, RagSourceType
from app.services.rag.embedder import EmbeddingResult


class VectorStoreError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecurityDocumentRow:
    source_type: RagSourceType
    title: str
    content: str
    embedding: list[float]
    url: str | None = None


@dataclass(frozen=True)
class SecurityDocumentSearchResult:
    security_document_id: int
    source_type: RagSourceType
    title: str
    content: str
    url: str | None = None
    vector_distance: float | None = None
    fts_rank: float | None = None


class SecurityDocumentVectorStore:
    def __init__(self, session) -> None:
        self.session = session

    # source_type 단위 기존 색인 삭제
    async def delete_by_source_type(self, source_type: RagSourceType) -> int:
        query = _get_sql_text()(
            """
            DELETE FROM public.security_documents
            WHERE source_type = CAST(:source_type AS reference_type_enum)
            """
        )
        result = await self.session.execute(
            query,
            {"source_type": source_type.value},
        )
        return result.rowcount or 0

    # security_documents batch 저장
    async def insert_rows(self, rows: list[SecurityDocumentRow]) -> int:
        if not rows:
            return 0

        await self.delete_existing_rows(rows)

        query = _get_sql_text()(
            """
            INSERT INTO public.security_documents (
                title,
                url,
                content,
                source_type,
                embedding,
                created_at,
                updated_at
            )
            VALUES (
                :title,
                :url,
                :content,
                CAST(:source_type AS reference_type_enum),
                CAST(:embedding AS vector),
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
            )
            """
        )
        await self.session.execute(
            query,
            [
                {
                    "title": row.title,
                    "url": row.url,
                    "content": row.content,
                    "source_type": row.source_type.value,
                    "embedding": to_vector_literal(row.embedding),
                }
                for row in rows
            ],
        )
        return len(rows)

    # 같은 source_type/title chunk 기존 row 삭제
    async def delete_existing_rows(self, rows: list[SecurityDocumentRow]) -> int:
        rows_by_source_type: dict[RagSourceType, set[str]] = defaultdict(set)
        for row in rows:
            rows_by_source_type[row.source_type].add(row.title)

        deleted_count = 0
        text, bindparam = _get_sqlalchemy_text_and_bindparam()
        query = text(
            """
            DELETE FROM public.security_documents
            WHERE source_type = CAST(:source_type AS reference_type_enum)
              AND title IN :titles
            """
        ).bindparams(bindparam("titles", expanding=True))

        for source_type, titles in rows_by_source_type.items():
            result = await self.session.execute(
                query,
                {
                    "source_type": source_type.value,
                    "titles": sorted(titles),
                },
            )
            deleted_count += result.rowcount or 0

        return deleted_count

    # pgvector 코사인 유사도 기반 검색
    async def search_by_vector(
        self,
        query_embedding: list[float],
        limit: int,
    ) -> list[SecurityDocumentSearchResult]:
        
        _validate_search_limit(limit)
        query = _get_sql_text()(
            """
            SELECT
                security_document_id,
                source_type::text AS source_type,
                title,
                content,
                url,
                embedding <=> CAST(:query_embedding AS vector) AS vector_distance
            FROM public.security_documents
            WHERE embedding IS NOT NULL
            ORDER BY embedding <=> CAST(:query_embedding AS vector)
            LIMIT :limit
            """
        )

        result = await self.session.execute(
            query,
            {
                "query_embedding": to_vector_literal(query_embedding),
                "limit": limit,
            },
        )

        return [
            _build_search_result(row)
            for row in result.mappings()
        ]

    # PostgreSQL FTS 기반 키워드 검색
    async def search_by_fts(
        self,
        query_text: str,
        limit: int,
    ) -> list[SecurityDocumentSearchResult]:
        _validate_search_limit(limit)
        fts_query_text = _build_fts_query_text(query_text)
        if not fts_query_text:
            return []

        query = _get_sql_text()(
            """
            WITH search_query AS (
                SELECT to_tsquery('english', :query_text) AS query
            )
            SELECT
                document.security_document_id,
                document.source_type::text AS source_type,
                document.title,
                document.content,
                document.url,
                ts_rank_cd(
                    to_tsvector(
                        'english',
                        coalesce(document.title, '') || ' ' || coalesce(document.content, '')
                    ),
                    search_query.query
                ) AS fts_rank
            FROM public.security_documents AS document
            CROSS JOIN search_query
            WHERE to_tsvector(
                    'english',
                    coalesce(document.title, '') || ' ' || coalesce(document.content, '')
                ) @@ search_query.query
            ORDER BY fts_rank DESC
            LIMIT :limit
            """
        )
        
        result = await self.session.execute(
            query,
            {
                "query_text": fts_query_text,
                "limit": limit,
            },
        )

        return [
            _build_search_result(row)
            for row in result.mappings()
        ]


# chunk와 embedding 결과를 DB row로 매핑
def build_security_document_rows(
    chunks: list[RagDocumentChunk],
    embedding_results: list[EmbeddingResult],
) -> list[SecurityDocumentRow]:
    if len(chunks) != len(embedding_results):
        raise VectorStoreError(
            f"Chunk and embedding count mismatch. chunks={len(chunks)} embeddings={len(embedding_results)}"
        )

    return [
        SecurityDocumentRow(
            source_type=chunk.source_type,
            title=_build_chunk_title(chunk),
            content=chunk.content,
            embedding=embedding_result.embedding,
            url=chunk.url,
        )
        for chunk, embedding_result in zip(chunks, embedding_results)
    ]


# chunk 위치를 title에 보존
def _build_chunk_title(chunk: RagDocumentChunk) -> str:
    return f"{chunk.title} [{chunk.source_id}#{chunk.chunk_index}]"


# DB 검색 row를 내부 결과 모델로 변환
def _build_search_result(row) -> SecurityDocumentSearchResult:
    return SecurityDocumentSearchResult(
        security_document_id=row["security_document_id"],
        source_type=RagSourceType(row["source_type"]),
        title=row["title"],
        content=row["content"],
        url=row["url"],
        vector_distance=row.get("vector_distance"),
        fts_rank=row.get("fts_rank"),
    )


# 검색 limit 검증
def _validate_search_limit(limit: int) -> None:
    if limit <= 0:
        raise VectorStoreError("Search limit must be positive")


# Finding 문장을 FTS 후보 검색용 OR prefix query로 변환
def _build_fts_query_text(query_text: str) -> str:
    tokens = _extract_fts_tokens(query_text)
    return " | ".join(f"{token}:*" for token in tokens)


# FTS에 넣을 의미 있는 토큰 추출
def _extract_fts_tokens(query_text: str) -> list[str]:
    seen: set[str] = set()
    tokens: list[str] = []

    for token in re.findall(r"[A-Za-z0-9]+", query_text.lower()):
        if token in FTS_STOP_WORDS:
            continue

        if len(token) < 2 and not token.isdigit():
            continue

        if token in seen:
            continue

        seen.add(token)
        tokens.append(token)

        if len(tokens) >= MAX_FTS_QUERY_TOKENS:
            break

    return tokens


# pgvector CAST 입력용 문자열 생성
def to_vector_literal(embedding: list[float]) -> str:
    if not embedding:
        raise VectorStoreError("Embedding vector must not be empty")

    return "[" + ",".join(_format_vector_number(value) for value in embedding) + "]"


# vector literal 숫자 포맷 정규화
def _format_vector_number(value: float) -> str:
    return format(float(value), ".10g")


# SQLAlchemy text 지연 로딩
def _get_sql_text():
    try:
        from sqlalchemy import text
    except ImportError as exc:
        raise VectorStoreError("sqlalchemy package is required for vector store") from exc

    return text


# SQLAlchemy text/bindparam 지연 로딩
def _get_sqlalchemy_text_and_bindparam():
    try:
        from sqlalchemy import bindparam, text
    except ImportError as exc:
        raise VectorStoreError("sqlalchemy package is required for vector store") from exc

    return text, bindparam


MAX_FTS_QUERY_TOKENS = 24
FTS_STOP_WORDS = {
    "a",
    "an",
    "and",
    "are",
    "as",
    "at",
    "be",
    "by",
    "for",
    "from",
    "in",
    "is",
    "it",
    "of",
    "on",
    "or",
    "that",
    "the",
    "to",
    "used",
    "user",
    "with",
}
