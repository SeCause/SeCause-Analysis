from dataclasses import dataclass

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


class SecurityDocumentVectorStore:
    def __init__(self, session) -> None:
        self.session = session

    # source_type 단위 기존 색인 삭제
    async def delete_by_source_type(self, source_type: RagSourceType) -> int:
        query = get_sql_text()(
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

        query = get_sql_text()(
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
            title=build_chunk_title(chunk),
            content=chunk.content,
            embedding=embedding_result.embedding,
            url=chunk.url,
        )
        for chunk, embedding_result in zip(chunks, embedding_results)
    ]


# chunk 위치를 title에 보존
def build_chunk_title(chunk: RagDocumentChunk) -> str:
    return f"{chunk.title} [{chunk.source_id}#{chunk.chunk_index}]"


# pgvector CAST 입력용 문자열 생성
def to_vector_literal(embedding: list[float]) -> str:
    if not embedding:
        raise VectorStoreError("Embedding vector must not be empty")

    return "[" + ",".join(format_vector_number(value) for value in embedding) + "]"


# vector literal 숫자 포맷 정규화
def format_vector_number(value: float) -> str:
    return format(float(value), ".10g")


# SQLAlchemy text 지연 로딩
def get_sql_text():
    try:
        from sqlalchemy import text
    except ImportError as exc:
        raise VectorStoreError("sqlalchemy package is required for vector store") from exc

    return text
