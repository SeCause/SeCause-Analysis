import argparse
import asyncio
from collections import Counter
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.services.rag.chunker import chunk_documents
from app.services.rag.document_loader import load_cwe_documents, load_owasp_documents
from app.services.rag.documents import RagDocumentChunk, RagSourceDocument, RagSourceType

DEFAULT_INSERT_BATCH_SIZE = 200


# RAG 문서 색인 실행 진입점
def main() -> None:
    args = parse_args()
    documents = load_documents(args.raw_root, args.source)

    if args.limit_docs is not None:
        documents = documents[: args.limit_docs]

    chunks = chunk_documents(
        documents,
        max_chars=args.max_chars,
        overlap_chars=args.overlap_chars,
    )
    print_index_summary(documents, chunks)

    if args.dry_run:
        print("dry_run=true")
        return

    asyncio.run(index_chunks(chunks, args.reset_source, args.insert_batch_size))


# CLI 옵션 정의
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Index raw RAG source documents into security_documents.",
    )
    parser.add_argument(
        "--raw-root",
        type=Path,
        default=Path("rag_documents/raw"),
        help="Directory containing raw RAG source documents.",
    )
    parser.add_argument(
        "--source",
        choices=["all", "owasp", "cwe"],
        default="all",
        help="Document source to index.",
    )
    parser.add_argument("--limit-docs", type=int, default=None)
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--overlap-chars", type=int, default=300)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load and chunk documents without embedding or DB writes.",
    )
    parser.add_argument(
        "--reset-source",
        action="store_true",
        help="Delete existing rows for indexed source types before inserting.",
    )
    parser.add_argument(
        "--insert-batch-size",
        type=int,
        default=DEFAULT_INSERT_BATCH_SIZE,
        help="Number of rows to insert per DB batch.",
    )
    return parser.parse_args()


# source 옵션에 맞는 원본 문서 로딩
def load_documents(raw_root: Path, source: str) -> list[RagSourceDocument]:
    documents: list[RagSourceDocument] = []

    if source in {"all", "owasp"}:
        documents.extend(load_owasp_documents(raw_root / "owasp"))

    if source in {"all", "cwe"}:
        documents.extend(load_cwe_documents(raw_root / "cwe" / "cwe.xml"))

    return documents


# 색인 대상 통계 출력
def print_index_summary(
    documents: list[RagSourceDocument],
    chunks: list[RagDocumentChunk],
) -> None:
    document_counts = Counter(document.source_type.value for document in documents)
    chunk_counts = Counter(chunk.source_type.value for chunk in chunks)

    print(f"documents={len(documents)} chunks={len(chunks)}")
    print(f"documents_by_source={dict(document_counts)}")
    print(f"chunks_by_source={dict(chunk_counts)}")


# embedding 생성 및 DB 저장
async def index_chunks(
    chunks: list[RagDocumentChunk],
    reset_source: bool,
    insert_batch_size: int,
) -> None:
    if not chunks:
        print("No chunks to index.")
        return

    if insert_batch_size <= 0:
        raise ValueError("--insert-batch-size must be positive")

    from app.core.database import AsyncSessionLocal
    from app.services.rag.embedder import OpenAIEmbedder
    from app.services.rag.vector_store import (
        SecurityDocumentVectorStore,
        build_security_document_rows,
    )

    embedder = OpenAIEmbedder()
    embedding_results = embedder.embed_documents([chunk.content for chunk in chunks])
    rows = build_security_document_rows(chunks, embedding_results)

    async with AsyncSessionLocal() as session:
        async with session.begin():
            store = SecurityDocumentVectorStore(session)

            if reset_source:
                for source_type in sorted(
                    {chunk.source_type for chunk in chunks},
                    key=lambda value: value.value,
                ):
                    deleted_count = await store.delete_by_source_type(source_type)
                    print(f"deleted source_type={source_type.value} rows={deleted_count}")

            inserted_count = 0
            for batch in batch_rows(rows, insert_batch_size):
                inserted_count += await store.insert_rows(batch)
                print(f"inserted={inserted_count}/{len(rows)}")

    print(f"completed rows={len(rows)}")


# DB insert batch 분할
def batch_rows(values: list, batch_size: int) -> list[list]:
    return [
        values[index : index + batch_size]
        for index in range(0, len(values), batch_size)
    ]


if __name__ == "__main__":
    main()
