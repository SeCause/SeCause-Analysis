import argparse
from collections import Counter
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.services.rag.chunker import chunk_documents
from app.services.rag.document_loader import load_cwe_documents, load_owasp_documents
from app.services.rag.documents import RagSourceDocument


# raw 문서 로딩 및 chunk 결과 미리보기
def main() -> None:
    args = parse_args()
    raw_root = args.raw_root
    documents = load_documents(raw_root, args.source)

    if args.limit_docs is not None:
        documents = documents[: args.limit_docs]

    chunks = chunk_documents(
        documents,
        max_chars=args.max_chars,
        overlap_chars=args.overlap_chars,
    )

    document_counts = Counter(document.source_type.value for document in documents)
    chunk_counts = Counter(chunk.source_type.value for chunk in chunks)

    print(f"documents={len(documents)} chunks={len(chunks)}")
    print(f"documents_by_source={dict(document_counts)}")
    print(f"chunks_by_source={dict(chunk_counts)}")

    for chunk in chunks[: args.samples]:
        preview = chunk.content.replace("\n", " ")[: args.preview_chars]
        print(
            "\n"
            f"[{chunk.source_type.value}] {chunk.source_id} "
            f"chunk={chunk.chunk_index} title={chunk.title}\n"
            f"{preview}"
        )


# CLI 옵션 정의
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Preview RAG source documents and generated chunks.",
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
        help="Document source to load.",
    )
    parser.add_argument("--limit-docs", type=int, default=None)
    parser.add_argument("--max-chars", type=int, default=4000)
    parser.add_argument("--overlap-chars", type=int, default=300)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--preview-chars", type=int, default=500)
    return parser.parse_args()


# source 옵션에 맞는 문서 로딩
def load_documents(raw_root: Path, source: str) -> list[RagSourceDocument]:
    documents: list[RagSourceDocument] = []

    if source in {"all", "owasp"}:
        documents.extend(load_owasp_documents(raw_root / "owasp"))

    if source in {"all", "cwe"}:
        documents.extend(load_cwe_documents(raw_root / "cwe" / "cwe.xml"))

    return documents


if __name__ == "__main__":
    main()
