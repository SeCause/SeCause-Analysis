import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas.finding import Finding, FindingSeverity, FindingTool
from app.services.rag.hybrid_search import search_evidence_for_finding
from app.services.rag.query_builder import build_rag_query


# RAG 검색 smoke test 실행
def main() -> None:
    args = parse_args()
    finding = build_finding(args)
    query = build_rag_query(finding)

    print(f"query_text={query.query_text}")
    results = search_evidence_for_finding(finding)
    print(f"result_count={len(results)}")

    for index, result in enumerate(results, start=1):
        preview = result.content.replace("\n", " ")[: args.preview_chars]
        print(
            "\n"
            f"[{index}] score={result.score:.6f} source={result.source}\n"
            f"title={result.title}\n"
            f"url={result.url}\n"
            f"{preview}"
        )


# CLI 옵션 정의
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a smoke test for RAG hybrid search.",
    )
    parser.add_argument("--type", default="SQL_INJECTION")
    parser.add_argument("--cwe-id", default="CWE-89")
    parser.add_argument("--severity", choices=[item.value for item in FindingSeverity], default="HIGH")
    parser.add_argument("--file-path", default="src/main/java/UserController.java")
    parser.add_argument(
        "--message",
        default="User input is used directly in SQL query.",
    )
    parser.add_argument(
        "--evidence",
        default="Statement.executeQuery(query)",
    )
    parser.add_argument("--preview-chars", type=int, default=500)
    return parser.parse_args()


# CLI 입력으로 샘플 finding 생성
def build_finding(args: argparse.Namespace) -> Finding:
    return Finding(
        tool=FindingTool.SEMGREP,
        type=args.type,
        cwe_id=args.cwe_id,
        severity=FindingSeverity(args.severity),
        file_path=args.file_path,
        line_start=1,
        message=args.message,
        evidence=args.evidence,
    )


if __name__ == "__main__":
    main()
