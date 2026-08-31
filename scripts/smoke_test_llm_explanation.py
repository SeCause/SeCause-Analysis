import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas.finding import Finding, FindingSeverity, FindingTool
from app.services.llm.explanation_generator import (
    build_fallback_explanation,
    enrich_finding_with_explanation,
)
from app.services.llm.prompt_builder import build_explanation_prompt
from app.services.rag.hybrid_search import EvidenceDocument, search_evidence_for_finding


# LLM 설명 생성 smoke test 실행
def main() -> None:
    args = parse_args()
    finding = build_finding(args)
    evidence_documents = load_evidence_documents(finding, args.use_rag)
    prompt = build_explanation_prompt(finding, evidence_documents)

    print(f"use_rag={args.use_rag}")
    print(f"call_claude={args.call_claude}")
    print(f"evidence_count={len(evidence_documents)}")
    print(f"prompt_chars={len(prompt)}")

    if args.print_prompt:
        print("\n[prompt]")
        print(prompt[: args.preview_chars])

    if args.call_claude:
        enriched_finding = enrich_finding_with_explanation(finding, evidence_documents)
    else:
        explanation = build_fallback_explanation(finding, evidence_documents)
        enriched_finding = finding.model_copy(
            update={
                "summary": explanation.summary,
                "root_cause": explanation.root_cause,
                "impact": explanation.impact,
                "recommendation": explanation.recommendation,
                "fix_examples": explanation.fix_examples,
                "references": explanation.references,
                "reference_documents": explanation.reference_documents,
            }
        )

    print("\n[result]")
    if args.json:
        print(json.dumps(enriched_finding.model_dump(by_alias=True), ensure_ascii=False, indent=2))
        return

    print(f"summary={enriched_finding.summary}")
    print(f"root_cause={enriched_finding.root_cause}")
    print(f"impact={enriched_finding.impact}")
    print(f"recommendation={enriched_finding.recommendation}")
    print(f"fix_examples={len(enriched_finding.fix_examples)}")
    print(f"references={len(enriched_finding.references)}")
    print(f"reference_documents={len(enriched_finding.reference_documents)}")


# CLI 옵션 정의
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a smoke test for LLM explanation generation.",
    )
    parser.add_argument("--type", default="SQL_INJECTION")
    parser.add_argument("--cwe-id", default="CWE-89")
    parser.add_argument("--severity", choices=[item.value for item in FindingSeverity], default="HIGH")
    parser.add_argument("--file-path", default="src/main/java/UserController.java")
    parser.add_argument("--line-start", type=int, default=42)
    parser.add_argument(
        "--message",
        default="User input is used directly in SQL query.",
    )
    parser.add_argument(
        "--evidence",
        default="Statement.executeQuery(query)",
    )
    parser.add_argument("--use-rag", action="store_true")
    parser.add_argument("--call-claude", action="store_true")
    parser.add_argument("--print-prompt", action="store_true")
    parser.add_argument("--preview-chars", type=int, default=2000)
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()


# CLI 입력으로 샘플 finding 생성
def build_finding(args: argparse.Namespace) -> Finding:
    return Finding(
        tool=FindingTool.SEMGREP,
        type=args.type,
        cwe_id=args.cwe_id,
        severity=FindingSeverity(args.severity),
        file_path=args.file_path,
        line_start=args.line_start,
        message=args.message,
        evidence=args.evidence,
    )


# 기본은 비용 없는 샘플 evidence, 옵션 사용 시 실제 RAG 검색 결과 사용
def load_evidence_documents(
    finding: Finding,
    use_rag: bool,
) -> list[EvidenceDocument]:
    if use_rag:
        return search_evidence_for_finding(finding)

    return [
        EvidenceDocument(
            title="SQL Injection Prevention Cheat Sheet",
            source="OWASP",
            url="https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.md",
            content=(
                "Prepared statements ensure that an attacker is not able to change "
                "the intent of a query, even if SQL commands are inserted by an attacker."
            ),
            score=0.9,
        ),
        EvidenceDocument(
            title="CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
            source="CWE",
            url="https://cwe.mitre.org/data/definitions/89.html",
            content=(
                "The product constructs all or part of an SQL command using externally-influenced "
                "input without neutralizing special elements that could modify the SQL command."
            ),
            score=0.8,
        ),
    ]


if __name__ == "__main__":
    main()
