"""분석 파이프라인의 관측 가능한 동작을 덤프해 리팩토링 전후를 비교한다.

외부 서비스를 쓰지 않는다. 스캐너, RAG, LLM, Spring 콜백을 모두 가짜 객체로 바꾸고
여섯 시나리오를 실행한 뒤 진행률 전송 순서, 콜백 페이로드, 정리 순서, 작업 반환값을
JSON 으로 출력한다.

사용법.

    export DATABASE_URL="postgresql+asyncpg://postgres:postgres@localhost:5432/secause"
    export CLAUDE_API_KEY="test-key"
    export REDIS_URL="redis://localhost:6379/0"

    PYTHONPATH=. python scripts/compare_pipeline_behavior.py > after.json
    git stash && PYTHONPATH=. python scripts/compare_pipeline_behavior.py > before.json && git stash pop
    diff before.json after.json

출력이 같으면 두 리비전의 관측 가능한 동작이 같다. 트레이스백 프레임과
LogRecord.funcName 은 비교 대상이 아니다.
"""
import json
import sys
from contextlib import ExitStack
from unittest.mock import Mock, patch

from app.jobs.analysis_job import run_analysis_job
from app.schemas.code_details import CodeDetails
from app.schemas.finding import FindingSeverity, FindingTool
from app.services.scanner.base import AnalyzerError, RawFinding

PAYLOAD = {
    "analysis_id": 11,
    "repository_id": 22,
    "repository_url": "https://github.com/example/repository.git",
    "branch": "main",
    "github_token_reference": "token-reference",
}


def raw(finding_type, line_start, path="src/example.py"):
    return RawFinding(
        tool=FindingTool.SEMGREP, type=finding_type, severity=FindingSeverity.HIGH,
        file_path=path, message="example finding", line_start=line_start,
    )


def scenario(name, runner_results, enrich_error=False):
    callback = Mock()
    order = []
    with ExitStack() as stack:
        stack.enter_context(patch("app.jobs.analysis_job.SpringCallbackClient", return_value=callback))
        stack.enter_context(patch("app.jobs.analysis_job.resolve_github_token_reference", return_value="token"))
        stack.enter_context(patch("app.jobs.analysis_job.shallow_clone_repository", return_value="/tmp/repository"))
        stack.enter_context(patch("app.jobs.analysis_job.collect_code_details",
                                  return_value=CodeDetails(file_count=42, line_count=1000, languages=["Python"])))
        stack.enter_context(patch("app.jobs.analysis_job.cleanup_repository",
                                  side_effect=lambda *_: order.append("cleanup_repository")))
        stack.enter_context(patch("app.jobs.analysis_job.delete_github_token_reference",
                                  side_effect=lambda *_: order.append("delete_token")))
        runners = []
        for tool, result in runner_results:
            runner = Mock(tool=tool)
            if isinstance(result, Exception):
                runner.run.side_effect = result
            else:
                runner.run.return_value = result
            runners.append(runner)
        stack.enter_context(patch("app.jobs.analysis_job.get_analyzer_runners", return_value=runners))
        stack.enter_context(patch("app.jobs.analysis_job.search_evidence_for_findings",
                                  side_effect=lambda findings, **kw: [[] for _ in findings]))
        if enrich_error:
            stack.enter_context(patch("app.jobs.analysis_job.enrich_finding_with_explanation",
                                      side_effect=RuntimeError("llm down")))
        else:
            stack.enter_context(patch("app.jobs.analysis_job.enrich_finding_with_explanation",
                                      side_effect=lambda finding, _, **kw: finding))
        try:
            result = run_analysis_job(PAYLOAD)
            error = None
        except Exception as exc:
            result = None
            error = f"{type(exc).__name__}: {exc}"

    sent = []
    for call in callback.method_calls:
        if call[0] == "send_progress":
            sent.append(["progress", *list(call[1])])
        else:
            arg = call[1][0] if call[1] else None
            body = arg.model_dump(mode="json", by_alias=True) if hasattr(arg, "model_dump") else arg
            sent.append([call[0], body])
    return {"scenario": name, "result": result, "error": error, "cleanup_order": order, "callback_calls": sent}


def main():
    scenarios = [
        scenario("empty", [(FindingTool.SEMGREP, [])]),
        scenario("two_findings", [(FindingTool.SEMGREP, [raw("FIRST", 10), raw("SECOND", 20)])]),
        scenario("one_scanner_failed", [(FindingTool.SEMGREP, [raw("FIRST", 10)]),
                                        (FindingTool.CODEQL, AnalyzerError("codeql missing"))]),
        scenario("all_scanners_failed", [(FindingTool.SEMGREP, AnalyzerError("semgrep missing"))]),
        scenario("duplicate_paths", [(FindingTool.SEMGREP, [raw("FIRST", 10), raw("FIRST", 10),
                                                            raw("OUTSIDE", 10, "/tmp/outside.py")])]),
        scenario("llm_failure", [(FindingTool.SEMGREP, [raw("FIRST", 10)])], enrich_error=True),
    ]
    json.dump(scenarios, sys.stdout, ensure_ascii=False, indent=2, sort_keys=True)
    print()


if __name__ == "__main__":
    main()
