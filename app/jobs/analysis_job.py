import logging
from typing import Any, Callable

from app.collector.git_collector import cleanup_repository, shallow_clone_repository
from app.jobs.secret_store import (
    delete_github_token_reference,
    resolve_github_token_reference,
)
from app.schemas.pipeline import AnalysisJobContext
from app.services.callback.spring_client import (
    AnalysisFailureCallbackPayload,
    AnalysisSuccessCallbackPayload,
    AnalysisSummary,
    SpringCallbackError,
    SpringCallbackClient,
)
from app.services.llm.explanation_generator import enrich_finding_with_explanation
from app.services.normalizer.deduplicator import deduplicate_findings
from app.services.normalizer.finding_normalizer import normalize_findings
from app.services.rag.hybrid_search import search_evidence_for_findings
from app.services.scanner.base import AnalyzerContext, AnalyzerRunner, RawFinding
from app.services.scanner.codeql_runner import CodeQLRunner
from app.services.scanner.semgrep_runner import SemgrepRunner

logger = logging.getLogger(__name__)
MAX_SCANNER_ERROR_SUMMARY_CHARS = 500

# 단계 기반 처리율이며 소요 시간의 비율/남은 시간 예측이 아니다.
# clone 10, scanner 40, 정규화/중복 제거 5, RAG 10, LLM 30.
# 마지막 5는 BE의 결과 저장에 예약한다. 성공은 BE가 100, 실패는 현재 값을 유지한다.
CLONE_PROGRESS = 10
SCANNER_WEIGHT = 40
NORMALIZE_PROGRESS = 55
RAG_WEIGHT = 10
RAG_PROGRESS = NORMALIZE_PROGRESS + RAG_WEIGHT
LLM_WEIGHT = 30
LLM_PROGRESS = RAG_PROGRESS + LLM_WEIGHT


class AnalysisProgressReporter:
    def __init__(self, client: SpringCallbackClient, analysis_id: int) -> None:
        self.client = client
        self.analysis_id = analysis_id
        self.last_progress = 0

    def report(self, progress: int, stage: str = "pipeline") -> None:
        # 같은 정수 진행률은 다시 전송하지 않아 finding 수가 커져도 호출 수를 제한한다.
        if not 0 <= progress < 100:
            raise ValueError("Intermediate progress must be between 0 and 99")
        if progress <= self.last_progress:
            return
        self.last_progress = progress
        try:
            self.client.send_progress(self.analysis_id, progress)
        except SpringCallbackError:
            logger.warning(
                "Spring progress callback failed; continuing analysis. analysis_id=%s stage=%s progress_percent=%s result=failed",
                self.analysis_id,
                stage,
                progress,
            )

        else:
            logger.info(
                "Spring progress callback completed. analysis_id=%s stage=%s progress_percent=%s result=sent",
                self.analysis_id, stage, progress,
            )


class AllAnalyzersFailedError(RuntimeError):
    pass


def run_analysis_job(payload: dict[str, Any]) -> dict[str, Any]:
    callback_client = SpringCallbackClient()
    context: AnalysisJobContext | None = None

    try:
        context = create_pipeline_context(payload)
        progress = AnalysisProgressReporter(callback_client, context.analysis_id)
        #토큰이 유효한지 검사
        github_token = resolve_github_token_reference(context.github_token_reference)

        logger.info(
            "Analysis pipeline started. analysis_id=%s repository_id=%s repository_url=%s branch=%s",
            context.analysis_id,
            context.repository_id,
            context.repository_url,
            context.branch,
        )

        # 분석기가 실제로 검사할 repository 경로 생성
        context.repo_path = str(
            shallow_clone_repository(
                context.repository_url,
                context.branch,
                github_token,
                context.analysis_id,
            )
        )

        #추후 runner 내부 조정 필요
        progress.report(CLONE_PROGRESS, "clone")
        raw_findings = run_analyzers(context, lambda value: progress.report(value, "scanner"))
        context.raw_findings = [finding.model_dump() for finding in raw_findings] #원본
        context.normalized_findings = normalize_findings(raw_findings, repo_root=context.repo_path) #정규화 후
        context.normalized_findings = deduplicate_findings(context.normalized_findings) #중복

        progress.report(NORMALIZE_PROGRESS, "normalize_deduplicate")
        evidence_by_finding = search_evidence_for_findings(
            context.normalized_findings,
            analysis_id=context.analysis_id,
            on_progress=lambda done, total: progress.report(
                NORMALIZE_PROGRESS + RAG_WEIGHT * done // total, "rag"
            ),
        )

        progress.report(RAG_PROGRESS, "rag")

        #LLM 설명 추가
        context.enriched_findings = []
        finding_total = len(context.normalized_findings)
        for finding_index, (finding, evidence_documents) in enumerate(
            zip(context.normalized_findings, evidence_by_finding),
            start=1,
        ):
            logger.info(
                "Finding enrichment started. analysis_id=%s finding_index=%s finding_total=%s tool=%s type=%s",
                context.analysis_id,
                finding_index,
                finding_total,
                finding.tool,
                finding.type,
            )
            enriched_finding = enrich_finding_with_explanation(
                finding,
                evidence_documents,
            )
            context.enriched_findings.append(enriched_finding)
            progress.report(RAG_PROGRESS + LLM_WEIGHT * finding_index // finding_total, "llm")
            logger.info(
                "Finding enrichment completed. analysis_id=%s finding_index=%s finding_total=%s",
                context.analysis_id,
                finding_index,
                finding_total,
            )

        success_payload = build_success_callback_payload(context)
        progress.report(LLM_PROGRESS, "llm")
        callback_client.send_success(success_payload)

        logger.info(
            "Analysis pipeline completed. analysis_id=%s finding_count=%s",
            context.analysis_id,
            len(context.enriched_findings),
        )

        return {
            "analysis_id": context.analysis_id,
            "repository_id": context.repository_id,
            "status": "COMPLETED",
            "finding_count": len(context.enriched_findings),
        }
    except Exception as exc:
        failure_payload = build_failure_callback_payload(context, payload, exc)
        if failure_payload.analysis_id is None:
            logger.exception(
                "Skipping Spring failure callback because analysis_id is missing"
            )
        else:
            try:
                callback_client.send_failure(failure_payload)
            except SpringCallbackError:
                logger.exception(
                    "Failed to send Spring failure callback. analysis_id=%s",
                    failure_payload.analysis_id,
                )
        raise
    finally:
        try:
            cleanup_repository(context.repo_path if context is not None else None)
        except Exception:
            logger.warning(
                "Failed to cleanup repository. analysis_id=%s",
                context.analysis_id if context is not None else payload.get("analysis_id"),
            )
        finally:
            cleanup_github_token_reference(context, payload)


# RQ payload를 worker 내부 pipeline context로 변환
def create_pipeline_context(payload: dict[str, Any]) -> AnalysisJobContext:
    return AnalysisJobContext.from_job_payload(payload)


# pipeline 종료 후 Redis에 임시 저장된 GitHub token reference를 정리
def cleanup_github_token_reference(
    context: AnalysisJobContext | None,
    payload: dict[str, Any],
) -> None:
    token_reference = (
        context.github_token_reference
        if context is not None
        else payload.get("github_token_reference") or payload.get("githubTokenReference")
    )

    if token_reference is None:
        return

    try:
        delete_github_token_reference(token_reference)
    except Exception:
        logger.warning(
            "Failed to delete GitHub token reference. analysis_id=%s",
            context.analysis_id if context is not None else payload.get("analysis_id"),
        )


# 등록된 analyzer runner stub을 순서대로 실행해 raw finding을 수집
def run_analyzers(
    context: AnalysisJobContext,
    report_progress: Callable[[int], None] | None = None,
) -> list[RawFinding]:
    analyzer_context = AnalyzerContext.from_pipeline_context(context)
    repo_path = context.repo_path or "repo-not-cloned"
    raw_findings: list[RawFinding] = []
    successful_scanner_count = 0

    runners = get_analyzer_runners()
    for runner_index, runner in enumerate(runners, start=1):
        logger.info(
            "Analysis stage started. stage=%s analysis_id=%s",
            runner.tool.value,
            context.analysis_id,
        )
        try:
            raw_findings.extend(runner.run(repo_path, analyzer_context))
            successful_scanner_count += 1
        except Exception as exc:
            error_summary = summarize_scanner_error(runner, exc)
            context.failed_scanners.append(error_summary)
            logger.warning(
                "Analysis stage failed; continuing with remaining scanners. stage=%s analysis_id=%s error_type=%s",
                runner.tool.value,
                context.analysis_id,
                exc.__class__.__name__,
            )
            continue
        finally:
            if report_progress is not None:
                report_progress(CLONE_PROGRESS + SCANNER_WEIGHT * runner_index // len(runners))
        logger.info(
            "Analysis stage completed. stage=%s analysis_id=%s",
            runner.tool.value,
            context.analysis_id,
        )

    if successful_scanner_count == 0:
        raise AllAnalyzersFailedError(
            "All scanners failed: " + "; ".join(context.failed_scanners)
        )

    return raw_findings


# callback에서 실패 스캐너와 원인을 식별할 수 있는 제한 길이 요약 생성
def summarize_scanner_error(runner: AnalyzerRunner, exc: Exception) -> str:
    detail = str(exc).strip() or "no error details"
    summary = f"{runner.tool.value}: {exc.__class__.__name__}: {detail}"
    return summary[:MAX_SCANNER_ERROR_SUMMARY_CHARS]


# pipeline에서 사용할 analyzer runner 목록을 제공
def get_analyzer_runners() -> list[AnalyzerRunner]:
    return [
        SemgrepRunner(),
        CodeQLRunner(),
    ]


# Spring 성공 callback에 전달할 payload 생성
def build_success_callback_payload(
    context: AnalysisJobContext,
) -> AnalysisSuccessCallbackPayload:
    return AnalysisSuccessCallbackPayload(
        analysis_id=context.analysis_id,
        repository_id=context.repository_id,
        findings=context.enriched_findings,
        summary=AnalysisSummary(total_count=len(context.enriched_findings)),
        failed_scanners=context.failed_scanners,
    )


# Spring 실패 callback에 전달할 payload 생성
def build_failure_callback_payload(
    context: AnalysisJobContext | None,
    payload: dict[str, Any],
    exc: Exception,
) -> AnalysisFailureCallbackPayload:
    return AnalysisFailureCallbackPayload(
        analysis_id=context.analysis_id if context else payload.get("analysis_id"),
        repository_id=context.repository_id if context else payload.get("repository_id"),
        error_code=exc.__class__.__name__,
        error_message=str(exc),
        failed_stage="CALLBACK" if isinstance(exc, SpringCallbackError) else "PIPELINE",
    )
