import logging
from typing import Any

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


class AllAnalyzersFailedError(RuntimeError):
    pass


def run_analysis_job(payload: dict[str, Any]) -> dict[str, Any]:
    callback_client = SpringCallbackClient()
    context: AnalysisJobContext | None = None

    try:
        context = create_pipeline_context(payload)
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
        raw_findings = run_analyzers(context)
        context.raw_findings = [finding.model_dump() for finding in raw_findings] #원본
        context.normalized_findings = normalize_findings(raw_findings) #정규화 후
        context.normalized_findings = deduplicate_findings(context.normalized_findings) #중복

        evidence_by_finding = search_evidence_for_findings(
            context.normalized_findings,
            analysis_id=context.analysis_id,
        )

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
            logger.info(
                "Finding enrichment completed. analysis_id=%s finding_index=%s finding_total=%s",
                context.analysis_id,
                finding_index,
                finding_total,
            )

        success_payload = build_success_callback_payload(context)
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
def run_analyzers(context: AnalysisJobContext) -> list[RawFinding]:
    analyzer_context = AnalyzerContext.from_pipeline_context(context)
    repo_path = context.repo_path or "repo-not-cloned"
    raw_findings: list[RawFinding] = []
    successful_scanner_count = 0

    for runner in get_analyzer_runners():
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
