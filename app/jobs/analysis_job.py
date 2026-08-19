import logging
from typing import Any

from app.jobs.secret_store import resolve_github_token_reference
from app.schemas.pipeline import AnalysisJobContext

logger = logging.getLogger(__name__)


def run_analysis_job(payload: dict[str, Any]) -> dict[str, Any]:
    context = AnalysisJobContext.from_job_payload(payload)
    resolve_github_token_reference(context.github_token_reference)

    logger.info(
        "Analysis job started. analysis_id=%s repository_id=%s repository_url=%s branch=%s",
        context.analysis_id,
        context.repository_id,
        context.repository_url,
        context.branch,
    )

    return {
        "analysis_id": context.analysis_id,
        "repository_id": context.repository_id,
        "status": "QUEUED",
    }
