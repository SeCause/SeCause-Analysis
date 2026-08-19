from typing import Any, Optional

from pydantic import AliasChoices, Field

from app.schemas.base import AnalysisTargetPayload
from app.schemas.finding import Finding


class AnalysisJobContext(AnalysisTargetPayload):
    github_token_reference: str = Field(
        repr=False,
        validation_alias=AliasChoices("githubTokenReference", "github_token_reference"),
        serialization_alias="githubTokenReference",
    )
    repo_path: Optional[str] = None
    raw_findings: list[dict[str, Any]] = Field(default_factory=list)
    normalized_findings: list[Finding] = Field(default_factory=list)
    enriched_findings: list[Finding] = Field(default_factory=list)

    @classmethod
    def from_job_payload(cls, payload: dict[str, Any]) -> "AnalysisJobContext":
        return cls.model_validate(payload)
