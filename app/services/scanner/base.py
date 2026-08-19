import logging
from abc import ABC
from typing import Any, Protocol

from pydantic import ConfigDict, Field

from app.schemas.base import CamelModel, to_camel
from app.schemas.finding import FindingSeverity, FindingTool
from app.schemas.pipeline import AnalysisJobContext

logger = logging.getLogger(__name__)


class AnalyzerContext(CamelModel):
    analysis_id: int
    repository_id: int
    branch: str

    @classmethod
    def from_pipeline_context(cls, context: AnalysisJobContext) -> "AnalyzerContext":
        return cls(
            analysis_id=context.analysis_id,
            repository_id=context.repository_id,
            branch=context.branch,
        )


class RawFinding(CamelModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=True,
    )

    tool: FindingTool
    type: str
    severity: FindingSeverity
    file_path: str
    message: str
    rule_id: str | None = None
    cwe_id: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    evidence: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AnalyzerError(RuntimeError):
    pass


class AnalyzerRunner(Protocol):
    tool: FindingTool

    def run(self, repo_path: str, context: AnalyzerContext) -> list[RawFinding]:
        ...


class StubAnalyzerRunner(ABC):
    tool: FindingTool

    def run(self, repo_path: str, context: AnalyzerContext) -> list[RawFinding]:
        logger.info(
            "Analyzer stub started. tool=%s analysis_id=%s repository_id=%s branch=%s repo_path=%s",
            self.tool.value,
            context.analysis_id,
            context.repository_id,
            context.branch,
            repo_path,
        )

        findings = self.collect_findings(repo_path, context)

        logger.info(
            "Analyzer stub completed. tool=%s analysis_id=%s finding_count=%s",
            self.tool.value,
            context.analysis_id,
            len(findings),
        )
        return findings

    def collect_findings(
        self,
        _repo_path: str,
        _context: AnalyzerContext,
    ) -> list[RawFinding]:
        return []
