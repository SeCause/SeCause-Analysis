from enum import Enum
from typing import Optional

from pydantic import ConfigDict, Field

from app.schemas.base import CamelModel, to_camel
from app.schemas.explanation import FixExample, ReferenceDocument


class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingTool(str, Enum):
    SEMGREP = "SEMGREP"
    CODEQL = "CODEQL"
    INFRA = "INFRA"


class Finding(CamelModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        use_enum_values=True,
    )

    tool: FindingTool
    type: str
    cwe_id: Optional[str] = None
    severity: FindingSeverity
    file_path: str
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    message: str
    evidence: Optional[str] = None
    summary: Optional[str] = None
    root_cause: Optional[str] = None
    impact: Optional[str] = None
    recommendation: Optional[str] = None
    fix_examples: list[FixExample] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    reference_documents: list[ReferenceDocument] = Field(default_factory=list)
