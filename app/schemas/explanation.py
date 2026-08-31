from pydantic import Field

from app.schemas.base import CamelModel


class ReferenceDocument(CamelModel):
    title: str
    url: str | None = None


class FixExample(CamelModel):
    language: str | None = None
    vulnerable_code: str | None = None
    fixed_code: str
    explanation: str


class ExplanationResult(CamelModel):
    summary: str
    root_cause: str
    impact: str
    recommendation: str
    fix_examples: list[FixExample] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    reference_documents: list[ReferenceDocument] = Field(default_factory=list)
