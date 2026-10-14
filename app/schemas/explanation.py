import logging

from pydantic import Field, ValidationError, field_validator

from app.schemas.base import CamelModel

logger = logging.getLogger(__name__)


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

    @field_validator("fix_examples", mode="before")
    @classmethod
    def discard_malformed_examples(cls, value):
        # Invalid optional code must not discard an otherwise valid explanation.
        if not isinstance(value, list):
            logger.warning("Omitting malformed fixExamples array")
            return []
        examples = []
        for item in value:
            try:
                examples.append(FixExample.model_validate(item))
            except ValidationError:
                logger.warning("Omitting malformed fix example")
        return examples
