from pydantic import Field

from app.schemas.base import CamelModel


class CodeDetails(CamelModel):
    file_count: int = Field(default=0, ge=0)
    line_count: int = Field(default=0, ge=0)
    languages: list[str] = Field(default_factory=list)
