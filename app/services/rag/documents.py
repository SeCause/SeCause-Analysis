from dataclasses import field, dataclass
from enum import Enum
from typing import Any


class RagSourceType(str, Enum):
    OWASP = "OWASP"
    CWE = "CWE"
    OTHER = "OTHER"


# 원본 문서 단위
@dataclass(frozen=True)
class RagSourceDocument:
    source_type: RagSourceType
    source_id: str
    title: str
    content: str
    url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


# 색인할 chunk 단위
@dataclass(frozen=True)
class RagDocumentChunk:
    source_type: RagSourceType
    source_id: str
    chunk_index: int
    title: str
    content: str
    url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
