from pathlib import PurePath
import re

from app.schemas.base import CamelModel
from app.schemas.finding import Finding
from app.services.rag.documents import RagSourceType


class RagQuery(CamelModel):
    cwe_id: str | None
    vulnerability_type: str
    severity: str
    language: str | None
    keywords: list[str]
    query_text: str
    source_types: list[RagSourceType]


# Finding의 핵심 속성을 RAG 검색에 사용할 query 객체로 변환
def build_rag_query(finding: Finding) -> RagQuery:
    language = infer_language(finding.file_path)
    keywords = [
        keyword
        for keyword in [
            finding.cwe_id,
            finding.type,
            finding.severity,
            language,
        ]
        if keyword
    ]
    query_text = build_rag_query_text(finding, keywords, language)
    source_types = infer_source_types(finding.cwe_id)

    return RagQuery(
        cwe_id=finding.cwe_id,
        vulnerability_type=finding.type,
        severity=str(finding.severity),
        language=language,
        keywords=keywords,
        query_text=query_text,
        source_types=source_types,
    )


# Finding 정보를 유사도/FTS 검색용 문자열로 구성
def build_rag_query_text(
    finding: Finding,
    keywords: list[str],
    language: str | None,
) -> str:
    file_name = redact_sensitive_text(PurePath(finding.file_path).name)
    parts = [
        *keywords,
        normalize_vulnerability_type(finding.type),
        language,
        file_name,
        redact_sensitive_text(finding.message),
        redact_sensitive_text(finding.evidence),
    ]

    return normalize_query_text(" ".join(str(part) for part in parts if part))


# 취약점 유형 토큰 정리
def normalize_vulnerability_type(value: str) -> str:
    return value.replace("_", " ").replace("-", " ")


# 검색 문자열 공백 정규화
def normalize_query_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


# 외부 embedding API로 전송하기 전 민감정보 마스킹
def redact_sensitive_text(value: str | None) -> str | None:
    if value is None:
        return None

    redacted_value = value
    for pattern in SECRET_PATTERNS:
        redacted_value = pattern.sub(REDACTED_SECRET, redacted_value)

    return redacted_value


# 파일 확장자를 기반으로 취약점이 발생한 언어/파일 타입을 추정
def infer_language(file_path: str) -> str | None:
    file_name = PurePath(file_path).name
    extension = (
        file_name.rsplit(".", 1)[-1].lower()
        if "." in file_name
        else file_name.lower()
    )
    return LANGUAGE_BY_EXTENSION.get(extension)


# CWE가 있으면 보안 기준 문서 중심으로 검색 범위 제한
def infer_source_types(cwe_id: str | None) -> list[RagSourceType]:
    if cwe_id:
        return [RagSourceType.CWE, RagSourceType.OWASP]

    return []


LANGUAGE_BY_EXTENSION = {
    "dockerfile": "Dockerfile",
    "go": "Go",
    "java": "Java",
    "js": "JavaScript",
    "jsx": "JavaScript",
    "kt": "Kotlin",
    "py": "Python",
    "rb": "Ruby",
    "tf": "Terraform",
    "ts": "TypeScript",
    "tsx": "TypeScript",
    "yaml": "YAML",
    "yml": "YAML",
}

REDACTED_SECRET = "[REDACTED_SECRET]"
SECRET_PATTERNS = [
    re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[a-z0-9._\-]+"),
    re.compile(r"(?i)\bbearer\s+[a-z0-9._\-]+"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(
        r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|authorization)\b"
        r"\s*[:=]\s*['\"]?[^'\"\s,;}]+"
    ),
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
]
