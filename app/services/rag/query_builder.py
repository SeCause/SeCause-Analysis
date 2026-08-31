from pathlib import PurePath
import re

from app.schemas.base import CamelModel
from app.schemas.finding import Finding


class RagQuery(CamelModel):
    cwe_id: str | None
    vulnerability_type: str
    severity: str
    language: str | None
    keywords: list[str]
    query_text: str


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

    return RagQuery(
        cwe_id=finding.cwe_id,
        vulnerability_type=finding.type,
        severity=str(finding.severity),
        language=language,
        keywords=keywords,
        query_text=query_text,
    )


# Finding 정보를 유사도/FTS 검색용 문자열로 구성
def build_rag_query_text(
    finding: Finding,
    keywords: list[str],
    language: str | None,
) -> str:
    file_name = PurePath(finding.file_path).name
    parts = [
        *keywords,
        normalize_vulnerability_type(finding.type),
        language,
        file_name,
        finding.message,
        finding.evidence,
    ]

    return normalize_query_text(" ".join(str(part) for part in parts if part))


# 취약점 유형 토큰 정리
def normalize_vulnerability_type(value: str) -> str:
    return value.replace("_", " ").replace("-", " ")


# 검색 문자열 공백 정규화
def normalize_query_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


# 파일 확장자를 기반으로 취약점이 발생한 언어/파일 타입을 추정
def infer_language(file_path: str) -> str | None:
    file_name = PurePath(file_path).name
    extension = (
        file_name.rsplit(".", 1)[-1].lower()
        if "." in file_name
        else file_name.lower()
    )
    return LANGUAGE_BY_EXTENSION.get(extension)


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
