from pathlib import PurePath

from app.schemas.base import CamelModel
from app.schemas.finding import Finding


class RagQuery(CamelModel):
    cwe_id: str | None
    vulnerability_type: str
    severity: str
    language: str | None
    keywords: list[str]


# Finding의 핵심 속성을 RAG 검색에 사용할 query 객체로 변환
def build_rag_query(finding: Finding) -> RagQuery:
    keywords = [
        keyword
        for keyword in [
            finding.cwe_id,
            finding.type,
            finding.severity,
            infer_language(finding.file_path),
        ]
        if keyword
    ]

    return RagQuery(
        cwe_id=finding.cwe_id,
        vulnerability_type=finding.type,
        severity=str(finding.severity),
        language=infer_language(finding.file_path),
        keywords=keywords,
    )


# 파일 확장자를 기반으로 취약점이 발생한 언어/파일 타입을 추정
def infer_language(file_path: str) -> str | None:
    file_name = PurePath(file_path).name
    extension = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else file_name.lower()
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
