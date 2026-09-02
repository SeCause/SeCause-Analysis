from app.schemas.finding import Finding
from app.services.rag.hybrid_search import EvidenceDocument


# Finding과 evidence 문서를 LLM 설명 생성용 prompt 문자열로 구성
def build_explanation_prompt(
    finding: Finding,
    evidence_documents: list[EvidenceDocument],
) -> str:
    from app.core.config import settings

    evidence_summary = build_evidence_context(
        evidence_documents=evidence_documents,
        max_documents=settings.LLM_EVIDENCE_TOP_K,
        max_chars_per_document=settings.LLM_MAX_EVIDENCE_CHARS,
        max_total_chars=settings.LLM_MAX_TOTAL_EVIDENCE_CHARS,
    )

    return (
        "You are a security analysis assistant.\n"
        "Analyze the finding using the provided evidence documents.\n"
        "Write all user-facing explanation values in Korean.\n"
        "Keep JSON keys in English camelCase exactly as specified.\n"
        "Keep code, file paths, identifiers, CWE IDs, and security terms unchanged when translation may reduce clarity.\n"
        "Include at least one fixExamples item whenever the vulnerable pattern can be inferred.\n"
        "Return only valid JSON matching this schema:\n"
        "{\n"
        '  "summary": "취약점 요약 한 문장",\n'
        '  "rootCause": "취약점이 발생한 원인",\n'
        '  "impact": "가능한 보안 영향",\n'
        '  "recommendation": "실무적인 수정 방향",\n'
        '  "fixExamples": [\n'
        "    {\n"
        '      "language": "언어 이름 또는 null",\n'
        '      "vulnerableCode": "취약한 코드 예시 또는 null",\n'
        '      "fixedCode": "안전한 코드 예시",\n'
        '      "explanation": "수정 코드가 안전한 이유"\n'
        "    }\n"
        "  ]\n"
        "}\n\n"
        "[Finding]\n"
        f"Finding type: {finding.type}\n"
        f"CWE: {finding.cwe_id or 'N/A'}\n"
        f"Severity: {finding.severity}\n"
        f"Tool: {finding.tool}\n"
        f"Location: {format_finding_location(finding)}\n"
        f"Message: {finding.message}\n"
        f"Code evidence: {finding.evidence or 'N/A'}\n\n"
        "[Reference Evidence]\n"
        f"{evidence_summary}"
    )


# evidence 문서 개수와 길이 제한
def build_evidence_context(
    evidence_documents: list[EvidenceDocument],
    max_documents: int,
    max_chars_per_document: int,
    max_total_chars: int,
) -> str:
    if max_documents <= 0 or max_chars_per_document <= 0 or max_total_chars <= 0:
        return "- No external evidence documents were included."

    total_chars = 0
    lines: list[str] = []

    for index, document in enumerate(evidence_documents[:max_documents], start=1):
        content = truncate_text(document.content, max_chars_per_document)
        entry = (
            f"{index}. Title: {document.title}\n"
            f"   Source: {document.source}\n"
            f"   URL: {document.url or 'N/A'}\n"
            f"   Score: {document.score:.6f}\n"
            f"   Content: {content}"
        )

        remaining_chars = max_total_chars - total_chars
        if remaining_chars <= 0:
            break

        entry = truncate_text(entry, remaining_chars)
        lines.append(entry)
        total_chars += len(entry)

    if not lines:
        return "- No external evidence documents were found."

    return "\n\n".join(lines)


# 긴 텍스트를 지정 길이로 절단
def truncate_text(value: str, max_chars: int) -> str:
    normalized_value = " ".join(value.split())
    if len(normalized_value) <= max_chars:
        return normalized_value

    if max_chars <= len(TRUNCATION_SUFFIX):
        return normalized_value[:max_chars]

    return normalized_value[: max_chars - len(TRUNCATION_SUFFIX)].rstrip() + TRUNCATION_SUFFIX


# 파일 위치 문자열 생성
def format_finding_location(finding: Finding) -> str:
    line_start = finding.line_start or "N/A"
    if finding.line_end is None or finding.line_end == finding.line_start:
        return f"{finding.file_path}:{line_start}"

    return f"{finding.file_path}:{line_start}-{finding.line_end}"


TRUNCATION_SUFFIX = "... [truncated]"
