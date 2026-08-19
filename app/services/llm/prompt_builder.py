from app.schemas.finding import Finding
from app.services.rag.hybrid_search import EvidenceDocument


# Finding과 evidence 문서를 LLM 설명 생성용 prompt 문자열로 구성
def build_explanation_prompt(
    finding: Finding,
    evidence_documents: list[EvidenceDocument],
) -> str:
    evidence_summary = "\n".join(
        f"- {document.title}: {document.content}" for document in evidence_documents
    )
    if not evidence_summary:
        evidence_summary = "- No external evidence documents were found."

    return (
        "Explain the security finding and provide a concise remediation guide.\n"
        f"Finding type: {finding.type}\n"
        f"CWE: {finding.cwe_id or 'N/A'}\n"
        f"Severity: {finding.severity}\n"
        f"Location: {finding.file_path}:{finding.line_start or 'N/A'}\n"
        f"Message: {finding.message}\n"
        "Evidence:\n"
        f"{evidence_summary}"
    )
