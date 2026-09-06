from app.schemas.finding import Finding, FindingSeverity, FindingTool

DeduplicationKey = tuple[str, str, int | None]

SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}

TOOL_RANK = {
    FindingTool.INFRA: 0,
    FindingTool.SEMGREP: 1,
    FindingTool.CODEQL: 2,
}


# 공통 Finding 목록에서 동일 key를 가진 중복 finding을 제거
def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    deduplicated: dict[DeduplicationKey, Finding] = {}

    for finding in findings:
        key = build_deduplication_key(finding)
        current = deduplicated.get(key)
        if current is None or should_replace_finding(current, finding):
            deduplicated[key] = finding

    return list(deduplicated.values())


# 취약점 식별값, file path, 시작 라인을 기준으로 중복 판단 key 생성
def build_deduplication_key(finding: Finding) -> DeduplicationKey:
    return (
        vulnerability_identity(finding),
        normalize_file_path(finding.file_path),
        finding.line_start,
    )


# 후보 finding이 기존 finding보다 보존할 가치가 높은지 판단
def should_replace_finding(current: Finding, candidate: Finding) -> bool:
    current_rank = severity_rank(current.severity)
    candidate_rank = severity_rank(candidate.severity)

    if candidate_rank != current_rank:
        return candidate_rank > current_rank

    current_evidence_length = evidence_length(current)
    candidate_evidence_length = evidence_length(candidate)
    if candidate_evidence_length != current_evidence_length:
        return candidate_evidence_length > current_evidence_length

    return tool_rank(candidate.tool) > tool_rank(current.tool)


# CWE가 있으면 CWE를, 없으면 type을 취약점 식별값으로 사용
def vulnerability_identity(finding: Finding) -> str:
    return normalize_key_part(finding.cwe_id) or normalize_key_part(finding.type)


# file path 중복 비교용 문자열을 생성
def normalize_file_path(file_path: str) -> str:
    return normalize_key_part(file_path)


# 중복 비교용 문자열을 trim/lowercase 형태로 정규화
def normalize_key_part(value: str | None) -> str:
    return str(value or "").strip().lower()


# severity enum/string 값을 비교 가능한 우선순위 숫자로 변환
def severity_rank(severity: FindingSeverity | str) -> int:
    try:
        return SEVERITY_RANK[FindingSeverity(severity)]
    except ValueError:
        return 0


# analyzer tool enum/string 값을 비교 가능한 우선순위 숫자로 변환
def tool_rank(tool: FindingTool | str) -> int:
    try:
        return TOOL_RANK[FindingTool(tool)]
    except ValueError:
        return 0


# evidence가 풍부한 finding을 고르기 위해 evidence 길이 계산
def evidence_length(finding: Finding) -> int:
    return len(finding.evidence or "")
