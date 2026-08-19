from app.schemas.finding import Finding, FindingSeverity

DeduplicationKey = tuple[str | None, str, str, int | None]

SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
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


# CWE, type, file path, 시작 라인을 기준으로 중복 판단 key 생성
def build_deduplication_key(finding: Finding) -> DeduplicationKey:
    return (
        finding.cwe_id,
        finding.type,
        finding.file_path,
        finding.line_start,
    )


# 후보 finding이 기존 finding보다 보존할 가치가 높은지 판단
def should_replace_finding(current: Finding, candidate: Finding) -> bool:
    current_rank = severity_rank(current.severity)
    candidate_rank = severity_rank(candidate.severity)

    if candidate_rank != current_rank:
        return candidate_rank > current_rank

    return evidence_length(candidate) > evidence_length(current)


# severity enum/string 값을 비교 가능한 우선순위 숫자로 변환
def severity_rank(severity: FindingSeverity | str) -> int:
    return SEVERITY_RANK[FindingSeverity(severity)]


# evidence가 풍부한 finding을 고르기 위해 evidence 길이 계산
def evidence_length(finding: Finding) -> int:
    return len(finding.evidence or "")
