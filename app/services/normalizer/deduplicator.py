from app.schemas.finding import Finding, FindingSeverity, FindingTool

DeduplicationKey = tuple[str, str, int | None]
UNKNOWN_FILE_PATH = "unknown"
UNIQUE_KEY_PREFIX = "__unique__"

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
        key = _build_deduplication_key(finding)
        current = deduplicated.get(key)
        if current is None or _should_replace_finding(current, finding):
            deduplicated[key] = finding

    return list(deduplicated.values())


# 취약점 식별값, file path, 시작 라인을 기준으로 중복 판단 key 생성
def _build_deduplication_key(finding: Finding) -> DeduplicationKey:
    if not _is_deduplicable(finding):
        return (UNIQUE_KEY_PREFIX, str(id(finding)), None)

    return (
        _vulnerability_identity(finding),
        _normalize_file_path(finding.file_path),
        finding.line_start,
    )


# 후보 finding이 기존 finding보다 보존할 가치가 높은지 판단
def _should_replace_finding(current: Finding, candidate: Finding) -> bool:
    current_rank = _severity_rank(current.severity)
    candidate_rank = _severity_rank(candidate.severity)

    if candidate_rank != current_rank:
        return candidate_rank > current_rank

    current_evidence_length = _evidence_length(current)
    candidate_evidence_length = _evidence_length(candidate)
    if candidate_evidence_length != current_evidence_length:
        return candidate_evidence_length > current_evidence_length

    return _tool_rank(candidate.tool) > _tool_rank(current.tool)


# 파일과 시작 라인이 명확할 때만 중복 병합 대상으로 취급
def _is_deduplicable(finding: Finding) -> bool:
    file_path = _normalize_file_path(finding.file_path)
    return bool(file_path) and file_path != UNKNOWN_FILE_PATH and finding.line_start is not None


# CWE가 있으면 CWE를, 없으면 type을 취약점 식별값으로 사용
def _vulnerability_identity(finding: Finding) -> str:
    return _normalize_identity_part(finding.cwe_id) or _normalize_identity_part(finding.type)


# file path는 case-sensitive 파일 시스템을 고려해 대소문자를 유지
def _normalize_file_path(file_path: str) -> str:
    return str(file_path or "").strip()


# 취약점 식별값 비교용 문자열을 trim/lowercase 형태로 정규화
def _normalize_identity_part(value: str | None) -> str:
    return str(value or "").strip().lower()


# severity enum/string 값을 비교 가능한 우선순위 숫자로 변환
def _severity_rank(severity: FindingSeverity | str) -> int:
    try:
        return SEVERITY_RANK[FindingSeverity(severity)]
    except (TypeError, ValueError):
        return 0


# analyzer tool enum/string 값을 비교 가능한 우선순위 숫자로 변환
def _tool_rank(tool: FindingTool | str) -> int:
    try:
        return TOOL_RANK[FindingTool(tool)]
    except (TypeError, ValueError):
        return 0


# evidence가 풍부한 finding을 고르기 위해 evidence 길이 계산
def _evidence_length(finding: Finding) -> int:
    return len(finding.evidence or "")
