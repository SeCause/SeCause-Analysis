from collections.abc import Iterable

from app.schemas.finding import Finding, FindingSeverity, FindingTool
from app.services.scanner.base import RawFinding

DEFAULT_FINDING_TYPE_SUFFIX = "FINDING"
DEFAULT_MESSAGE = "Security finding detected"


class UnknownFindingToolError(ValueError):
    pass


# 여러 analyzer raw finding을 공통 Finding 목록으로 변환
def normalize_findings(raw_findings: Iterable[RawFinding]) -> list[Finding]:
    return [normalize_finding(raw_finding) for raw_finding in raw_findings]


# raw finding의 tool에 맞는 normalizer를 선택해 공통 Finding으로 변환
def normalize_finding(raw_finding: RawFinding) -> Finding:
    try:
        tool = normalize_tool(raw_finding.tool)
        normalizer = FINDING_NORMALIZERS[tool]
    except ValueError as exc:
        raise UnknownFindingToolError(f"Unsupported finding tool: {raw_finding.tool}") from exc

    return normalizer(raw_finding, tool)


# Semgrep raw finding을 공통 Finding으로 변환
def normalize_semgrep_finding(raw_finding: RawFinding, tool: FindingTool) -> Finding:
    return build_finding(raw_finding, tool)


# CodeQL raw finding을 공통 Finding으로 변환
def normalize_codeql_finding(raw_finding: RawFinding, tool: FindingTool) -> Finding:
    return build_finding(raw_finding, tool)


# Infra raw finding을 공통 Finding으로 변환
def normalize_infra_finding(raw_finding: RawFinding, tool: FindingTool) -> Finding:
    return build_finding(raw_finding, tool)


# 도구별 raw finding의 공통 필드를 Finding schema에 매핑
def build_finding(raw_finding: RawFinding, tool: FindingTool) -> Finding:
    finding_type = normalize_type(raw_finding.type, raw_finding.rule_id, tool)
    line_start, line_end = normalize_line_range(
        raw_finding.line_start,
        raw_finding.line_end,
    )

    return Finding(
        tool=tool,
        type=finding_type,
        cwe_id=normalize_optional_text(raw_finding.cwe_id),
        severity=normalize_severity(raw_finding.severity),
        file_path=normalize_file_path(raw_finding.file_path),
        line_start=line_start,
        line_end=line_end,
        message=normalize_message(
            raw_finding.message,
            raw_finding.rule_id,
            finding_type,
        ),
        evidence=normalize_optional_text(raw_finding.evidence),
        recommendation=None,
        references=[],
    )


# analyzer tool 값을 FindingTool enum으로 정규화
def normalize_tool(tool: FindingTool | str) -> FindingTool:
    return FindingTool(tool)


# finding type이 비어 있으면 rule id 또는 tool 기반 기본값을 생성
def normalize_type(
    finding_type: str | None,
    rule_id: str | None,
    tool: FindingTool,
) -> str:
    normalized_type = normalize_required_text(finding_type)
    if normalized_type:
        return normalized_type

    normalized_rule_id = normalize_required_text(rule_id)
    if normalized_rule_id:
        return normalized_rule_id

    return f"{tool.value}_{DEFAULT_FINDING_TYPE_SUFFIX}"


# severity 값을 FindingSeverity enum으로 정규화
def normalize_severity(severity: FindingSeverity | str | None) -> FindingSeverity:
    try:
        return FindingSeverity(severity)
    except (TypeError, ValueError):
        return FindingSeverity.INFO


# file path를 안전한 문자열로 정규화
def normalize_file_path(file_path: str | None) -> str:
    return normalize_required_text(file_path) or "unknown"


# message가 비어 있으면 rule id, finding type, 기본 메시지 순서로 대체
def normalize_message(
    message: str | None,
    rule_id: str | None,
    finding_type: str,
) -> str:
    return (
        normalize_required_text(message)
        or normalize_required_text(rule_id)
        or finding_type
        or DEFAULT_MESSAGE
    )


# line range를 양수 기반으로 보정하고 역전된 범위를 정리
def normalize_line_range(
    line_start: int | None,
    line_end: int | None,
) -> tuple[int | None, int | None]:
    normalized_start = normalize_line_number(line_start)
    normalized_end = normalize_line_number(line_end)

    if (
        normalized_start is not None
        and normalized_end is not None
        and normalized_end < normalized_start
    ):
        return normalized_start, normalized_start

    return normalized_start, normalized_end


# line number가 양수 정수일 때만 유지
def normalize_line_number(line_number: int | None) -> int | None:
    if not isinstance(line_number, int) or line_number <= 0:
        return None

    return line_number


# 빈 문자열을 None으로 정규화
def normalize_optional_text(value: str | None) -> str | None:
    normalized_value = normalize_required_text(value)
    return normalized_value or None


# 문자열 값을 trim하고 빈 값이면 빈 문자열로 정규화
def normalize_required_text(value: str | None) -> str:
    if value is None:
        return ""

    return str(value).strip()


FINDING_NORMALIZERS = {
    FindingTool.SEMGREP: normalize_semgrep_finding,
    FindingTool.CODEQL: normalize_codeql_finding,
    FindingTool.INFRA: normalize_infra_finding,
}
