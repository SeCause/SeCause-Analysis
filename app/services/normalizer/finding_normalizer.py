from collections.abc import Iterable

from app.schemas.finding import Finding, FindingTool
from app.services.scanner.base import RawFinding


class UnknownFindingToolError(ValueError):
    pass


# 여러 analyzer raw finding을 공통 Finding 목록으로 변환
def normalize_findings(raw_findings: Iterable[RawFinding]) -> list[Finding]:
    return [normalize_finding(raw_finding) for raw_finding in raw_findings]


# raw finding의 tool에 맞는 normalizer를 선택해 공통 Finding으로 변환
def normalize_finding(raw_finding: RawFinding) -> Finding:
    try:
        normalizer = FINDING_NORMALIZERS[FindingTool(raw_finding.tool)]
    except ValueError as exc:
        raise UnknownFindingToolError(f"Unsupported finding tool: {raw_finding.tool}") from exc

    return normalizer(raw_finding)


# Semgrep raw finding을 공통 Finding으로 변환
def normalize_semgrep_finding(raw_finding: RawFinding) -> Finding:
    return build_finding(raw_finding)


# CodeQL raw finding을 공통 Finding으로 변환
def normalize_codeql_finding(raw_finding: RawFinding) -> Finding:
    return build_finding(raw_finding)


# Infra raw finding을 공통 Finding으로 변환
def normalize_infra_finding(raw_finding: RawFinding) -> Finding:
    return build_finding(raw_finding)


# 도구별 raw finding의 공통 필드를 Finding schema에 매핑
def build_finding(raw_finding: RawFinding) -> Finding:
    return Finding(
        tool=FindingTool(raw_finding.tool),
        type=raw_finding.type,
        cwe_id=raw_finding.cwe_id,
        severity=raw_finding.severity,
        file_path=raw_finding.file_path,
        line_start=raw_finding.line_start,
        line_end=raw_finding.line_end,
        message=raw_finding.message,
        evidence=raw_finding.evidence,
        recommendation=None,
        references=[],
    )


FINDING_NORMALIZERS = {
    FindingTool.SEMGREP: normalize_semgrep_finding,
    FindingTool.CODEQL: normalize_codeql_finding,
    FindingTool.INFRA: normalize_infra_finding,
}
