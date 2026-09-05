from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from app.schemas.finding import FindingSeverity, FindingTool
from app.services.scanner.base import AnalyzerError, RawFinding

if TYPE_CHECKING:
    from app.services.scanner.codeql_runner import CodeQLLanguage

DEFAULT_FINDING_TYPE = "CODEQL_FINDING"
CWE_PATTERN = re.compile(r"cwe[-_/ ]?0*(\d+)", flags=re.IGNORECASE)


# CodeQL SARIF 파일을 RawFinding 목록으로 변환
def parse_sarif_file(
    sarif_path: Path,
    language: CodeQLLanguage,
) -> list[RawFinding]:
    if not sarif_path.exists():
        raise AnalyzerError(f"CodeQL SARIF output does not exist: {sarif_path}")

    try:
        payload = json.loads(sarif_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AnalyzerError("Failed to parse CodeQL SARIF output") from exc

    runs = payload.get("runs", [])
    if not isinstance(runs, list):
        raise AnalyzerError("Invalid CodeQL SARIF output: runs must be a list")

    findings: list[RawFinding] = []
    for run in runs:
        if not isinstance(run, dict):
            continue

        rules = build_sarif_rule_map(run)
        results = run.get("results", [])
        if not isinstance(results, list):
            raise AnalyzerError("Invalid CodeQL SARIF output: results must be a list")

        findings.extend(
            convert_sarif_result(result, rules, language)
            for result in results
            if isinstance(result, dict)
        )

    return findings


# SARIF rule descriptor를 rule id 기준으로 매핑
def build_sarif_rule_map(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    if not isinstance(rules, list):
        return {}

    return {
        rule["id"]: rule
        for rule in rules
        if isinstance(rule, dict) and isinstance(rule.get("id"), str)
    }


# SARIF result 1건을 RawFinding으로 변환
def convert_sarif_result(
    result: dict[str, Any],
    rules: dict[str, dict[str, Any]],
    language: CodeQLLanguage,
) -> RawFinding:
    rule_id = result.get("ruleId")
    rule = rules.get(rule_id, {}) if isinstance(rule_id, str) else {}
    location = get_primary_location(result)
    region = location.get("region", {})
    properties = result.get("properties", {})
    rule_properties = rule.get("properties", {})

    return RawFinding(
        tool=FindingTool.CODEQL,
        type=normalize_rule_type(rule_id),
        severity=map_codeql_severity(properties, rule_properties, result.get("level")),
        file_path=get_artifact_uri(location),
        message=get_sarif_message(result, rule_id),
        rule_id=rule_id,
        cwe_id=extract_cwe_id(result, rule),
        line_start=get_region_line(region, "startLine"),
        line_end=get_region_line(region, "endLine"),
        evidence=get_region_snippet(region),
        metadata={
            "language": language.name,
            "partial_fingerprints": result.get("partialFingerprints", {}),
            "codeql_properties": properties,
            "rule_properties": rule_properties,
        },
    )


# SARIF result의 대표 location을 추출
def get_primary_location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get("locations", [])
    if not isinstance(locations, list) or not locations:
        return {}

    first_location = locations[0]
    if not isinstance(first_location, dict):
        return {}

    physical_location = first_location.get("physicalLocation", {})
    return physical_location if isinstance(physical_location, dict) else {}


# SARIF artifact uri를 추출
def get_artifact_uri(location: dict[str, Any]) -> str:
    artifact_location = location.get("artifactLocation", {})
    if not isinstance(artifact_location, dict):
        return ""

    return str(artifact_location.get("uri") or "")


# SARIF message 텍스트를 추출
def get_sarif_message(result: dict[str, Any], rule_id: str | None) -> str:
    message = result.get("message", {})
    if isinstance(message, dict):
        fallback = rule_id or DEFAULT_FINDING_TYPE
        return str(message.get("text") or message.get("markdown") or fallback)

    return str(rule_id or DEFAULT_FINDING_TYPE)


# SARIF region의 line 번호를 추출
def get_region_line(region: Any, key: str) -> int | None:
    if not isinstance(region, dict):
        return None

    line_number = region.get(key)
    return line_number if isinstance(line_number, int) else None


# SARIF region snippet을 추출
def get_region_snippet(region: Any) -> str | None:
    if not isinstance(region, dict):
        return None

    snippet = region.get("snippet", {})
    if not isinstance(snippet, dict):
        return None

    text = snippet.get("text")
    return str(text) if text else None


# CodeQL rule id를 내부 finding type 문자열로 정규화
def normalize_rule_type(rule_id: str | None) -> str:
    if not rule_id:
        return DEFAULT_FINDING_TYPE

    rule_name = re.split(r"[/.:]", rule_id)[-1]
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", rule_name).strip("_").upper()
    return normalized or DEFAULT_FINDING_TYPE


# CodeQL severity 정보를 내부 severity로 매핑
def map_codeql_severity(
    properties: Any,
    rule_properties: Any,
    level: Any,
) -> FindingSeverity:
    security_severity = get_security_severity(properties) or get_security_severity(
        rule_properties
    )
    if security_severity is not None:
        if security_severity >= 9.0:
            return FindingSeverity.CRITICAL
        if security_severity >= 7.0:
            return FindingSeverity.HIGH
        if security_severity >= 4.0:
            return FindingSeverity.MEDIUM
        if security_severity > 0:
            return FindingSeverity.LOW

    level_mapping = {
        "error": FindingSeverity.HIGH,
        "warning": FindingSeverity.MEDIUM,
        "note": FindingSeverity.LOW,
        "none": FindingSeverity.INFO,
    }
    return level_mapping.get(str(level or "").lower(), FindingSeverity.INFO)


# SARIF properties에서 security-severity 숫자를 추출
def get_security_severity(properties: Any) -> float | None:
    if not isinstance(properties, dict):
        return None

    value = properties.get("security-severity")
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# SARIF result/rule metadata에서 CWE ID를 추출
def extract_cwe_id(result: dict[str, Any], rule: dict[str, Any]) -> str | None:
    candidates = [
        result.get("properties", {}),
        rule.get("properties", {}),
        rule.get("id"),
    ]
    for candidate in candidates:
        match = CWE_PATTERN.search(str(candidate))
        if match:
            return f"CWE-{int(match.group(1))}"

    return None
