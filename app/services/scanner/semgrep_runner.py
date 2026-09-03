import json
import logging
from pathlib import Path
import re
import subprocess
from typing import Any

from app.core.config import settings
from app.schemas.finding import FindingSeverity, FindingTool
from app.services.scanner.base import AnalyzerContext, AnalyzerError, RawFinding

logger = logging.getLogger(__name__)
DEFAULT_FINDING_TYPE = "SEMGREP_FINDING"
MAX_SEMGREP_OUTPUT_CHARS = 1200
CWE_PATTERN = re.compile(r"CWE-\d+", flags=re.IGNORECASE)


class SemgrepRunner:
    tool = FindingTool.SEMGREP

    # Semgrep CLI를 실행하고 JSON 결과를 RawFinding 목록으로 변환
    def run(self, repo_path: str, context: AnalyzerContext) -> list[RawFinding]:
        repository_path = validate_repository_path(repo_path)
        command = build_semgrep_command(repository_path)

        logger.info(
            "Semgrep analysis started. analysis_id=%s repository_id=%s repo_path=%s",
            context.analysis_id,
            context.repository_id,
            repository_path,
        )

        output = execute_semgrep(command)
        findings = parse_semgrep_output(output)

        logger.info(
            "Semgrep analysis completed. analysis_id=%s finding_count=%s",
            context.analysis_id,
            len(findings),
        )
        return findings


# Semgrep 실행 대상 repository path를 검증
def validate_repository_path(repo_path: str) -> Path:
    repository_path = Path(repo_path)
    if not repository_path.exists() or not repository_path.is_dir():
        raise AnalyzerError(f"Repository path does not exist: {repo_path}")

    return repository_path


# Semgrep CLI command를 구성
def build_semgrep_command(repo_path: Path) -> list[str]:
    return [
        "semgrep",
        "--config",
        settings.SEMGREP_CONFIG,
        "--json",
        "--quiet",
        str(repo_path),
    ]


# Semgrep CLI를 실행하고 stdout JSON 문자열을 반환
def execute_semgrep(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=settings.SEMGREP_TIMEOUT_SECONDS,
        )
    except FileNotFoundError as exc:
        raise AnalyzerError("Semgrep executable is unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise AnalyzerError("Semgrep analysis timed out") from exc
    except OSError as exc:
        raise AnalyzerError("Semgrep execution failed") from exc

    if result.returncode != 0:
        stderr = truncate_semgrep_output(result.stderr)
        raise AnalyzerError(f"Semgrep analysis failed. stderr={stderr}")

    return result.stdout


# Semgrep JSON stdout을 RawFinding 목록으로 변환
def parse_semgrep_output(output: str) -> list[RawFinding]:
    try:
        payload = json.loads(output or "{}")
    except json.JSONDecodeError as exc:
        raise AnalyzerError("Failed to parse Semgrep JSON output") from exc

    results = payload.get("results", [])
    if not isinstance(results, list):
        raise AnalyzerError("Invalid Semgrep JSON output: results must be a list")

    return [convert_semgrep_result(result) for result in results]


# Semgrep result 1건을 RawFinding으로 변환
def convert_semgrep_result(result: dict[str, Any]) -> RawFinding:
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    rule_id = result.get("check_id")

    return RawFinding(
        tool=FindingTool.SEMGREP,
        type=normalize_rule_type(rule_id),
        severity=map_semgrep_severity(extra.get("severity")),
        file_path=str(result.get("path") or ""),
        message=str(extra.get("message") or rule_id or DEFAULT_FINDING_TYPE),
        rule_id=rule_id,
        cwe_id=extract_cwe_id(metadata),
        line_start=get_line_number(result.get("start")),
        line_end=get_line_number(result.get("end")),
        evidence=extra.get("lines"),
        metadata={
            "semgrep_metadata": metadata,
            "fingerprint": result.get("extra", {}).get("fingerprint"),
        },
    )


# Semgrep rule id를 내부 finding type 문자열로 정규화
def normalize_rule_type(rule_id: str | None) -> str:
    if not rule_id:
        return DEFAULT_FINDING_TYPE

    rule_name = re.split(r"[./]", rule_id)[-1]
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", rule_name).strip("_").upper()
    return normalized or DEFAULT_FINDING_TYPE


# Semgrep severity를 내부 severity로 매핑
def map_semgrep_severity(severity: str | None) -> FindingSeverity:
    severity_mapping = {
        "ERROR": FindingSeverity.HIGH,
        "WARNING": FindingSeverity.MEDIUM,
        "INFO": FindingSeverity.LOW,
    }
    return severity_mapping.get(str(severity or "").upper(), FindingSeverity.INFO)


# Semgrep metadata에서 CWE ID를 추출
def extract_cwe_id(metadata: Any) -> str | None:
    if not metadata:
        return None

    matches = CWE_PATTERN.findall(str(metadata))
    if not matches:
        return None

    return matches[0].upper()


# Semgrep 위치 객체에서 line 번호를 추출
def get_line_number(location: Any) -> int | None:
    if not isinstance(location, dict):
        return None

    line_number = location.get("line")
    return line_number if isinstance(line_number, int) else None


# Semgrep stderr가 과도하게 길어지지 않도록 제한
def truncate_semgrep_output(output: str | None) -> str:
    if not output:
        return ""

    output = output.strip()
    if len(output) <= MAX_SEMGREP_OUTPUT_CHARS:
        return output

    return output[:MAX_SEMGREP_OUTPUT_CHARS] + "...(truncated)"
