import subprocess

from app.services.scanner.base import AnalyzerError


# 외부 CLI command를 실행하고 stdout 문자열을 반환
def execute_command(
    command: list[str],
    stage: str,
    timeout_seconds: int | float,
    executable_name: str,
    max_output_chars: int = 1200,
) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as exc:
        raise AnalyzerError(f"{executable_name} executable is unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise AnalyzerError(f"{stage} timed out") from exc
    except OSError as exc:
        raise AnalyzerError(f"{stage} execution failed") from exc

    if result.returncode != 0:
        stderr = truncate_output(result.stderr, max_output_chars)
        raise AnalyzerError(f"{stage} failed. stderr={stderr}")

    return result.stdout


# CLI stderr/stdout가 과도하게 길어지지 않도록 제한
def truncate_output(output: str | None, max_chars: int = 1200) -> str:
    if not output:
        return ""

    output = output.strip()
    if len(output) <= max_chars:
        return output

    return output[:max_chars] + "...(truncated)"
