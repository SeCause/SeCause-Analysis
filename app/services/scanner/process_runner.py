import os
import select
import subprocess
import tempfile
import time

from app.services.scanner.base import AnalyzerError


# 외부 CLI command를 실행하고 stdout 문자열을 반환
def execute_command(
    command: list[str],
    stage: str,
    timeout_seconds: int | float,
    executable_name: str,
    max_stdout_chars: int,
    max_error_chars: int = 1200,
) -> str:
    stderr_file = tempfile.TemporaryFile()
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=stderr_file,
        )
        stdout = read_limited_stdout(
            process,
            stage,
            timeout_seconds,
            max_stdout_chars,
        )
    except FileNotFoundError as exc:
        stderr_file.close()
        raise AnalyzerError(
            f"{executable_name} executable is unavailable. "
            f"Install {executable_name} CLI in the analysis runtime image or disable this analyzer."
        ) from exc
    except AnalyzerError:
        stderr_file.close()
        raise
    except OSError as exc:
        stderr_file.close()
        raise AnalyzerError(f"{stage} execution failed") from exc
    finally:
        if not stderr_file.closed:
            stderr_file.seek(0)

    if process.returncode != 0:
        stderr = truncate_output(
            stderr_file.read().decode("utf-8", errors="replace"),
            max_error_chars,
        )
        stderr_file.close()
        raise AnalyzerError(f"{stage} failed. stderr={stderr}")

    stderr_file.close()
    return stdout


# stdout을 점진적으로 읽고 제한을 초과하면 프로세스를 종료
def read_limited_stdout(
    process: subprocess.Popen,
    stage: str,
    timeout_seconds: int | float,
    max_stdout_chars: int,
) -> str:
    if process.stdout is None:
        raise AnalyzerError(f"{stage} stdout pipe is unavailable")

    stdout_chunks: list[bytes] = []
    total_bytes = 0
    deadline = time.monotonic() + float(timeout_seconds)

    try:
        while True:
            if time.monotonic() >= deadline:
                terminate_process(process)
                raise AnalyzerError(f"{stage} timed out")

            if process.poll() is not None:
                total_bytes = drain_stdout(
                    process.stdout.fileno(),
                    stdout_chunks,
                    total_bytes,
                    max_stdout_chars,
                    process,
                    stage,
                )
                break

            ready, _, _ = select.select([process.stdout], [], [], 0.1)
            if ready:
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    continue

                total_bytes = append_stdout_chunk(
                    chunk,
                    stdout_chunks,
                    total_bytes,
                    max_stdout_chars,
                    process,
                    stage,
                )

        process.wait()
        return b"".join(stdout_chunks).decode("utf-8", errors="replace")
    finally:
        process.stdout.close()


# 프로세스 종료 후 pipe에 남아 있는 stdout을 모두 읽음
def drain_stdout(
    stdout_fd: int,
    stdout_chunks: list[bytes],
    total_bytes: int,
    max_stdout_chars: int,
    process: subprocess.Popen,
    stage: str,
) -> int:
    while True:
        chunk = os.read(stdout_fd, 8192)
        if not chunk:
            return total_bytes

        total_bytes = append_stdout_chunk(
            chunk,
            stdout_chunks,
            total_bytes,
            max_stdout_chars,
            process,
            stage,
        )


# stdout chunk를 누적하고 제한 초과 여부를 확인
def append_stdout_chunk(
    chunk: bytes,
    stdout_chunks: list[bytes],
    total_bytes: int,
    max_stdout_chars: int,
    process: subprocess.Popen,
    stage: str,
) -> int:
    next_total = total_bytes + len(chunk)
    if next_total > max_stdout_chars:
        terminate_process(process)
        raise AnalyzerError(
            f"{stage} stdout exceeded {max_stdout_chars} bytes. "
            "Reduce analyzer output size or increase the configured output limit."
        )

    stdout_chunks.append(chunk)
    return next_total


# 외부 CLI 프로세스를 종료하고 남아 있으면 강제 종료
def terminate_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


# CLI stderr/stdout가 과도하게 길어지지 않도록 제한
def truncate_output(output: str | None, max_chars: int = 1200) -> str:
    if not output:
        return ""

    output = output.strip()
    if len(output) <= max_chars:
        return output

    return output[:max_chars] + "...(truncated)"
