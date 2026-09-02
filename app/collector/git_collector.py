import logging
import os
from pathlib import Path
from pydantic import SecretStr
import shutil
import subprocess
from urllib.parse import quote, urlsplit, urlunsplit

from app.core.config import settings

logger = logging.getLogger(__name__)
MAX_GIT_OUTPUT_CHARS = 1200


class GitCloneUrlError(ValueError):
    pass


class GitCloneError(RuntimeError):
    pass


# GitHub token을 포함한 HTTPS clone URL을 생성
def build_authenticated_clone_url(
    repository_url: str,
    github_token: SecretStr,
) -> str:
    parsed_url = urlsplit(repository_url)
    token = github_token.get_secret_value()

    if parsed_url.scheme != "https" or parsed_url.hostname is None:
        raise GitCloneUrlError("Repository URL must be a valid HTTPS URL")

    if not token:
        raise GitCloneUrlError("GitHub token must not be empty")

    host = parsed_url.hostname
    if parsed_url.port is not None:
        host = f"{host}:{parsed_url.port}"

    encoded_token = quote(token, safe="")
    authenticated_host = f"x-access-token:{encoded_token}@{host}"

    return urlunsplit(
        (
            parsed_url.scheme,
            authenticated_host,
            parsed_url.path,
            parsed_url.query,
            parsed_url.fragment,
        )
    )


# Git shallow clone을 수행하고 clone된 repository path를 반환
def shallow_clone_repository(
    repository_url: str,
    branch: str,
    github_token: SecretStr,
    analysis_id: int,
    clone_root_dir: str | Path | None = None,
    timeout_seconds: int | None = None,
) -> Path:
    if not branch.strip():
        raise GitCloneError("Repository branch must not be empty")

    clone_url = build_authenticated_clone_url(repository_url, github_token)
    destination = build_repository_path(analysis_id, clone_root_dir)
    timeout = timeout_seconds or settings.GIT_CLONE_TIMEOUT_SECONDS

    prepare_clone_destination(destination)

    logger.info(
        "Git shallow clone started. analysis_id=%s repository_url=%s branch=%s destination=%s",
        analysis_id,
        mask_clone_url(clone_url),
        branch,
        destination,
    )

    command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--branch",
        branch,
        clone_url,
        str(destination),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        cleanup_repository(destination)
        raise GitCloneError(
            f"Git shallow clone timed out. repository_url={mask_clone_url(clone_url)} branch={branch}"
        ) from exc
    except OSError as exc:
        cleanup_repository(destination)
        raise GitCloneError("Git executable is unavailable") from exc

    if result.returncode != 0:
        cleanup_repository(destination)
        stderr = truncate_output(sanitize_git_output(result.stderr, clone_url, github_token))
        raise GitCloneError(
            "Git shallow clone failed. "
            f"repository_url={mask_clone_url(clone_url)} branch={branch} stderr={stderr}"
        )

    logger.info(
        "Git shallow clone completed. analysis_id=%s repository_url=%s branch=%s destination=%s",
        analysis_id,
        mask_clone_url(clone_url),
        branch,
        destination,
    )

    return destination


# analysis_id별 repository clone 경로를 생성
def build_repository_path(
    analysis_id: int,
    clone_root_dir: str | Path | None = None,
) -> Path:
    root_dir = Path(clone_root_dir or settings.GIT_CLONE_ROOT_DIR)
    return root_dir / f"analysis-{analysis_id}" / "repository"


# clone 대상 디렉터리를 비우고 부모 디렉터리를 준비
def prepare_clone_destination(destination: Path) -> None:
    cleanup_repository(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)


# clone된 repository 디렉터리를 삭제
def cleanup_repository(repo_path: str | Path | None) -> None:
    if repo_path is None:
        return

    path = Path(repo_path)
    if path.exists():
        shutil.rmtree(path)

    cleanup_empty_parent(path.parent)


# 비어 있는 analysis 작업 디렉터리를 삭제
def cleanup_empty_parent(path: Path) -> None:
    try:
        path.rmdir()
    except OSError:
        return


# 로그 출력용으로 credential 정보를 제거한 clone URL을 생성
def mask_clone_url(clone_url: str) -> str:
    parsed_url = urlsplit(clone_url)
    if parsed_url.hostname is None:
        return clone_url

    host = parsed_url.hostname
    if parsed_url.port is not None:
        host = f"{host}:{parsed_url.port}"

    return urlunsplit(
        (
            parsed_url.scheme,
            host,
            parsed_url.path,
            parsed_url.query,
            parsed_url.fragment,
        )
    )


# git stderr/stdout에서 credential 값을 제거
def sanitize_git_output(
    output: str | None,
    clone_url: str,
    github_token: SecretStr,
) -> str:
    if not output:
        return ""

    token = github_token.get_secret_value()
    sanitized = output.replace(clone_url, mask_clone_url(clone_url))
    if token:
        sanitized = sanitized.replace(token, "***")

    return sanitized.strip()


# git 출력이 로그/예외 메시지에 과도하게 남지 않도록 길이를 제한
def truncate_output(output: str) -> str:
    if len(output) <= MAX_GIT_OUTPUT_CHARS:
        return output

    return output[:MAX_GIT_OUTPUT_CHARS] + "...(truncated)"
