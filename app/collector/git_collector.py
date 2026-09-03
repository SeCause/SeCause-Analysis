import logging
import os
from pathlib import Path
from pydantic import SecretStr
import shutil
import subprocess
import tempfile
from urllib.parse import urlsplit, urlunsplit

from app.core.config import settings

logger = logging.getLogger(__name__)
MAX_GIT_OUTPUT_CHARS = 1200


class GitCloneUrlError(ValueError):
    pass


class GitCloneError(RuntimeError):
    pass


# Git clone에 사용할 HTTPS repository URL을 검증
def validate_clone_url(repository_url: str) -> str:
    parsed_url = urlsplit(repository_url)

    if parsed_url.scheme != "https" or parsed_url.hostname is None:
        raise GitCloneUrlError("Repository URL must be a valid HTTPS URL")

    if parsed_url.username is not None or parsed_url.password is not None:
        raise GitCloneUrlError("Repository URL must not include credentials")

    if parsed_url.hostname.lower() not in get_allowed_git_hosts():
        raise GitCloneUrlError("Repository URL host is not allowed")

    return urlunsplit(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.query,
            parsed_url.fragment,
        )
    )


# 허용된 Git repository host 목록을 설정에서 로딩
def get_allowed_git_hosts() -> set[str]:
    return {
        host.strip().lower()
        for host in settings.GIT_ALLOWED_HOSTS.split(",")
        if host.strip()
    }


# GitHub token을 command line 인자에 넣지 않기 위한 askpass script 생성
def create_git_askpass_script() -> Path:
    script = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="secause-git-askpass-",
        suffix=".sh",
        delete=False,
    )
    try:
        script.write(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "*Username*) printf '%s\\n' 'x-access-token' ;;\n"
            "*Password*) printf '%s\\n' \"$GIT_ASKPASS_TOKEN\" ;;\n"
            "*) printf '\\n' ;;\n"
            "esac\n"
        )
    finally:
        script.close()

    os.chmod(script.name, 0o700)
    return Path(script.name)


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

    token = github_token.get_secret_value()
    if not token:
        raise GitCloneError("GitHub token must not be empty")

    clone_url = validate_clone_url(repository_url)
    destination = create_repository_path(analysis_id, clone_root_dir)
    timeout = timeout_seconds or settings.GIT_CLONE_TIMEOUT_SECONDS

    prepare_clone_destination(destination)

    logger.info(
        "Git shallow clone started. analysis_id=%s repository_url=%s branch=%s destination=%s",
        analysis_id,
        clone_url,
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

    askpass_script = create_git_askpass_script()
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            env={
                **os.environ,
                "GIT_ASKPASS": str(askpass_script),
                "GIT_ASKPASS_TOKEN": token,
                "GIT_TERMINAL_PROMPT": "0",
            },
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        cleanup_repository(destination)
        raise GitCloneError(
            f"Git shallow clone timed out. repository_url={clone_url} branch={branch}"
        ) from exc
    except OSError as exc:
        cleanup_repository(destination)
        raise GitCloneError("Git executable is unavailable") from exc
    finally:
        cleanup_askpass_script(askpass_script)

    if result.returncode != 0:
        cleanup_repository(destination)
        stderr = truncate_output(sanitize_git_output(result.stderr, github_token))
        raise GitCloneError(
            "Git shallow clone failed. "
            f"repository_url={clone_url} branch={branch} stderr={stderr}"
        )

    logger.info(
        "Git shallow clone completed. analysis_id=%s repository_url=%s branch=%s destination=%s",
        analysis_id,
        clone_url,
        branch,
        destination,
    )

    return destination


# analysis_id별 임시 repository clone 경로를 생성
def create_repository_path(
    analysis_id: int,
    clone_root_dir: str | Path | None = None,
) -> Path:
    root_dir = resolve_clone_root_dir(clone_root_dir)
    job_dir = tempfile.mkdtemp(prefix=f"analysis-{analysis_id}-", dir=root_dir)
    return Path(job_dir) / "repository"


# clone root 경로를 준비하고 symlink 사용을 차단
def resolve_clone_root_dir(clone_root_dir: str | Path | None = None) -> Path:
    configured_root = (
        clone_root_dir if clone_root_dir is not None else settings.GIT_CLONE_ROOT_DIR
    )
    root_dir = (
        Path(configured_root).expanduser()
        if configured_root
        else Path(tempfile.gettempdir()) / "secause-analysis"
    )

    if root_dir.exists() and root_dir.is_symlink():
        raise GitCloneError("Git clone root directory must not be a symlink")

    root_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root_dir.stat().st_uid != os.getuid():
        raise GitCloneError("Git clone root directory is owned by another user")

    return root_dir


# clone 대상 디렉터리를 비우고 부모 디렉터리를 준비
def prepare_clone_destination(destination: Path) -> None:
    validate_managed_repository_path(destination)
    if destination.exists():
        raise GitCloneError("Git clone destination already exists")


# clone된 repository 디렉터리를 삭제
def cleanup_repository(repo_path: str | Path | None) -> None:
    if repo_path is None:
        return

    path = Path(repo_path)
    validate_managed_repository_path(path)

    job_dir = path.parent
    if job_dir.exists():
        shutil.rmtree(job_dir)


# 생성한 job별 repository 경로인지 검증
def validate_managed_repository_path(path: Path) -> None:
    if path.name != "repository" or not path.parent.name.startswith("analysis-"):
        raise GitCloneError("Refusing to operate on unmanaged repository path")

    if path.is_symlink() or path.parent.is_symlink():
        raise GitCloneError("Refusing to operate on symlink repository path")

    if path.parent.exists() and path.parent.stat().st_uid != os.getuid():
        raise GitCloneError("Refusing to operate on repository path owned by another user")


# 임시 askpass script를 삭제
def cleanup_askpass_script(script_path: Path | None) -> None:
    if script_path is None:
        return

    try:
        script_path.unlink(missing_ok=True)
    except OSError:
        logger.warning("Failed to delete Git askpass script. path=%s", script_path)


# git stderr/stdout에서 credential 값을 제거
def sanitize_git_output(
    output: str | None,
    github_token: SecretStr,
) -> str:
    if not output:
        return ""

    token = github_token.get_secret_value()
    sanitized = output
    if token:
        sanitized = sanitized.replace(token, "***")

    return sanitized.strip()


# git 출력이 로그/예외 메시지에 과도하게 남지 않도록 길이를 제한
def truncate_output(output: str) -> str:
    if len(output) <= MAX_GIT_OUTPUT_CHARS:
        return output

    return output[:MAX_GIT_OUTPUT_CHARS] + "...(truncated)"
