from pydantic import SecretStr
from urllib.parse import quote, urlsplit, urlunsplit


class GitCloneUrlError(ValueError):
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
