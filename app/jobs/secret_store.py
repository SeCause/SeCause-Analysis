from uuid import uuid4

from pydantic import SecretStr

from app.core.config import settings
from app.jobs.queue import get_redis_connection

GITHUB_TOKEN_REFERENCE_PREFIX = "analysis:github-token:"


class SecretReferenceError(RuntimeError):
    pass


def store_github_token(github_token: SecretStr) -> str:
    token_reference = f"{GITHUB_TOKEN_REFERENCE_PREFIX}{uuid4()}"
    redis_connection = get_redis_connection()
    redis_connection.setex(
        token_reference,
        settings.GITHUB_TOKEN_TTL_SECONDS,
        github_token.get_secret_value(),
    )
    return token_reference


def resolve_github_token_reference(token_reference: str) -> SecretStr:
    token = get_redis_connection().get(token_reference)
    if token is None:
        raise SecretReferenceError("GitHub token reference is missing or expired")

    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return SecretStr(token)


def delete_github_token_reference(token_reference: str) -> None:
    get_redis_connection().delete(token_reference)
