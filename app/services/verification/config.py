"""Verification-only settings; existing analysis settings remain unchanged."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class VerificationSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=(".env", ".env.verification"), extra="ignore")

    CLAUDE_API_KEY: str = ""
    REDIS_URL: str = "redis://localhost:6379/0"
    ANALYSIS_CALLBACK_INTERNAL_TOKEN: str | None = None
    VERIFICATION_MODEL: str = "claude-sonnet-4-6"
    VERIFICATION_LLM_TIMEOUT_SECONDS: float = Field(default=45, gt=0, le=90)
    VERIFICATION_LLM_MAX_RETRIES: int = Field(default=1, ge=0, le=2)
    VERIFICATION_MAX_OUTPUT_TOKENS: int = Field(default=8000, ge=1024, le=16000)


@lru_cache
def get_verification_settings() -> VerificationSettings:
    return VerificationSettings()
