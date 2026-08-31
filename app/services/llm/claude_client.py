import json
import logging
import time
from typing import Any

from app.schemas.explanation import ExplanationResult

logger = logging.getLogger(__name__)


class ClaudeClientError(RuntimeError):
    pass


class ClaudeConfigurationError(ClaudeClientError):
    pass


class ClaudeResponseParseError(ClaudeClientError):
    pass


class ClaudeExplanationClient:
    def __init__(self) -> None:
        from app.core.config import settings

        if not settings.CLAUDE_API_KEY:
            raise ClaudeConfigurationError("CLAUDE_API_KEY is required")

        self.api_key = settings.CLAUDE_API_KEY
        self.model = settings.CLAUDE_MODEL
        self.timeout_seconds = settings.CLAUDE_TIMEOUT_SECONDS
        self.max_output_tokens = settings.CLAUDE_MAX_OUTPUT_TOKENS
        self.max_retries = settings.CLAUDE_MAX_RETRIES

    # Claude API 호출 후 JSON 응답 반환
    def generate_explanation(self, prompt: str) -> ExplanationResult:
        response_text = self._request_with_retry(prompt)
        return parse_explanation_response(response_text)

    # 외부 API 오류 발생 시 제한된 횟수만큼 재시도
    def _request_with_retry(self, prompt: str) -> str:
        last_error: Exception | None = None

        for attempt in range(self.max_retries + 1):
            try:
                return self._request_once(prompt)
            except Exception as exc:
                last_error = exc
                if not _is_retryable_error(exc) or attempt >= self.max_retries:
                    break

                sleep_seconds = min(2 ** attempt, 8)
                logger.warning(
                    "Claude request failed. retrying attempt=%s sleep_seconds=%s error=%s",
                    attempt + 1,
                    sleep_seconds,
                    exc.__class__.__name__,
                )
                time.sleep(sleep_seconds)

        raise ClaudeClientError("Claude explanation request failed") from last_error

    # Claude Messages API 단건 호출
    def _request_once(self, prompt: str) -> str:
        try:
            from anthropic import Anthropic
        except ImportError as exc:
            raise ClaudeConfigurationError("anthropic package is required") from exc

        client = Anthropic(
            api_key=self.api_key,
            timeout=self.timeout_seconds,
            max_retries=0,
        )
        response = client.messages.create(
            model=self.model,
            max_tokens=self.max_output_tokens,
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        text_blocks = [
            block.text
            for block in response.content
            if getattr(block, "type", None) == "text" and getattr(block, "text", None)
        ]
        if not text_blocks:
            raise ClaudeResponseParseError("Claude response text is empty")

        return "\n".join(text_blocks)


# Claude 응답에서 JSON 객체를 추출해 DTO로 검증
def parse_explanation_response(response_text: str) -> ExplanationResult:
    try:
        payload = json.loads(response_text)
    except json.JSONDecodeError:
        payload = _extract_json_object(response_text)

    try:
        return ExplanationResult.model_validate(payload)
    except Exception as exc:
        raise ClaudeResponseParseError("Claude response does not match explanation schema") from exc


# 코드블록이나 설명 문구가 섞인 경우 첫 JSON object만 추출
def _extract_json_object(response_text: str) -> dict[str, Any]:
    start = response_text.find("{")
    end = response_text.rfind("}")
    if start < 0 or end < start:
        raise ClaudeResponseParseError("Claude response does not contain a JSON object")

    try:
        return json.loads(response_text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ClaudeResponseParseError("Claude response JSON is invalid") from exc


# timeout, rate limit, 5xx 계열 오류만 재시도 대상으로 처리
def _is_retryable_error(exc: Exception) -> bool:
    retryable_error_names = {
        "APIConnectionError",
        "APITimeoutError",
        "InternalServerError",
        "RateLimitError",
    }
    if exc.__class__.__name__ in retryable_error_names:
        return True

    status_code = getattr(exc, "status_code", None)
    return status_code == 429 or (status_code is not None and status_code >= 500)
