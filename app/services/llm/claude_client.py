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
        payload = self._request_with_retry(prompt)
        return _build_explanation_result(payload)

    # 외부 API 오류 발생 시 제한된 횟수만큼 재시도
    def _request_with_retry(self, prompt: str) -> dict[str, Any]:
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
    def _request_once(self, prompt: str) -> dict[str, Any]:
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
            tools=[EXPLANATION_TOOL_SCHEMA],
            tool_choice={
                "type": "tool",
                "name": EXPLANATION_TOOL_NAME,
            },
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        for block in response.content:
            if (
                getattr(block, "type", None) == "tool_use"
                and getattr(block, "name", None) == EXPLANATION_TOOL_NAME
            ):
                tool_input = getattr(block, "input", None)
                if isinstance(tool_input, dict):
                    return tool_input

        raise ClaudeResponseParseError("Claude response does not contain explanation tool output")


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


# Claude tool input을 DTO로 검증
def _build_explanation_result(payload: dict[str, Any]) -> ExplanationResult:
    try:
        return ExplanationResult.model_validate(payload)
    except Exception as exc:
        raise ClaudeResponseParseError("Claude response does not match explanation schema") from exc


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


EXPLANATION_TOOL_NAME = "generate_security_explanation"
EXPLANATION_TOOL_SCHEMA = {
    "name": EXPLANATION_TOOL_NAME,
    "description": "Generate a Korean security finding explanation and remediation example.",
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "summary": {
                "type": "string",
                "description": "취약점 요약 한 문장",
            },
            "rootCause": {
                "type": "string",
                "description": "취약점이 발생한 원인",
            },
            "impact": {
                "type": "string",
                "description": "가능한 보안 영향",
            },
            "recommendation": {
                "type": "string",
                "description": "실무적인 수정 방향",
            },
            "fixExamples": {
                "type": "array",
                "minItems": 1,
                "items": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "language": {
                            "type": ["string", "null"],
                            "description": "언어 이름 또는 null",
                        },
                        "vulnerableCode": {
                            "type": ["string", "null"],
                            "description": "취약한 코드 예시 또는 null",
                        },
                        "fixedCode": {
                            "type": "string",
                            "description": "안전한 코드 예시",
                        },
                        "explanation": {
                            "type": "string",
                            "description": "수정 코드가 안전한 이유",
                        },
                    },
                    "required": [
                        "language",
                        "vulnerableCode",
                        "fixedCode",
                        "explanation",
                    ],
                },
            },
        },
        "required": [
            "summary",
            "rootCause",
            "impact",
            "recommendation",
            "fixExamples",
        ],
    },
}
