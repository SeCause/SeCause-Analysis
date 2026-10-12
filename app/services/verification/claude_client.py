"""Isolated Claude adapter with structured output and bounded SDK retries."""

from dataclasses import dataclass

from anthropic import Anthropic

from app.schemas.verification import VerificationJudgment, VerificationRequest, VerificationUsage
from app.services.verification.config import VerificationSettings, get_verification_settings
from app.services.verification.prompt import SYSTEM_PROMPT, build_verification_prompt

TOOL_NAME = "verify_security_explanation"


class VerificationModelError(RuntimeError):
    """External model failed or returned an unusable judgment."""


@dataclass(frozen=True)
class ModelJudgment:
    judgment: VerificationJudgment
    model: str
    usage: VerificationUsage


class ClaudeVerificationClient:
    def __init__(self, settings: VerificationSettings | None = None) -> None:
        self.settings = settings or get_verification_settings()

    def verify(self, request: VerificationRequest) -> ModelJudgment:
        if not self.settings.CLAUDE_API_KEY.strip():
            raise VerificationModelError("Verification model is not configured")

        # Suppress SDK/validation exception details: they may contain source code.
        try:
            with Anthropic(
                api_key=self.settings.CLAUDE_API_KEY,
                timeout=self.settings.VERIFICATION_LLM_TIMEOUT_SECONDS,
                max_retries=self.settings.VERIFICATION_LLM_MAX_RETRIES,
            ) as client:
                response = client.messages.create(
                    model=self.settings.VERIFICATION_MODEL,
                    max_tokens=self.settings.VERIFICATION_MAX_OUTPUT_TOKENS,
                    system=SYSTEM_PROMPT,
                    tools=[{
                        "name": TOOL_NAME,
                        "description": "Verify every claim against supplied evidence.",
                        "input_schema": VerificationJudgment.model_json_schema(by_alias=True),
                    }],
                    tool_choice={"type": "tool", "name": TOOL_NAME},
                    messages=[{"role": "user", "content": build_verification_prompt(request)}],
                )
            if response.stop_reason != "tool_use":
                raise ValueError("Incomplete verification response")
            outputs = [
                block.input for block in response.content
                if getattr(block, "type", None) == "tool_use"
                and getattr(block, "name", None) == TOOL_NAME
            ]
            if len(outputs) != 1:
                raise ValueError("Expected one judgment")
            return ModelJudgment(
                judgment=VerificationJudgment.model_validate(outputs[0]),
                model=response.model,
                usage=VerificationUsage(
                    input_tokens=response.usage.input_tokens,
                    output_tokens=response.usage.output_tokens,
                ),
            )
        except Exception:
            raise VerificationModelError("Verification model request or response failed") from None
