import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.services.verification.claude_client import ClaudeVerificationClient, TOOL_NAME, VerificationModelError
from app.services.verification.config import VerificationSettings
from tests.services.verification.test_schemas import sample_request


def model_response():
    return SimpleNamespace(
        stop_reason="tool_use", model="test-model",
        usage=SimpleNamespace(input_tokens=100, output_tokens=50),
        content=[SimpleNamespace(type="tool_use", name=TOOL_NAME, input={"results": [{
            "field": "summary", "sourceText": "SQL 위험", "claim": "SQL 위험",
            "verdict": "INSUFFICIENT_EVIDENCE", "reason": "근거 부족", "citations": [],
        }]})],
    )


class ClaudeVerificationTest(unittest.TestCase):
    def client(self):
        return ClaudeVerificationClient(VerificationSettings(_env_file=None, CLAUDE_API_KEY="test"))

    def test_structured_tool_and_usage(self):
        sdk = Mock()
        sdk.messages.create.return_value = model_response()
        with patch("app.services.verification.claude_client.Anthropic") as factory:
            factory.return_value.__enter__.return_value = sdk
            result = self.client().verify(sample_request())
        self.assertEqual(result.usage.input_tokens, 100)
        self.assertEqual(result.model, "test-model")
        kwargs = sdk.messages.create.call_args.kwargs
        self.assertEqual(kwargs["tool_choice"]["name"], TOOL_NAME)
        self.assertIn("untrusted DATA", kwargs["system"])
        self.assertIn("rootCause", kwargs["messages"][0]["content"])
        self.assertEqual(factory.call_args.kwargs["max_retries"], 1)

    def test_truncated_missing_and_invalid_output_fail(self):
        for variant in ("truncated", "missing", "invalid"):
            response = model_response()
            if variant == "truncated":
                response.stop_reason = "max_tokens"
            elif variant == "missing":
                response.content = []
            else:
                response.content[0].input = {"private-code": "secret"}
            with self.subTest(variant=variant), patch(
                "app.services.verification.claude_client.Anthropic"
            ) as factory:
                factory.return_value.__enter__.return_value.messages.create.return_value = response
                with self.assertRaises(VerificationModelError) as error:
                    self.client().verify(sample_request())
                self.assertNotIn("secret", str(error.exception))
                self.assertTrue(error.exception.__suppress_context__)

    def test_api_failure_is_not_a_verdict(self):
        with patch("app.services.verification.claude_client.Anthropic", side_effect=RuntimeError("secret")):
            with self.assertRaises(VerificationModelError):
                self.client().verify(sample_request())

    def test_missing_key_fails_before_call(self):
        client = ClaudeVerificationClient(VerificationSettings(_env_file=None, CLAUDE_API_KEY=""))
        with self.assertRaisesRegex(VerificationModelError, "configured"):
            client.verify(sample_request())
