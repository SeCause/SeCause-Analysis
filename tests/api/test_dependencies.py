import unittest
from unittest.mock import patch

from fastapi import HTTPException

from app.api.dependencies import verify_internal_token


class InternalTokenDependencyTest(unittest.TestCase):
    def test_matching_token_is_accepted(self):
        with patch(
            "app.api.dependencies.settings.ANALYSIS_CALLBACK_INTERNAL_TOKEN",
            "shared-secret",
        ):
            self.assertIsNone(verify_internal_token("shared-secret"))

    def test_missing_or_mismatched_token_returns_401(self):
        with patch(
            "app.api.dependencies.settings.ANALYSIS_CALLBACK_INTERNAL_TOKEN",
            "shared-secret",
        ):
            for provided_token in (None, "wrong-secret"):
                with self.subTest(provided_token=provided_token):
                    with self.assertRaises(HTTPException) as raised:
                        verify_internal_token(provided_token)
                    self.assertEqual(raised.exception.status_code, 401)
                    self.assertEqual(raised.exception.detail, "Unauthorized")

    def test_non_ascii_tokens_are_compared_without_type_error(self):
        with patch(
            "app.api.dependencies.settings.ANALYSIS_CALLBACK_INTERNAL_TOKEN",
            "공유-비밀",
        ):
            self.assertIsNone(verify_internal_token("공유-비밀"))

            with self.assertRaises(HTTPException) as raised:
                verify_internal_token("다른-비밀")

        self.assertEqual(raised.exception.status_code, 401)

    def test_empty_configuration_skips_authentication_with_warning(self):
        with patch(
            "app.api.dependencies.settings.ANALYSIS_CALLBACK_INTERNAL_TOKEN",
            "",
        ), self.assertLogs("app.api.dependencies", level="WARNING") as logs:
            self.assertIsNone(verify_internal_token(None))

        self.assertIn("authentication is disabled", logs.output[0])


if __name__ == "__main__":
    unittest.main()
