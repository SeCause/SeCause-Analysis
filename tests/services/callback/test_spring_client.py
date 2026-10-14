import unittest
from unittest.mock import Mock, patch

import httpx
from pydantic import ValidationError

from app.services.callback.spring_client import (
    AnalysisProgressCallbackPayload, SpringCallbackClient, SpringCallbackError,
    _format_callback_path,
)


class SpringCallbackClientTest(unittest.TestCase):
    def make_client(self):
        client = SpringCallbackClient.__new__(SpringCallbackClient)
        client.base_url = "https://api.secause.site/"
        client.progress_path = "api/internal/analyses/{analysisId}/progress"
        client.timeout_seconds = 10
        client.max_retries = 2
        client.internal_token = "test-token"
        return client

    def test_progress_posts_only_percent_with_internal_token(self):
        client = self.make_client()
        response = httpx.Response(200, request=httpx.Request("POST", client.base_url))
        with patch("app.services.callback.spring_client.httpx.Client") as transport:
            post = transport.return_value.__enter__.return_value.post
            post.return_value = response
            client.send_progress(123, 45)
            transport.assert_called_once_with(timeout=10)
            post.assert_called_once_with(
                "https://api.secause.site/api/internal/analyses/123/progress",
                json={"progressPercent": 45}, headers={"X-Internal-Token": "test-token"},
            )

    def test_progress_payload_rejects_out_of_range_and_non_integer_values(self):
        for value in [-1, 101, 4.5, "45", True]:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                AnalysisProgressCallbackPayload(progress_percent=value)

    def test_progress_retries_network_failure_then_succeeds(self):
        client = self.make_client()
        response = httpx.Response(200, request=httpx.Request("POST", client.base_url))
        with patch("app.services.callback.spring_client.httpx.Client") as transport, patch(
            "app.services.callback.spring_client.time.sleep"
        ) as sleep:
            post = transport.return_value.__enter__.return_value.post
            post.side_effect = [httpx.ConnectError("offline"), response]
            client.send_progress(123, 45)
            self.assertEqual(post.call_count, 2)
            sleep.assert_called_once_with(1)

    def test_progress_retry_is_bounded(self):
        client = self.make_client()
        with patch("app.services.callback.spring_client.httpx.Client") as transport, patch(
            "app.services.callback.spring_client.time.sleep"
        ):
            post = transport.return_value.__enter__.return_value.post
            post.side_effect = httpx.ConnectError("offline")
            with self.assertRaises(SpringCallbackError):
                client.send_progress(123, 45)
            self.assertEqual(post.call_count, 3)

    def test_progress_does_not_retry_unauthorized(self):
        client = self.make_client()
        with patch("app.services.callback.spring_client.httpx.Client") as transport:
            post = transport.return_value.__enter__.return_value.post
            post.return_value = httpx.Response(401, request=httpx.Request("POST", client.base_url))
            with self.assertRaises(SpringCallbackError):
                client.send_progress(123, 45)
            self.assertEqual(post.call_count, 1)

    def test_callback_path_replaces_analysis_id_placeholder(self):
        self.assertEqual(
            _format_callback_path(
                "/api/internal/analyses/{analysisId}/result",
                123,
            ),
            "/api/internal/analyses/123/result",
        )


if __name__ == "__main__":
    unittest.main()
