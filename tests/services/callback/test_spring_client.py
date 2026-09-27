import unittest

from app.services.callback.spring_client import _format_callback_path


class SpringCallbackClientTest(unittest.TestCase):
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
