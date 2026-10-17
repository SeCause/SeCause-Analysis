import unittest
from unittest.mock import patch
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from redis.exceptions import ConnectionError

from app.api.routes import verifications
from app.schemas.verification import VerificationAccepted, VerificationResponse, VerificationStatus
from app.services.verification.config import VerificationSettings
from app.services.verification.rules import VerificationInputError
from app.services.verification.tasks import VerificationNotFoundError
from tests.services.verification.test_schemas import sample_request

BASE_URL = "/api/internal/answer-verifications"


class VerificationApiTest(unittest.TestCase):
    def setUp(self):
        app = FastAPI()
        app.include_router(verifications.router, prefix="/api")
        self.client = TestClient(app)
        self.headers = {"X-Internal-Token": "test-secret"}
        self.payload = sample_request().model_dump(by_alias=True, mode="json")
        self.settings = VerificationSettings(_env_file=None, ANALYSIS_CALLBACK_INTERNAL_TOKEN="test-secret")
        patcher = patch.object(verifications, "get_verification_settings", return_value=self.settings)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.client.close)

    def test_accepts_request_and_returns_identifier(self):
        identifier = uuid4()
        with patch.object(verifications, "enqueue_verification", return_value=VerificationAccepted(
            verification_id=identifier,
        )) as enqueue:
            response = self.client.post(BASE_URL, headers=self.headers, json=self.payload)
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json(), {"verificationId": str(identifier), "status": "QUEUED"})
        self.assertEqual(enqueue.call_args.args[0], sample_request())

    def test_both_endpoints_require_token(self):
        for headers in ({}, {"X-Internal-Token": "wrong"}):
            with self.subTest(headers=headers), patch.object(verifications, "enqueue_verification") as enqueue:
                response = self.client.post(BASE_URL, headers=headers, json=self.payload)
                self.assertEqual(response.status_code, 401)
                self.assertEqual(self.client.get(f"{BASE_URL}/{uuid4()}", headers=headers).status_code, 401)
                enqueue.assert_not_called()

    def test_missing_configuration_fails_closed(self):
        self.settings.ANALYSIS_CALLBACK_INTERNAL_TOKEN = ""
        self.assertEqual(self.client.post(BASE_URL, headers=self.headers, json=self.payload).status_code, 503)
        self.assertEqual(self.client.get(f"{BASE_URL}/{uuid4()}", headers=self.headers).status_code, 503)

    def test_invalid_input_is_rejected_before_enqueue(self):
        self.payload["answer"]["summary"] = ""
        with patch.object(verifications, "enqueue_verification") as enqueue:
            response = self.client.post(BASE_URL, headers=self.headers, json=self.payload)
        self.assertEqual(response.status_code, 422)
        enqueue.assert_not_called()

    def test_rule_failure_and_queue_failure(self):
        for error, expected in [(VerificationInputError("Duplicate IDs"), 422), (ConnectionError("secret"), 503)]:
            with patch.object(verifications, "enqueue_verification", side_effect=error):
                response = self.client.post(BASE_URL, headers=self.headers, json=self.payload)
            self.assertEqual(response.status_code, expected)
            self.assertNotIn("secret", response.text)

    def test_result_lookup_and_errors(self):
        identifier = uuid4()
        with patch.object(verifications, "get_verification", return_value=VerificationResponse(
            verification_id=identifier, status=VerificationStatus.RUNNING,
        )):
            response = self.client.get(f"{BASE_URL}/{identifier}", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"verificationId": str(identifier), "status": "RUNNING"})
        for error, expected in [(VerificationNotFoundError(), 404), (ConnectionError("secret"), 503)]:
            with patch.object(verifications, "get_verification", side_effect=error):
                self.assertEqual(self.client.get(f"{BASE_URL}/{identifier}", headers=self.headers).status_code, expected)
        self.assertEqual(self.client.get(f"{BASE_URL}/invalid", headers=self.headers).status_code, 422)

    def test_main_registers_both_analysis_and_verification(self):
        from app.main import app

        paths = app.openapi()["paths"]
        self.assertIn("/api/internal/analyze", paths)
        self.assertIn(BASE_URL, paths)
        self.assertIn(f"{BASE_URL}/{{verification_id}}", paths)
