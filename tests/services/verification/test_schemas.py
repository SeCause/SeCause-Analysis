import unittest

from pydantic import ValidationError

from app.schemas.verification import VerificationRequest


def sample_request():
    return VerificationRequest.model_validate({
        "answer": {"summary": "SQL 위험", "rootCause": "입력을 연결함", "impact": "조회 가능"},
        "evidence": [{"evidenceId": "code-1", "kind": "CODE", "content": "query = user_input"}],
    })


class VerificationSchemaTest(unittest.TestCase):
    def test_camel_case_round_trip_and_empty_evidence(self):
        request = sample_request()
        payload = request.model_dump(by_alias=True, mode="json")
        self.assertEqual(payload["answer"]["rootCause"], "입력을 연결함")
        self.assertEqual(VerificationRequest.model_validate(payload), request)
        payload["evidence"] = []
        self.assertEqual(VerificationRequest.model_validate(payload).evidence, [])

    def test_blank_unknown_and_oversized_fields_are_rejected(self):
        for field, value in [("summary", "  "), ("summary", "x" * 4001), ("extra", "x")]:
            payload = sample_request().model_dump(by_alias=True)
            payload["answer"][field] = value
            with self.subTest(field=field, size=len(value)), self.assertRaises(ValidationError):
                VerificationRequest.model_validate(payload)

    def test_invalid_evidence_kind_is_rejected(self):
        payload = sample_request().model_dump(by_alias=True)
        payload["evidence"][0]["kind"] = "UNKNOWN"
        with self.assertRaises(ValidationError):
            VerificationRequest.model_validate(payload)
