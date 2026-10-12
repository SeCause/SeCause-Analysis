import unittest

from app.schemas.verification import VerificationRequest
from app.services.verification.rules import VerificationInputError, validate_verification_request
from tests.services.verification.test_schemas import sample_request


class VerificationRulesTest(unittest.TestCase):
    def request_with(self, evidence):
        payload = sample_request().model_dump(by_alias=True)
        payload["evidence"] = evidence
        return VerificationRequest.model_validate(payload)

    def test_absent_evidence_is_not_malformed(self):
        validate_verification_request(self.request_with([]))

    def test_duplicate_ids_are_rejected(self):
        evidence = sample_request().model_dump(by_alias=True)["evidence"]
        with self.assertRaisesRegex(VerificationInputError, "unique"):
            validate_verification_request(self.request_with(evidence * 2))

    def test_line_ranges_require_code_path_and_order(self):
        original = sample_request().model_dump(by_alias=True)["evidence"][0]
        for changes in [
            {"lineStart": 1},
            {"lineStart": 1, "lineEnd": 2},
            {"lineStart": 5, "lineEnd": 2, "filePath": "app.py"},
            {"kind": "DOCUMENT", "lineStart": 1, "lineEnd": 2, "filePath": "app.py"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(VerificationInputError):
                validate_verification_request(self.request_with([{**original, **changes}]))
        validate_verification_request(self.request_with([
            {**original, "lineStart": 1, "lineEnd": 2, "filePath": "app.py"}
        ]))

    def test_total_limit_counts_utf8_bytes(self):
        evidence = [
            {"evidenceId": f"doc-{index}", "kind": "DOCUMENT", "content": "가" * 12000}
            for index in range(2)
        ]
        with self.assertRaisesRegex(VerificationInputError, "UTF-8"):
            validate_verification_request(self.request_with(evidence))
