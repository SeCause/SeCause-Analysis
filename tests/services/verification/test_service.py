import unittest
from unittest.mock import Mock

from app.schemas.verification import VerificationJudgment, VerificationRequest, VerificationUsage, Verdict
from app.services.verification.claude_client import ModelJudgment, VerificationModelError
from app.services.verification.service import VerificationIntegrityError, validate_judgment, verify_answer
from tests.services.verification.test_schemas import sample_request


def complete_judgment(request):
    return VerificationJudgment.model_validate({"results": [
        {"field": field, "sourceText": text, "claim": text, "verdict": "SUPPORTED",
         "reason": "제공된 코드와 일치", "citations": [{
             "evidenceId": "code-1", "quote": "query = user_input",
         }]}
        for field, text in request.answer.model_dump(by_alias=True).items()
    ]})


class VerificationServiceTest(unittest.TestCase):
    def test_verified_result_includes_metadata(self):
        request = sample_request()
        client = Mock()
        client.verify.return_value = ModelJudgment(complete_judgment(request), "test-model", VerificationUsage())
        result = verify_answer(request, client)
        self.assertEqual(len(result.results), 3)
        self.assertEqual(result.model, "test-model")
        self.assertGreaterEqual(result.duration_ms, 0)
        self.assertTrue(result.prompt_version)

    def test_missing_evidence_does_not_call_model(self):
        payload = sample_request().model_dump()
        payload["evidence"] = []
        client = Mock()
        result = verify_answer(VerificationRequest.model_validate(payload), client)
        client.verify.assert_not_called()
        self.assertTrue(all(item.verdict == Verdict.INSUFFICIENT_EVIDENCE for item in result.results))
        self.assertEqual(result.model, "not-invoked")

    def test_invented_citations_and_omitted_text_are_rejected(self):
        request = sample_request()
        for variant in ("id", "quote", "field", "partial", "source", "uncited"):
            judgment = complete_judgment(request)
            if variant == "id":
                judgment.results[0].citations[0].evidence_id = "invented"
            elif variant == "quote":
                judgment.results[0].citations[0].quote = "invented code"
            elif variant == "field":
                judgment.results.pop()
            elif variant == "partial":
                judgment.results[0].source_text = "SQL"
            elif variant == "source":
                judgment.results[0].source_text = "not in answer"
            else:
                judgment.results[0].citations = []
            with self.subTest(variant=variant), self.assertRaises(VerificationIntegrityError):
                validate_judgment(request, judgment)

    def test_model_failure_is_not_insufficient_evidence(self):
        client = Mock()
        client.verify.side_effect = VerificationModelError("unavailable")
        with self.assertRaises(VerificationModelError):
            verify_answer(sample_request(), client)

    def test_insufficient_evidence_can_have_no_citations(self):
        request = sample_request()
        judgment = complete_judgment(request)
        judgment.results[0].verdict = Verdict.INSUFFICIENT_EVIDENCE
        judgment.results[0].citations = []
        validate_judgment(request, judgment)
