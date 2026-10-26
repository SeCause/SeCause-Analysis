import unittest

from scripts.evaluate_verification import label_match
from tests.services.verification.test_schemas import sample_request
from tests.services.verification.test_service import complete_judgment


class EvaluationTest(unittest.TestCase):
    def test_missing_compound_claim_is_not_counted_as_matching(self):
        judgment = complete_judgment(sample_request())
        expected = {field: ["SUPPORTED"] for field in ("summary", "rootCause", "impact")}
        self.assertTrue(label_match(judgment, expected))
        expected['summary'].append('INSUFFICIENT_EVIDENCE')
        self.assertFalse(label_match(judgment, expected))

