import json
import unittest

from app.schemas.finding import FindingSeverity, FindingTool
from app.services.scanner.base import AnalyzerError
from app.services.scanner.semgrep_runner import parse_semgrep_output


class SemgrepRunnerTest(unittest.TestCase):
    def test_parse_semgrep_output_maps_result_to_raw_finding(self):
        payload = {
            "results": [
                {
                    "check_id": "python.sql-injection",
                    "path": "src/db.py",
                    "start": {"line": 10},
                    "end": {"line": 12},
                    "extra": {
                        "message": "User input flows into SQL query",
                        "severity": "ERROR",
                        "lines": "cursor.execute(query)",
                        "fingerprint": "abc",
                        "metadata": {"cwe": "CWE-89"},
                    },
                }
            ]
        }

        findings = parse_semgrep_output(json.dumps(payload))

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.tool, FindingTool.SEMGREP)
        self.assertEqual(finding.type, "SQL_INJECTION")
        self.assertEqual(finding.severity, FindingSeverity.HIGH)
        self.assertEqual(finding.file_path, "src/db.py")
        self.assertEqual(finding.cwe_id, "CWE-89")
        self.assertEqual(finding.line_start, 10)
        self.assertEqual(finding.line_end, 12)
        self.assertEqual(finding.evidence, "cursor.execute(query)")
        self.assertEqual(finding.metadata["fingerprint"], "abc")

    def test_parse_semgrep_output_rejects_array_root(self):
        with self.assertRaisesRegex(AnalyzerError, "root must be an object"):
            parse_semgrep_output("[]")

    def test_parse_semgrep_output_rejects_null_root(self):
        with self.assertRaisesRegex(AnalyzerError, "root must be an object"):
            parse_semgrep_output("null")

    def test_parse_semgrep_output_rejects_non_list_results(self):
        with self.assertRaisesRegex(AnalyzerError, "results must be a list"):
            parse_semgrep_output('{"results": {}}')

    def test_parse_semgrep_output_rejects_null_result_item(self):
        with self.assertRaisesRegex(AnalyzerError, "result must be an object"):
            parse_semgrep_output('{"results": [null]}')

    def test_parse_semgrep_output_rejects_null_extra(self):
        with self.assertRaisesRegex(AnalyzerError, "extra must be an object"):
            parse_semgrep_output('{"results": [{"extra": null}]}')


if __name__ == "__main__":
    unittest.main()
