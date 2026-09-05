import json
import tempfile
import unittest
from pathlib import Path

from app.schemas.finding import FindingSeverity, FindingTool
from app.services.scanner.base import AnalyzerError
from app.services.scanner.codeql_runner import CodeQLLanguage
from app.services.scanner.codeql_sarif_parser import (
    map_codeql_severity,
    normalize_rule_type,
    parse_sarif_file,
)


class CodeQLSarifParserTest(unittest.TestCase):
    def test_parse_sarif_file_maps_result_to_raw_finding(self):
        language = CodeQLLanguage(
            name="python",
            extensions=(".py",),
            query_pack="codeql/python-queries",
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_path = Path(tmpdir) / "result.sarif"
            sarif_path.write_text(json.dumps(build_sarif_payload()), encoding="utf-8")

            findings = parse_sarif_file(sarif_path, language)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.tool, FindingTool.CODEQL)
        self.assertEqual(finding.type, "SQL_INJECTION")
        self.assertEqual(finding.severity, FindingSeverity.HIGH)
        self.assertEqual(finding.file_path, "src/db.py")
        self.assertEqual(finding.message, "User input flows into SQL query")
        self.assertEqual(finding.rule_id, "py/sql-injection")
        self.assertEqual(finding.cwe_id, "CWE-89")
        self.assertEqual(finding.line_start, 10)
        self.assertEqual(finding.line_end, 12)
        self.assertEqual(finding.evidence, "cursor.execute(query)")
        self.assertEqual(finding.metadata["language"], "python")

    def test_parse_sarif_file_rejects_invalid_json(self):
        language = CodeQLLanguage("python", (".py",), "codeql/python-queries")

        with tempfile.TemporaryDirectory() as tmpdir:
            sarif_path = Path(tmpdir) / "bad.sarif"
            sarif_path.write_text("{", encoding="utf-8")

            with self.assertRaisesRegex(AnalyzerError, "Failed to parse"):
                parse_sarif_file(sarif_path, language)

    def test_parse_sarif_file_rejects_missing_file(self):
        language = CodeQLLanguage("python", (".py",), "codeql/python-queries")

        with self.assertRaisesRegex(AnalyzerError, "does not exist"):
            parse_sarif_file(Path("/tmp/missing-codeql-output.sarif"), language)

    def test_normalize_rule_type_uses_last_rule_segment(self):
        self.assertEqual(normalize_rule_type("java/xxe.unsafe"), "UNSAFE")

    def test_map_codeql_severity_falls_back_to_sarif_level(self):
        self.assertEqual(
            map_codeql_severity({}, {}, "error"),
            FindingSeverity.HIGH,
        )


def build_sarif_payload() -> dict:
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "py/sql-injection",
                                "properties": {
                                    "tags": ["external/cwe/cwe-089"],
                                    "security-severity": "8.8",
                                },
                            }
                        ]
                    }
                },
                "results": [
                    {
                        "ruleId": "py/sql-injection",
                        "level": "warning",
                        "message": {"text": "User input flows into SQL query"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/db.py"},
                                    "region": {
                                        "startLine": 10,
                                        "endLine": 12,
                                        "snippet": {"text": "cursor.execute(query)"},
                                    },
                                }
                            }
                        ],
                        "properties": {"security-severity": "8.8"},
                        "partialFingerprints": {"primary": "abc"},
                    }
                ],
            }
        ]
    }


if __name__ == "__main__":
    unittest.main()
