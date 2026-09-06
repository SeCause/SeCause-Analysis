import unittest

from app.schemas.finding import FindingSeverity, FindingTool
from app.services.normalizer.finding_normalizer import (
    UnknownFindingToolError,
    normalize_finding,
    normalize_findings,
)
from app.services.scanner.base import RawFinding


class FindingNormalizerTest(unittest.TestCase):
    def test_normalize_findings_maps_common_raw_fields(self):
        raw_finding = RawFinding(
            tool=FindingTool.SEMGREP,
            type="SQL_INJECTION",
            severity=FindingSeverity.HIGH,
            file_path="src/db.py",
            message="User input flows into SQL query",
            rule_id="python.sql-injection",
            cwe_id="CWE-89",
            line_start=10,
            line_end=12,
            evidence="cursor.execute(query)",
        )

        findings = normalize_findings([raw_finding])

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.tool, FindingTool.SEMGREP)
        self.assertEqual(finding.type, "SQL_INJECTION")
        self.assertEqual(finding.severity, FindingSeverity.HIGH)
        self.assertEqual(finding.file_path, "src/db.py")
        self.assertEqual(finding.message, "User input flows into SQL query")
        self.assertEqual(finding.cwe_id, "CWE-89")
        self.assertEqual(finding.line_start, 10)
        self.assertEqual(finding.line_end, 12)
        self.assertEqual(finding.evidence, "cursor.execute(query)")

    def test_normalize_finding_uses_fallbacks_for_blank_required_fields(self):
        raw_finding = RawFinding(
            tool=FindingTool.CODEQL,
            type=" ",
            severity=FindingSeverity.INFO,
            file_path=" ",
            message=" ",
            rule_id="py/sql-injection",
            cwe_id=" ",
            line_start=0,
            line_end=-1,
            evidence=" ",
        )

        finding = normalize_finding(raw_finding)

        self.assertEqual(finding.type, "py/sql-injection")
        self.assertEqual(finding.file_path, "unknown")
        self.assertEqual(finding.message, "py/sql-injection")
        self.assertIsNone(finding.cwe_id)
        self.assertIsNone(finding.line_start)
        self.assertIsNone(finding.line_end)
        self.assertIsNone(finding.evidence)

    def test_normalize_finding_falls_back_to_tool_type_without_rule_id(self):
        raw_finding = RawFinding(
            tool=FindingTool.INFRA,
            type=" ",
            severity=FindingSeverity.LOW,
            file_path="Dockerfile",
            message=" ",
        )

        finding = normalize_finding(raw_finding)

        self.assertEqual(finding.type, "INFRA_FINDING")
        self.assertEqual(finding.message, "INFRA_FINDING")

    def test_normalize_finding_coerces_invalid_severity_to_info(self):
        raw_finding = RawFinding.model_construct(
            tool=FindingTool.CODEQL,
            type="SQL_INJECTION",
            severity="INVALID",
            file_path="src/db.py",
            message="message",
        )

        finding = normalize_finding(raw_finding)

        self.assertEqual(finding.severity, FindingSeverity.INFO)

    def test_normalize_finding_clamps_reversed_line_range(self):
        raw_finding = RawFinding(
            tool=FindingTool.SEMGREP,
            type="SQL_INJECTION",
            severity=FindingSeverity.HIGH,
            file_path="src/db.py",
            message="message",
            line_start=12,
            line_end=10,
        )

        finding = normalize_finding(raw_finding)

        self.assertEqual(finding.line_start, 12)
        self.assertEqual(finding.line_end, 12)

    def test_normalize_finding_rejects_unknown_tool(self):
        raw_finding = RawFinding.model_construct(
            tool="UNKNOWN",
            type="SQL_INJECTION",
            severity=FindingSeverity.HIGH,
            file_path="src/db.py",
            message="message",
        )

        with self.assertRaisesRegex(UnknownFindingToolError, "Unsupported finding tool"):
            normalize_finding(raw_finding)


if __name__ == "__main__":
    unittest.main()
