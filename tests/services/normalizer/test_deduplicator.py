import unittest

from app.schemas.finding import Finding, FindingSeverity, FindingTool
from app.services.normalizer.deduplicator import (
    build_deduplication_key,
    deduplicate_findings,
)
from app.services.normalizer.finding_normalizer import normalize_findings
from app.services.scanner.base import RawFinding


class DeduplicatorTest(unittest.TestCase):
    def test_deduplicate_findings_keeps_unique_findings(self):
        findings = [
            build_finding("CWE-89", "SQL_INJECTION", "src/db.py", 10),
            build_finding("CWE-79", "XSS", "src/view.py", 20),
        ]

        deduplicated = deduplicate_findings(findings)

        self.assertEqual(len(deduplicated), 2)

    def test_build_deduplication_key_prefers_cwe_over_type(self):
        semgrep = build_finding("CWE-89", "SQL_INJECTION", " src/db.py ", 10)
        codeql = build_finding("CWE-89", "SQL_QUERY_BUILT_FROM_USER", "src/db.py", 10)

        self.assertEqual(
            build_deduplication_key(semgrep),
            build_deduplication_key(codeql),
        )

    def test_build_deduplication_key_uses_type_when_cwe_is_missing(self):
        finding = build_finding(None, "SQL_INJECTION", "src/db.py", 10)

        self.assertEqual(
            build_deduplication_key(finding),
            ("sql_injection", "src/db.py", 10),
        )

    def test_deduplicate_findings_keeps_higher_severity(self):
        low = build_finding(
            "CWE-89",
            "SQL_INJECTION",
            "src/db.py",
            10,
            severity=FindingSeverity.LOW,
        )
        high = build_finding(
            "CWE-89",
            "SQL_INJECTION",
            "src/db.py",
            10,
            severity=FindingSeverity.HIGH,
        )

        deduplicated = deduplicate_findings([low, high])

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0].severity, FindingSeverity.HIGH)

    def test_deduplicate_findings_keeps_richer_evidence_on_severity_tie(self):
        short = build_finding("CWE-89", "SQL_INJECTION", "src/db.py", 10, evidence="x")
        rich = build_finding(
            "CWE-89",
            "SQL_INJECTION",
            "src/db.py",
            10,
            evidence="cursor.execute(user_input)",
        )

        deduplicated = deduplicate_findings([short, rich])

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0].evidence, "cursor.execute(user_input)")

    def test_deduplicate_findings_prefers_codeql_on_full_tie(self):
        semgrep = build_finding(
            "CWE-89",
            "SQL_INJECTION",
            "src/db.py",
            10,
            tool=FindingTool.SEMGREP,
            evidence="same",
        )
        codeql = build_finding(
            "CWE-89",
            "SQL_QUERY_BUILT_FROM_USER",
            "src/db.py",
            10,
            tool=FindingTool.CODEQL,
            evidence="same",
        )

        deduplicated = deduplicate_findings([semgrep, codeql])

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0].tool, FindingTool.CODEQL)

    def test_normalize_and_deduplicate_flow_merges_cross_tool_same_cwe(self):
        raw_findings = [
            RawFinding(
                tool=FindingTool.SEMGREP,
                type="SQL_INJECTION",
                severity=FindingSeverity.MEDIUM,
                file_path="src/db.py",
                message="semgrep message",
                cwe_id="CWE-89",
                line_start=10,
                line_end=10,
                evidence="same",
            ),
            RawFinding(
                tool=FindingTool.CODEQL,
                type="SQL_QUERY_BUILT_FROM_USER",
                severity=FindingSeverity.HIGH,
                file_path="src/db.py",
                message="codeql message",
                cwe_id="CWE-89",
                line_start=10,
                line_end=12,
                evidence="same",
            ),
        ]

        deduplicated = deduplicate_findings(normalize_findings(raw_findings))

        self.assertEqual(len(deduplicated), 1)
        self.assertEqual(deduplicated[0].tool, FindingTool.CODEQL)
        self.assertEqual(deduplicated[0].severity, FindingSeverity.HIGH)


def build_finding(
    cwe_id: str | None,
    finding_type: str,
    file_path: str,
    line_start: int | None,
    severity: FindingSeverity = FindingSeverity.MEDIUM,
    tool: FindingTool = FindingTool.SEMGREP,
    evidence: str | None = None,
) -> Finding:
    return Finding(
        tool=tool,
        type=finding_type,
        cwe_id=cwe_id,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        line_end=line_start,
        message="message",
        evidence=evidence,
    )


if __name__ == "__main__":
    unittest.main()
