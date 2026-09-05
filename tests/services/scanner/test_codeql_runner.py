import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.scanner.base import AnalyzerContext, AnalyzerError
from app.services.scanner.codeql_runner import (
    CodeQLRunner,
    SUPPORTED_CODEQL_LANGUAGES,
    build_query_suite,
    cleanup_codeql_work_root,
    create_codeql_analysis_work_root,
)


class CodeQLRunnerTest(unittest.TestCase):
    def test_run_executes_codeql_and_cleans_work_directory(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir) / "repo"
            repo_path.mkdir()
            (repo_path / "app.py").write_text("print('hello')", encoding="utf-8")
            work_root = Path(tmpdir) / "codeql-work"

            with patch(
                "app.services.scanner.codeql_runner.settings.CODEQL_WORK_ROOT_DIR",
                str(work_root),
            ), patch(
                "app.services.scanner.codeql_runner.execute_codeql",
                side_effect=write_empty_sarif_on_analyze,
            ) as execute:
                findings = CodeQLRunner().run(
                    str(repo_path),
                    AnalyzerContext(analysis_id=7, repository_id=3, branch="main"),
                )

            self.assertEqual(findings, [])
            self.assertEqual(execute.call_count, 2)
            self.assertFalse(list(work_root.glob("analysis-7-*")))

    def test_cleanup_removes_only_analysis_work_directory_under_codeql_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            codeql_root = Path(tmpdir) / "codeql-work"

            with patch(
                "app.services.scanner.codeql_runner.settings.CODEQL_WORK_ROOT_DIR",
                str(codeql_root),
            ):
                analysis_root = create_codeql_analysis_work_root(10)
                marker = analysis_root / "marker"
                marker.write_text("ok", encoding="utf-8")

                cleanup_codeql_work_root(analysis_root)

            self.assertFalse(analysis_root.exists())

    def test_cleanup_rejects_path_outside_codeql_root(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            outside_path = Path(tmpdir) / "analysis-10-danger"
            outside_path.mkdir()
            codeql_root = Path(tmpdir) / "codeql-work"

            with patch(
                "app.services.scanner.codeql_runner.settings.CODEQL_WORK_ROOT_DIR",
                str(codeql_root),
            ):
                with self.assertRaisesRegex(AnalyzerError, "Unsafe CodeQL"):
                    cleanup_codeql_work_root(outside_path)

            self.assertTrue(outside_path.exists())

    def test_build_query_suite_uses_language_specific_suite_file(self):
        suites = {
            language.name: build_query_suite(language)
            for language in SUPPORTED_CODEQL_LANGUAGES
        }

        self.assertEqual(
            suites["python"],
            "codeql/python-queries:codeql-suites/python-security-extended.qls",
        )
        self.assertEqual(
            suites["javascript-typescript"],
            "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        )
        self.assertEqual(
            suites["java-kotlin"],
            "codeql/java-queries:codeql-suites/java-security-extended.qls",
        )


def write_empty_sarif_on_analyze(command: list[str], stage: str) -> str:
    if stage != "database analyze":
        return ""

    output_arg = next(item for item in command if item.startswith("--output="))
    sarif_path = Path(output_arg.removeprefix("--output="))
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    sarif_path.write_text(
        json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}),
        encoding="utf-8",
    )
    return ""


if __name__ == "__main__":
    unittest.main()
