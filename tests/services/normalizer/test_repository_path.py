import tempfile
import unittest
from pathlib import Path

from app.services.normalizer.repository_path import (
    InvalidFindingPath, repository_relative_path, sarif_artifact_path,
)
from app.services.normalizer.finding_normalizer import normalize_findings
from app.services.normalizer.deduplicator import deduplicate_findings
from app.services.scanner.base import RawFinding


class RepositoryPathTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repository"
        self.root.mkdir()
        (self.root / "src").mkdir()
        (self.root / "src" / "한글 file.py").touch()
        (self.root / "internal").symlink_to(self.root / "src", target_is_directory=True)
        (self.root / "external").symlink_to(self.root.parent, target_is_directory=True)

    def test_paths_preserve_structure_and_names(self):
        for path in ["src/한글 file.py", str(self.root / "src/한글 file.py"),
                     "./src/../src/한글 file.py", "src\\한글 file.py", "src//한글 file.py"]:
            with self.subTest(path=path):
                self.assertEqual(repository_relative_path(path, self.root), "src/한글 file.py")

    def test_internal_symlink_keeps_repository_name(self):
        self.assertEqual(repository_relative_path("internal/한글 file.py", self.root), "internal/한글 file.py")

    def test_parent_after_internal_symlink_uses_actual_target(self):
        (self.root / "src/nested").mkdir()
        (self.root / "nested-link").symlink_to(self.root / "src/nested", target_is_directory=True)
        self.assertEqual(repository_relative_path("nested-link/../한글 file.py", self.root), "src/한글 file.py")

    def test_rejects_external_traversal_and_symlinks(self):
        for path in [str(self.root.parent / "outside.py"), "../outside.py", "src/../../x.py",
                     "external/x.py", "external/../repository/src/한글 file.py",
                     "../repository/src/한글 file.py", "", ".", "C:\\src\\x.py", "https://host/x.py"]:
            with self.subTest(path=path), self.assertRaises(InvalidFindingPath):
                repository_relative_path(path, self.root)

    def test_looping_symlink_is_invalid(self):
        (self.root / "loop").symlink_to("loop")
        with self.assertRaises(InvalidFindingPath):
            repository_relative_path("loop/x.py", self.root)

    def test_external_absolute_symlink_pointing_inside_is_invalid(self):
        alias = self.root.parent / "outside-link"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(InvalidFindingPath):
            repository_relative_path(str(alias / "src/한글 file.py"), self.root)

    def test_normalization_before_dedup_isolates_invalid_finding(self):
        def raw(path):
            return RawFinding(tool="SEMGREP", type="SQL", severity="HIGH", file_path=path,
                              message="message /tmp/unchanged", evidence="/tmp/evidence", line_start=1)
        inputs = [raw(str(self.root / "src/한글 file.py")), raw("src/한글 file.py"), raw("../bad")]
        with self.assertLogs("app.services.normalizer.finding_normalizer", level="WARNING"):
            findings = deduplicate_findings(normalize_findings(inputs, self.root))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].file_path, "src/한글 file.py")
        self.assertEqual(findings[0].message, "message /tmp/unchanged")
        self.assertEqual(findings[0].evidence, "/tmp/evidence")
        self.assertEqual(inputs[0].file_path, str(self.root / "src/한글 file.py"))

    def test_uri_formats_and_recursive_base(self):
        uri = (self.root / "src/한글 file.py").as_uri()
        bases = {"ROOT": {"uri": self.root.as_uri() + "/"},
                 "SRC": {"uri": "src/", "uriBaseId": "ROOT"}}
        for artifact in [{"uri": uri}, {"uri": uri.replace("file:///", "file://localhost/")},
                         {"uri": "src/%ED%95%9C%EA%B8%80%20file.py"},
                         {"uri": "%ED%95%9C%EA%B8%80%20file.py", "uriBaseId": "SRC"}]:
            with self.subTest(artifact=artifact):
                self.assertEqual(repository_relative_path(sarif_artifact_path(artifact, bases), self.root),
                                 "src/한글 file.py")

    def test_uri_rejections(self):
        bases = {"A": {"uri": "a/", "uriBaseId": "B"},
                 "B": {"uri": "b/", "uriBaseId": "A"}, "REL": {"uri": "src/"}}
        for artifact in [{"uri": "https://host/src/x.py"}, {"uri": "file://remote/src/x.py"},
                         {"uri": "file:src/x.py"}, {"uri": "file://[bad/x.py"},
                         {"uri": "\nx.py"}, {"uri": "x.py?query"}, {"uri": "x.py#fragment"},
                         {"uri": "%ZZ.py"}, {"uri": "%FF.py"}, {"index": 0},
                         {"uri": "x.py", "uriBaseId": "MISSING"},
                         {"uri": "x.py", "uriBaseId": "A"}, {"uri": "x.py", "uriBaseId": "REL"}]:
            with self.subTest(artifact=artifact), self.assertRaises(InvalidFindingPath):
                sarif_artifact_path(artifact, bases)

    def test_uri_encoded_traversal_and_external_file_are_rejected_at_boundary(self):
        for uri in ["%2e%2e/out.py", self.root.parent.as_uri() + "/out.py"]:
            with self.subTest(uri=uri), self.assertRaises(InvalidFindingPath):
                repository_relative_path(sarif_artifact_path({"uri": uri}, {}), self.root)
