import tempfile
import unittest
from pathlib import Path

from app.services.llm.source_context import read_source_context


class SourceContextTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        self.path = self.root / "example.py"
        self.path.write_text("\n".join(f"code_{n}" for n in range(1, 41)), encoding="utf-8")

    def test_numbered_finding_and_surrounding_lines(self):
        result = read_source_context(self.root, "example.py", 20, 21)
        self.assertIsNone(result.reason)
        self.assertEqual(result.text.splitlines()[0], "5 | code_5")
        self.assertEqual(result.text.splitlines()[-1], "36 | code_36")
        self.assertIn("20 | code_20\n21 | code_21", result.text)

    def test_file_boundaries_and_single_line(self):
        result = read_source_context(self.root, "example.py", 1)
        self.assertEqual(len(result.text.splitlines()), 16)
        self.assertTrue(result.text.startswith("1 | code_1"))

    def test_invalid_ranges_and_missing_files(self):
        for start, end in [(None, None), (0, None), (3, 2), (41, None), (40, 41)]:
            with self.subTest(start=start, end=end):
                self.assertEqual(read_source_context(self.root, "example.py", start, end).reason,
                                 "invalid_line_range")
        self.assertEqual(read_source_context(self.root, "missing.py", 1).reason, "file_unavailable")

    def test_external_paths_and_symlink_are_rejected(self):
        outside = self.root.parent / "outside.py"
        outside.write_text("private", encoding="utf-8")
        (self.root / "link.py").symlink_to(outside)
        for path in ["../outside.py", str(outside), "link.py"]:
            with self.subTest(path=path):
                result = read_source_context(self.root, path, 1)
                self.assertIsNone(result.text)
                self.assertEqual(result.reason, "invalid_path")

    def test_internal_symlink_and_backslash_filename(self):
        (self.root / "link.py").symlink_to(self.path)
        self.assertIn("1 | code_1", read_source_context(self.root, "link.py", 1).text)
        name = r"a\b.py"
        (self.root / name).write_text("safe()", encoding="utf-8")
        self.assertEqual(read_source_context(self.root, name, 1).text, "1 | safe()")

    def test_binary_encoding_and_size_limits(self):
        for data, reason in [(b"a\x00b", "binary_file"), (b"\xff", "unsupported_encoding")]:
            self.path.write_bytes(data)
            self.assertEqual(read_source_context(self.root, "example.py", 1).reason, reason)
        self.path.write_bytes(b"a" * 11)
        self.assertEqual(read_source_context(self.root, "example.py", 1, max_file_bytes=10).reason,
                         "file_too_large")

    def test_budget_prioritizes_finding_and_never_exceeds_limit(self):
        result = read_source_context(self.root, "example.py", 20, max_chars=25)
        self.assertIn("20 | code_20", result.text)
        self.assertLessEqual(len(result.text), 25)
        self.assertEqual(result.reason, "truncated")
        self.assertEqual(read_source_context(self.root, "example.py", 20, max_chars=2).reason,
                         "finding_range_too_long")

    def test_long_surrounding_line_cannot_leave_a_gap(self):
        self.path.write_text("short\n" + "x" * 100 + "\ntarget\nafter\n", encoding="utf-8")
        result = read_source_context(self.root, "example.py", 3, surrounding_lines=2, max_chars=30)
        self.assertEqual(result.text, "3 | target\n4 | after")
        self.assertEqual(result.reason, "truncated")

    def test_entire_finding_range_must_fit(self):
        result = read_source_context(self.root, "example.py", 20, 23, max_chars=25)
        self.assertIsNone(result.text)
        self.assertEqual(result.reason, "finding_range_too_long")

    def test_exact_budget_and_zero_surrounding_lines(self):
        expected = "20 | code_20\n21 | code_21"
        result = read_source_context(self.root, "example.py", 20, 21,
                                     surrounding_lines=0, max_chars=len(expected))
        self.assertEqual(result.text, expected)
        self.assertIsNone(result.reason)
