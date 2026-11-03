import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.collector.code_statistics import collect_code_details
from app.collector.source_files import EXCLUDED_DIRECTORIES


class CodeStatisticsTest(unittest.TestCase):
    def test_inventory_includes_clean_files_and_counts_physical_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'clean.js').write_bytes(b'// comment\r\n\r\nsafe();')
            (root / 'clean.ts').write_text('const safe: boolean = true;\n')
            (root / 'empty.py').touch()
            (root / 'README.md').write_text('not source')
            (root / 'package-lock.json').write_text('{}')
            details = collect_code_details(root)
        self.assertEqual(details.model_dump(by_alias=True), {
            'fileCount': 3, 'lineCount': 4,
            'languages': ['JavaScript', 'Python', 'TypeScript'],
        })

    def test_excludes_nested_directories_binary_and_all_symlinks(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / 'src').mkdir()
            (root / 'src/main.py').write_text('safe()\n')
            for name in EXCLUDED_DIRECTORIES:
                excluded = root / 'src' / name
                excluded.mkdir()
                (excluded / 'ignored.py').write_text('unsafe()')
            (root / 'binary.py').write_bytes(b'hello\x00world')
            (root / 'encoded.js').write_bytes(b'\xff\xfe')
            (root / 'control.ts').write_bytes(b'abc\x01')
            (root / 'alias.py').symlink_to(root / 'src/main.py')
            (root / 'alias-dir').symlink_to(root / 'src', target_is_directory=True)
            (root / 'external.py').symlink_to(Path(outside) / 'missing.py')
            self.assertEqual(collect_code_details(root).file_count, 1)
            from app.services.scanner.codeql_runner import detect_codeql_languages
            self.assertEqual([language.name for language in detect_codeql_languages(root)], ['python'])

    def test_unreadable_files_fail_instead_of_silent_partial_totals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'main.py').touch()
            with patch.object(Path, 'open', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    collect_code_details(root)

    def test_config_special_names_and_empty_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(collect_code_details(root).model_dump(by_alias=True), {
                'fileCount': 0, 'lineCount': 0, 'languages': [],
            })
            (root / 'Dockerfile').write_text('FROM python:3.11\n')
            (root / 'config.yaml').write_bytes(b'\xef\xbb\xbfsecure: true\n')
            (root / 'unknown.xyz').write_text('unknown')
            self.assertEqual(collect_code_details(root).model_dump(by_alias=True), {
                'fileCount': 2, 'lineCount': 2, 'languages': ['Dockerfile', 'YAML'],
            })

    def test_invalid_root_and_root_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'link').symlink_to(root, target_is_directory=True)
            for path in [root / 'missing', root / 'link']:
                with self.assertRaises(ValueError):
                    collect_code_details(path)

    def test_codeql_does_not_detect_languages_from_excluded_or_linked_sources(self):
        from app.services.scanner.codeql_runner import detect_codeql_languages

        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            for name in EXCLUDED_DIRECTORIES:
                excluded = root / name
                excluded.mkdir()
                (excluded / 'ignored.py').write_text('safe()')
            external = Path(outside) / 'external.java'
            external.write_text('class External {}')
            (root / 'external.java').symlink_to(external)
            (root / 'binary.ts').write_bytes(b'\x00binary')
            self.assertEqual(detect_codeql_languages(root), [])
            self.assertEqual(collect_code_details(root).file_count, 0)
