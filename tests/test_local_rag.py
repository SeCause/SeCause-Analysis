from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from scripts.index_rag_documents import load_documents
from scripts.local.prepare_rag import prepare_owasp


def fake_clone(command, **kwargs):
    checkout = Path(command[-1])
    (checkout / 'cheatsheets').mkdir(parents=True)
    (checkout / 'cheatsheets/First.md').write_text('# First\nEvidence')
    (checkout / 'cheatsheets/Second.md').write_text('# Second\nEvidence')
    (checkout / 'LICENSE.md').write_text('upstream license')


class LocalRagTest(unittest.TestCase):
    def test_owasp_only_uses_custom_root_without_cwe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'owasp').mkdir()
            (root / 'owasp/Guide.md').write_text('# Local guide\nEvidence')
            self.assertEqual([doc.title for doc in load_documents(root, 'owasp')], ['Local guide'])
            with self.assertRaises(FileNotFoundError):
                load_documents(root, 'all')

    def test_cwe_only_does_not_require_owasp(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'cwe').mkdir()
            (root / 'cwe/cwe.xml').write_text(
                '<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">'
                '<Weaknesses><Weakness ID="79" Name="XSS"/></Weaknesses></Weakness_Catalog>')
            self.assertEqual([doc.source_id for doc in load_documents(root, 'cwe')], ['CWE-79'])

    def test_missing_or_license_only_owasp_is_not_silently_indexed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                load_documents(root, 'owasp')
            (root / 'owasp').mkdir()
            (root / 'owasp/LICENSE.md').write_text('license')
            with self.assertRaises(FileNotFoundError):
                load_documents(root, 'owasp')

    def test_failed_copy_is_not_published_and_retry_prepares_every_document(self):
        real_copy = shutil.copy2
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def interrupted(source, destination):
                if Path(source).name == 'Second.md':
                    raise OSError('copy interrupted')
                return real_copy(source, destination)
            with patch('scripts.local.prepare_rag.subprocess.run', side_effect=fake_clone), patch(
                'scripts.local.prepare_rag.shutil.copy2', side_effect=interrupted
            ):
                with self.assertRaises(OSError):
                    prepare_owasp(root)
            self.assertFalse((root / 'owasp').exists())
            with patch('scripts.local.prepare_rag.subprocess.run', side_effect=fake_clone):
                prepare_owasp(root)
            self.assertEqual({doc.source_id for doc in load_documents(root, 'owasp')}, {'First', 'Second'})

    def test_license_only_directory_is_completed_without_overwriting_user_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'owasp').mkdir()
            (root / 'owasp/LICENSE.md').write_text('user license')
            (root / 'owasp/notes.txt').write_text('user notes')
            with patch('scripts.local.prepare_rag.subprocess.run', side_effect=fake_clone):
                prepare_owasp(root)
            self.assertEqual((root / 'owasp/LICENSE.md').read_text(), 'user license')
            self.assertEqual((root / 'owasp/notes.txt').read_text(), 'user notes')
            self.assertEqual(len(load_documents(root, 'owasp')), 2)

    def test_user_managed_documents_are_preserved_without_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'owasp').mkdir()
            (root / 'owasp/Custom.md').write_text('# Custom\nUser content')
            with patch('scripts.local.prepare_rag.subprocess.run') as clone:
                prepare_owasp(root)
            clone.assert_not_called()
            self.assertEqual((root / 'owasp/Custom.md').read_text(), '# Custom\nUser content')

    def test_interrupted_directory_swap_recovers_user_documents(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.owasp-backup').mkdir()
            (root / '.owasp-backup/Custom.md').write_text('# Preserved')
            with patch('scripts.local.prepare_rag.subprocess.run') as clone:
                prepare_owasp(root)
            clone.assert_not_called()
            self.assertEqual((root / 'owasp/Custom.md').read_text(), '# Preserved')
