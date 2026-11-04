import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DatabaseInitTest(unittest.TestCase):
    def run_init(self, directory, schema):
        root = Path(directory)
        executable = root / 'psql'
        executable.write_text('#!/bin/sh\ncat "$8" > "$CAPTURED_SQL"\n')
        executable.chmod(0o755)
        return subprocess.run(['sh', str(ROOT / 'scripts/local/init-db.sh')],
            env={**os.environ, 'PATH': str(root) + os.pathsep + os.environ['PATH'],
                 'BACKEND_SCHEMA_FILE': str(schema), 'POSTGRES_USER': 'test',
                 'POSTGRES_DB': 'test', 'CAPTURED_SQL': str(root / 'executed.sql')},
            capture_output=True, text=True)

    def test_missing_schema_never_executes_psql(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_init(directory, Path(directory) / 'missing.sql')
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(directory) / 'executed.sql').exists())

    def test_only_extension_and_enum_preamble_is_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            schema = root / 'schema.sql'
            schema.write_text('CREATE EXTENSION vector@@\nALTER TABLE users ADD test int@@\n')
            result = self.run_init(directory, schema)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'executed.sql').read_text(), 'CREATE EXTENSION vector;\n')
