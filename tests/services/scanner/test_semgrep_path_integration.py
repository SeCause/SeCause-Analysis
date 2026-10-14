"""Offline CLI check; requires semgrep on PATH, never downloads registry rules."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.services.scanner.semgrep_runner import build_semgrep_command, parse_semgrep_output
from app.services.normalizer.finding_normalizer import normalize_findings


@unittest.skipUnless(shutil.which("semgrep"), "Semgrep CLI is not installed")
class SemgrepPathIntegrationTest(unittest.TestCase):
    def test_actual_absolute_and_repository_relative_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "repository"
            source = root / "src" / "한글 file.py"
            source.parent.mkdir(parents=True)
            source.write_text("eval(input())\n", encoding="utf-8")
            config = Path(tmp) / "rule.yaml"
            config.write_text("rules:\n- id: local-eval\n  languages: [python]\n  severity: ERROR\n  message: unsafe eval\n  pattern: eval(...)\n", encoding="utf-8")
            env = {**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0",
                   "SEMGREP_SEND_METRICS": "off", "SEMGREP_USER_DATA_FOLDER": str(Path(tmp) / "data")}
            for target in [root, Path(".")]:
                with self.subTest(target=target), patch(
                    "app.services.scanner.semgrep_runner.settings.SEMGREP_CONFIG", str(config),
                ):
                    command = build_semgrep_command(target)
                    command[0] = shutil.which("semgrep")
                    result = subprocess.run(command, cwd=root, env=env, capture_output=True,
                                            text=True, timeout=60)
                    self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
                    raw = parse_semgrep_output(result.stdout)
                    self.assertEqual(len(raw), 1, result.stderr)
                    self.assertEqual(raw[0].file_path, str(source) if target.is_absolute() else "src/한글 file.py")
                    self.assertEqual(normalize_findings(raw, root)[0].file_path, "src/한글 file.py")
