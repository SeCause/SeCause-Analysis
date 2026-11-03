"""Shared repository candidate policy for statistics and scanner language detection.

Prune excluded directories at every depth; never follow any symlink. Lockfiles
are excluded. Gitignore and scanner-specific rules are not applied here.
Unreadable paths raise rather than silently producing a partial inventory.
"""
import os
from collections.abc import Iterator
from pathlib import Path

EXCLUDED_DIRECTORIES = {
    '.git', '.hg', '.svn', 'node_modules', 'vendor', 'bower_components',
    '.venv', 'venv', 'env', '__pycache__', '.tox', '.mypy_cache', '.pytest_cache',
    'build', 'dist', 'target', 'out', 'coverage', '.next', '.nuxt', '.gradle',
}
LOCKFILES = {'package-lock.json', 'npm-shrinkwrap.json', 'composer.lock', 'Pipfile.lock'}


def iter_source_files(repo_root: str | Path) -> Iterator[Path]:
    root = Path(repo_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Source inventory requires a real repository directory')

    def fail(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=fail):
        dirs[:] = [name for name in dirs if name not in EXCLUDED_DIRECTORIES
                   and not (Path(directory) / name).is_symlink()]
        for name in files:
            path = Path(directory) / name
            if name not in LOCKFILES and not path.is_symlink() and path.is_file():
                yield path


def count_text_lines(path: Path) -> int | None:
    """Count physical lines in UTF-8 text; return None for binary/non-UTF-8 data.

    Include blank/comment lines and a final unterminated line; empty files have
    zero lines. Decoding uses utf-8-sig so a UTF-8 BOM does not affect the result.
    """
    lines = 0
    try:
        with path.open(encoding='utf-8-sig') as stream:
            for line in stream:
                if any(ord(char) < 32 and char not in '\t\n\r\f' for char in line):
                    return None
                lines += 1
    except UnicodeError:
        return None
    return lines
