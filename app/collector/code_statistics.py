from pathlib import Path

from app.schemas.code_details import CodeDetails
from app.collector.source_files import count_text_lines, iter_source_files

LANGUAGES = {
    '.py': 'Python', '.java': 'Java', '.js': 'JavaScript', '.jsx': 'JavaScript',
    '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.ts': 'TypeScript', '.tsx': 'TypeScript',
    '.go': 'Go', '.rs': 'Rust', '.c': 'C', '.h': 'C', '.cpp': 'C++', '.hpp': 'C++',
    '.cc': 'C++', '.cs': 'C#', '.rb': 'Ruby', '.php': 'PHP', '.kt': 'Kotlin',
    '.kts': 'Kotlin', '.swift': 'Swift', '.scala': 'Scala', '.sh': 'Shell',
    '.bash': 'Shell', '.sql': 'SQL', '.html': 'HTML', '.htm': 'HTML', '.css': 'CSS',
    '.scss': 'SCSS', '.vue': 'Vue', '.svelte': 'Svelte', '.xml': 'XML',
    '.json': 'JSON', '.yaml': 'YAML', '.yml': 'YAML', '.toml': 'TOML',
}
FILENAMES = {'Dockerfile': 'Dockerfile', 'Makefile': 'Makefile'}


def collect_code_details(repo_root: str | Path) -> CodeDetails:
    details = CodeDetails()
    languages = set()
    for path in iter_source_files(repo_root):
        language = FILENAMES.get(path.name) or LANGUAGES.get(path.suffix.lower())
        if language is None:
            continue
        lines = count_text_lines(path)
        if lines is None:
            continue
        details.file_count += 1
        details.line_count += lines
        languages.add(language)
    details.languages = sorted(languages)
    return details
