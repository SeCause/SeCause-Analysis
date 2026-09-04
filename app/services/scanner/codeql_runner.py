import logging
from dataclasses import dataclass
from pathlib import Path
import tempfile

from app.core.config import settings
from app.schemas.finding import FindingTool
from app.services.scanner.base import AnalyzerContext, AnalyzerError, RawFinding

logger = logging.getLogger(__name__)
EXCLUDED_SCAN_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "out",
    "target",
    "venv",
}


@dataclass(frozen=True)
class CodeQLLanguage:
    name: str
    extensions: tuple[str, ...]
    query_pack: str


SUPPORTED_CODEQL_LANGUAGES = (
    CodeQLLanguage(
        name="python",
        extensions=(".py",),
        query_pack="codeql/python-queries",
    ),
    CodeQLLanguage(
        name="javascript-typescript",
        extensions=(".js", ".jsx", ".ts", ".tsx"),
        query_pack="codeql/javascript-queries",
    ),
    CodeQLLanguage(
        name="java-kotlin",
        extensions=(".java", ".kt", ".kts"),
        query_pack="codeql/java-queries",
    ),
)


class CodeQLRunner:
    tool = FindingTool.CODEQL

    # CodeQL 분석 구조를 준비하고 감지된 언어별 분석 단계로 위임
    def run(self, repo_path: str, context: AnalyzerContext) -> list[RawFinding]:
        repository_path = validate_repository_path(repo_path)
        languages = detect_codeql_languages(repository_path)

        if not languages:
            logger.info(
                "CodeQL analysis skipped. analysis_id=%s reason=no_supported_language",
                context.analysis_id,
            )
            return []

        logger.info(
            "CodeQL analysis skeleton started. analysis_id=%s repository_id=%s languages=%s repo_path=%s",
            context.analysis_id,
            context.repository_id,
            [language.name for language in languages],
            repository_path,
        )

        # 실제 database create/analyze/SARIF parse는 다음 단계에서 language별로 연결
        return []


# CodeQL 실행 대상 repository path를 검증
def validate_repository_path(repo_path: str) -> Path:
    repository_path = Path(repo_path)
    if not repository_path.exists() or not repository_path.is_dir():
        raise AnalyzerError(f"Repository path does not exist: {repo_path}")

    return repository_path


# repository 파일 확장자를 기반으로 CodeQL 지원 언어를 감지
def detect_codeql_languages(repo_path: Path) -> list[CodeQLLanguage]:
    suffixes = collect_source_suffixes(repo_path)

    return [
        language
        for language in SUPPORTED_CODEQL_LANGUAGES
        if any(extension in suffixes for extension in language.extensions)
    ]


# 분석 대상 source file 확장자를 수집
def collect_source_suffixes(repo_path: Path) -> set[str]:
    return {
        path.suffix.lower()
        for path in repo_path.rglob("*")
        if is_source_file_candidate(repo_path, path)
    }


# CodeQL 언어 감지에 사용할 source file 후보인지 판별
def is_source_file_candidate(repo_path: Path, path: Path) -> bool:
    if not path.is_file():
        return False

    relative_parts = path.relative_to(repo_path).parts
    return not any(part in EXCLUDED_SCAN_DIRS for part in relative_parts[:-1])


# CodeQL 작업 root 경로를 생성
def create_codeql_work_root() -> Path:
    configured_root = settings.CODEQL_WORK_ROOT_DIR
    root_dir = (
        Path(configured_root).expanduser()
        if configured_root
        else Path(tempfile.gettempdir()) / "secause-codeql"
    )
    root_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root_dir


# CodeQL query suite spec을 생성
def build_query_suite(language: CodeQLLanguage) -> str:
    return f"{language.query_pack}:codeql-suites/{settings.CODEQL_QUERY_SUITE}.qls"
