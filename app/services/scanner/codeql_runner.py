import logging
from dataclasses import dataclass
from pathlib import Path
import shutil
import tempfile

from app.core.config import settings
from app.schemas.finding import FindingTool
from app.services.scanner.base import AnalyzerContext, AnalyzerError, RawFinding
from app.services.scanner.codeql_sarif_parser import parse_sarif_file
from app.services.scanner.process_runner import execute_command

logger = logging.getLogger(__name__)
MAX_CODEQL_OUTPUT_CHARS = 1200
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
    build_mode_none: bool = False


@dataclass(frozen=True)
class CodeQLCommandPaths:
    work_dir: Path
    database_dir: Path
    sarif_path: Path


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
        build_mode_none=True,
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

        work_root = create_codeql_analysis_work_root(context.analysis_id)
        try:
            findings: list[RawFinding] = []
            for language in languages:
                paths = build_codeql_command_paths(work_root, language)
                paths.work_dir.mkdir(parents=True, exist_ok=True)

                execute_codeql(
                    build_database_create_command(
                        repository_path,
                        language,
                        paths.database_dir,
                    ),
                    "database create",
                )
                execute_codeql(
                    build_database_analyze_command(
                        language,
                        paths.database_dir,
                        paths.sarif_path,
                    ),
                    "database analyze",
                )
                findings.extend(parse_sarif_file(paths.sarif_path, language))

            logger.info(
                "CodeQL analysis completed. analysis_id=%s finding_count=%s",
                context.analysis_id,
                len(findings),
            )
            return findings
        finally:
            cleanup_codeql_work_root(work_root)


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


# CodeQL 분석 job별 임시 작업 경로를 생성
def create_codeql_analysis_work_root(analysis_id: int) -> Path:
    root_dir = create_codeql_work_root()
    return Path(tempfile.mkdtemp(prefix=f"analysis-{analysis_id}-", dir=root_dir))


# CodeQL language별 database/result 경로를 생성
def build_codeql_command_paths(
    work_root: Path,
    language: CodeQLLanguage,
) -> CodeQLCommandPaths:
    language_dir_name = sanitize_path_segment(language.name)
    work_dir = work_root / language_dir_name
    return CodeQLCommandPaths(
        work_dir=work_dir,
        database_dir=work_dir / "database",
        sarif_path=work_dir / "result.sarif",
    )


# CodeQL database create command를 구성
def build_database_create_command(
    repo_path: Path,
    language: CodeQLLanguage,
    database_dir: Path,
) -> list[str]:
    command = [
        "codeql",
        "database",
        "create",
        str(database_dir),
        f"--language={language.name}",
        f"--source-root={repo_path}",
        "--overwrite",
    ]

    if language.build_mode_none:
        command.append("--build-mode=none")

    return command


# CodeQL CLI command를 실행
def execute_codeql(command: list[str], stage: str) -> str:
    return execute_command(
        command=command,
        stage=f"CodeQL {stage}",
        timeout_seconds=settings.CODEQL_TIMEOUT_SECONDS,
        executable_name="CodeQL",
        max_output_chars=MAX_CODEQL_OUTPUT_CHARS,
    )


# CodeQL 작업 디렉터리를 삭제
def cleanup_codeql_work_root(work_root: Path | None) -> None:
    if work_root is None:
        return

    shutil.rmtree(work_root, ignore_errors=True)


# CodeQL database analyze command를 구성
def build_database_analyze_command(
    language: CodeQLLanguage,
    database_dir: Path,
    sarif_path: Path,
) -> list[str]:
    return [
        "codeql",
        "database",
        "analyze",
        str(database_dir),
        build_query_suite(language),
        "--format=sarif-latest",
        f"--output={sarif_path}",
    ]


# CodeQL query suite spec을 생성
def build_query_suite(language: CodeQLLanguage) -> str:
    return f"{language.query_pack}:codeql-suites/{settings.CODEQL_QUERY_SUITE}.qls"


# 파일 경로 segment에 안전한 문자만 남김
def sanitize_path_segment(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in {"-", "_"} else "-"
        for character in value
    )
