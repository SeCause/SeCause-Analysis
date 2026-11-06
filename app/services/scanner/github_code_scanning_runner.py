import subprocess
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

from app.schemas.finding import FindingTool
from app.services.scanner.base import AnalyzerContext, AnalyzerError, RawFinding
from app.services.scanner.github_code_scanning_client import (
    fetch_codeql_findings,
    find_codeql_analysis_ids,
)


class CodeQLAnalysisUnavailable(AnalyzerError):
    pass


class GitHubCodeScanningRunner:
    tool = FindingTool.CODEQL

    def __init__(self, repository_url: str, github_token: SecretStr) -> None:
        self._repository_url = repository_url
        self._github_token = github_token

    def run(self, repo_path: str, context: AnalyzerContext) -> list[RawFinding]:
        url = urlsplit(self._repository_url)
        parts = url.path.strip("/").removesuffix(".git").split("/")
        if url.scheme != "https" or url.hostname != "github.com" or len(parts) != 2 or not all(parts):
            raise CodeQLAnalysisUnavailable("GitHub Code Scanning requires a GitHub.com repository")
        owner, repository = parts

        try:
            commit_sha = subprocess.run(
                ["git", "-C", repo_path, "rev-parse", "--verify", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            raise AnalyzerError("Could not resolve the cloned commit SHA") from None

        token = self._github_token.get_secret_value()
        with httpx.Client(timeout=10) as client:
            analysis_ids = find_codeql_analysis_ids(
                client,
                owner=owner,
                repository=repository,
                branch=context.branch,
                commit_sha=commit_sha,
                github_token=token,
            )
            if not analysis_ids:
                raise CodeQLAnalysisUnavailable("No completed CodeQL analysis for the cloned commit")
            return fetch_codeql_findings(
                client,
                owner=owner,
                repository=repository,
                analysis_ids=analysis_ids,
                github_token=token,
            )
