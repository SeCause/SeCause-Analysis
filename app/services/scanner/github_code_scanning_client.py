from urllib.parse import quote

import httpx

from app.services.scanner.base import RawFinding
from app.services.scanner.codeql_sarif_parser import parse_sarif_payload


class CodeScanningLookupError(RuntimeError):
    pass


def find_codeql_analysis_ids(
    client: httpx.Client,
    *,
    owner: str,
    repository: str,
    branch: str,
    commit_sha: str,
    github_token: str,
) -> list[int]:
    """Return successful CodeQL analyses for the exact branch and commit."""
    ref = f"refs/heads/{branch}"
    url = _analyses_url(owner, repository)
    analysis_ids: list[int] = []
    page = 1
    while True:
        response, analyses = _get_json(
            client, url, github_token, "application/vnd.github+json",
            params={"ref": ref, "tool_name": "CodeQL", "per_page": 100, "page": page},
        )

        if not isinstance(analyses, list) or any(
            not isinstance(analysis, dict) for analysis in analyses
        ):
            raise CodeScanningLookupError("Invalid GitHub Code Scanning response")

        for analysis in analyses:
            if (
                analysis.get("ref") == ref
                and analysis.get("commit_sha") == commit_sha
                and analysis.get("error") == ""
            ):
                analysis_id = analysis.get("id")
                if type(analysis_id) is not int:
                    raise CodeScanningLookupError("Invalid GitHub Code Scanning analysis ID")
                analysis_ids.append(analysis_id)

        if "next" not in response.links:
            return analysis_ids
        page += 1


def fetch_codeql_findings(
    client: httpx.Client,
    *,
    owner: str,
    repository: str,
    analysis_ids: list[int],
    github_token: str,
) -> list[RawFinding]:
    """Read the SARIF snapshot of each previously matched analysis."""
    url = _analyses_url(owner, repository)
    findings: list[RawFinding] = []
    for analysis_id in analysis_ids:
        _, payload = _get_json(
            client, f"{url}/{analysis_id}", github_token, "application/sarif+json",
        )
        findings.extend(parse_sarif_payload(payload))
    return findings


def _analyses_url(owner: str, repository: str) -> str:
    slug = f"{quote(owner, safe='')}/{quote(repository, safe='')}"
    return f"https://api.github.com/repos/{slug}/code-scanning/analyses"


def _get_json(
    client: httpx.Client,
    url: str,
    github_token: str,
    accept: str,
    *,
    params: dict[str, str | int] | None = None,
) -> tuple[httpx.Response, object]:
    try:
        response = client.get(
            url,
            headers={"Accept": accept, "Authorization": f"Bearer {github_token}"},
            params=params,
            follow_redirects=False,
        )
        response.raise_for_status()
        return response, response.json()
    except httpx.HTTPStatusError as exc:
        raise CodeScanningLookupError(
            f"GitHub Code Scanning lookup returned HTTP {exc.response.status_code}"
        ) from None
    except (httpx.RequestError, ValueError):
        raise CodeScanningLookupError("GitHub Code Scanning lookup failed") from None
