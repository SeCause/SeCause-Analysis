import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from app.schemas.finding import Finding, FindingSeverity, FindingTool
from app.services.rag.hybrid_search import search_evidence_for_findings


class HybridSearchTest(unittest.TestCase):
    def test_multiple_findings_use_one_asyncio_run(self):
        findings = [build_finding("FIRST"), build_finding("SECOND")]
        real_asyncio_run = asyncio.run
        search_loop_ids: list[int] = []

        async def record_search_loop(_query):
            search_loop_ids.append(id(asyncio.get_running_loop()))
            return []

        with patch(
            "app.services.rag.hybrid_search.search_evidence_async",
            new_callable=AsyncMock,
            side_effect=record_search_loop,
        ) as search_evidence_async, patch(
            "app.services.rag.hybrid_search.asyncio.run",
            wraps=real_asyncio_run,
        ) as asyncio_run:
            results = search_evidence_for_findings(findings)

        self.assertEqual(results, [[], []])
        asyncio_run.assert_called_once()
        self.assertEqual(search_evidence_async.await_count, 2)
        self.assertEqual(len(set(search_loop_ids)), 1)


def build_finding(finding_type: str) -> Finding:
    return Finding(
        tool=FindingTool.SEMGREP,
        type=finding_type,
        severity=FindingSeverity.HIGH,
        file_path="src/example.py",
        message="example finding",
    )


if __name__ == "__main__":
    unittest.main()
