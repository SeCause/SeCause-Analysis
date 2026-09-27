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

    def test_multiple_findings_query_database_on_same_event_loop(self):
        findings = [build_finding("FIRST"), build_finding("SECOND")]
        database_loop_ids: list[int] = []
        session_factory = FakeAsyncSessionFactory(database_loop_ids)

        with patch(
            "app.core.database.AsyncSessionLocal",
            session_factory,
        ), patch(
            "app.services.rag.hybrid_search.OpenAIEmbedder",
        ) as embedder:
            embedder.return_value.embed_query.return_value = [0.0]
            results = search_evidence_for_findings(findings, analysis_id=11)

        self.assertEqual(results, [[], []])
        self.assertEqual(session_factory.call_count, 2)
        self.assertEqual(len(database_loop_ids), 4)
        self.assertEqual(len(set(database_loop_ids)), 1)

    def test_finding_progress_is_logged(self):
        findings = [build_finding("FIRST"), build_finding("SECOND")]

        with patch(
            "app.services.rag.hybrid_search.search_evidence_async",
            new_callable=AsyncMock,
            return_value=[],
        ), self.assertLogs(
            "app.services.rag.hybrid_search",
            level="INFO",
        ) as logs:
            search_evidence_for_findings(findings, analysis_id=11)

        output = "\n".join(logs.output)
        self.assertIn("analysis_id=11 finding_index=1 finding_total=2", output)
        self.assertIn("analysis_id=11 finding_index=2 finding_total=2", output)
        self.assertIn("Finding RAG search completed", output)


class FakeAsyncSessionFactory:
    def __init__(self, loop_ids: list[int]):
        self.loop_ids = loop_ids
        self.call_count = 0

    def __call__(self):
        self.call_count += 1
        return FakeAsyncSessionContext(self.loop_ids)


class FakeAsyncSessionContext:
    def __init__(self, loop_ids: list[int]):
        self.session = FakeAsyncSession(loop_ids)

    async def __aenter__(self):
        return self.session

    async def __aexit__(self, exc_type, exc_value, traceback):
        return False


class FakeAsyncSession:
    def __init__(self, loop_ids: list[int]):
        self.loop_ids = loop_ids

    async def execute(self, _query, _parameters):
        self.loop_ids.append(id(asyncio.get_running_loop()))
        return FakeQueryResult()


class FakeQueryResult:
    def mappings(self):
        return []


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
