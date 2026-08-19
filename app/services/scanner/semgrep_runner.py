from app.schemas.finding import FindingTool
from app.services.scanner.base import StubAnalyzerRunner


class SemgrepRunner(StubAnalyzerRunner):
    tool = FindingTool.SEMGREP
