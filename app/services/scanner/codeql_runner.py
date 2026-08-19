from app.schemas.finding import FindingTool
from app.services.scanner.base import StubAnalyzerRunner


class CodeQLRunner(StubAnalyzerRunner):
    tool = FindingTool.CODEQL
