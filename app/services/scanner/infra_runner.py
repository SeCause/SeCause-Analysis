from app.schemas.finding import FindingTool
from app.services.scanner.base import StubAnalyzerRunner


class InfraRunner(StubAnalyzerRunner):
    tool = FindingTool.INFRA

    supported_patterns = (
        "Dockerfile",
        "*.dockerfile",
        "*.yml",
        "*.yaml",
        "*.tf",
    )
