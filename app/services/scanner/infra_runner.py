from app.schemas.finding import FindingTool
from app.services.scanner.base import StubAnalyzerRunner


# TODO: 실제 인프라 분석 로직 구현 후 analysis pipeline runner 목록에 재등록
class InfraRunner(StubAnalyzerRunner):
    tool = FindingTool.INFRA

    supported_patterns = (
        "Dockerfile",
        "*.dockerfile",
        "*.yml",
        "*.yaml",
        "*.tf",
    )
