from typing import Optional

from app.schemas.base import AnalysisRequestPayload, CamelModel


class AnalyzeRequest(AnalysisRequestPayload):
    pass


class AnalyzeResponse(CamelModel):
    accepted: bool
    analysis_id: int
    job_id: Optional[str] = None
    message: str
