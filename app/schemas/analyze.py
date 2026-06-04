from pydantic import BaseModel

class AnalyzeRequest(BaseModel):
    analysis_id: int
    repository_id: int
    github_link: str
    branch: str

class AnalyzeResponse(BaseModel):
    accepted: bool
    analysis_id: int
    message: str