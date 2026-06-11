from typing import Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, SecretStr


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    analysis_id: int = Field(
        validation_alias=AliasChoices("analysisId", "analysis_id"),
    )
    repository_id: int = Field(
        validation_alias=AliasChoices("repositoryId", "repository_id"),
    )
    repository_url: str = Field(
        validation_alias=AliasChoices("repositoryUrl", "repository_url", "github_link"),
    )
    branch: str
    github_token: SecretStr = Field(
        exclude=True,
        repr=False,
        validation_alias=AliasChoices("githubToken", "github_token"),
    )

    def to_job_payload(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "repository_id": self.repository_id,
            "repository_url": self.repository_url,
            "branch": self.branch,
            "github_token": self.github_token.get_secret_value(),
        }


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    accepted: bool
    analysis_id: int = Field(serialization_alias="analysisId")
    job_id: Optional[str] = Field(default=None, serialization_alias="jobId")
    message: str
