from pydantic import AliasChoices, BaseModel, ConfigDict, Field, SecretStr


def to_camel(value: str) -> str:
    words = value.split("_")
    return words[0] + "".join(word.capitalize() for word in words[1:])


class CamelModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
    )


class AnalysisTargetPayload(CamelModel):
    analysis_id: int
    repository_id: int
    repository_url: str = Field(
        validation_alias=AliasChoices("repositoryUrl", "repository_url", "github_link"),
    )
    branch: str


class AnalysisRequestPayload(AnalysisTargetPayload):
    github_token: SecretStr = Field(
        exclude=True,
        repr=False,
        validation_alias=AliasChoices("githubToken", "github_token"),
    )

    def to_job_payload(self, github_token_reference: str) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "repository_id": self.repository_id,
            "repository_url": self.repository_url,
            "branch": self.branch,
            "github_token_reference": github_token_reference,
        }
