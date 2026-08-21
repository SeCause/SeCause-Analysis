from collections.abc import Sequence
from dataclasses import dataclass


class EmbeddingConfigurationError(RuntimeError):
    pass


class EmbeddingProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class EmbeddingResult:
    text: str
    embedding: list[float]


class OpenAIEmbedder:
    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        dimension: int | None = None,
        batch_size: int | None = None,
    ) -> None:
        embedding_settings = get_embedding_settings()
        self.api_key = api_key if api_key is not None else embedding_settings["api_key"]
        self.model = model or embedding_settings["model"]
        self.dimension = dimension or embedding_settings["dimension"]
        self.batch_size = batch_size or embedding_settings["batch_size"]

        if not self.api_key:
            raise EmbeddingConfigurationError("OPENAI_API_KEY is required")

        if self.batch_size <= 0:
            raise EmbeddingConfigurationError("EMBEDDING_BATCH_SIZE must be positive")

        self.client = create_openai_client(self.api_key)

    # 문서 색인용 embedding 생성
    def embed_documents(self, texts: Sequence[str]) -> list[EmbeddingResult]:
        return self._embed(texts)

    # 검색 query용 embedding 생성
    def embed_query(self, text: str) -> list[float]:
        results = self._embed([text])
        return results[0].embedding

    # OpenAI embedding API 배치 호출
    def _embed(self, texts: Sequence[str]) -> list[EmbeddingResult]:
        cleaned_texts = [text.strip() for text in texts if text.strip()]
        if not cleaned_texts:
            return []

        results: list[EmbeddingResult] = []
        for batch in batched(cleaned_texts, self.batch_size):
            results.extend(self._embed_batch(batch))

        return results

    # 단일 batch embedding 처리
    def _embed_batch(self, texts: list[str]) -> list[EmbeddingResult]:
        try:
            response = self.client.embeddings.create(
                model=self.model,
                input=texts,
                dimensions=self.dimension,
            )
        except Exception as exc:
            raise EmbeddingProviderError("OpenAI embedding request failed") from exc

        embeddings_by_index = {
            item.index: item.embedding
            for item in response.data
        }

        return [
            EmbeddingResult(
                text=text,
                embedding=validate_embedding_dimension(
                    embeddings_by_index[index],
                    self.dimension,
                ),
            )
            for index, text in enumerate(texts)
        ]


# sequence를 고정 크기 batch로 분할
def batched(values: Sequence[str], batch_size: int) -> list[list[str]]:
    return [
        list(values[index : index + batch_size])
        for index in range(0, len(values), batch_size)
    ]


# OpenAI SDK client 생성
def create_openai_client(api_key: str):
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise EmbeddingConfigurationError(
            "openai package is required for OpenAI embeddings"
        ) from exc

    return OpenAI(api_key=api_key)


# 앱 설정 지연 로딩
def get_embedding_settings() -> dict:
    from app.core.config import settings

    return {
        "api_key": settings.OPENAI_API_KEY,
        "model": settings.EMBEDDING_MODEL,
        "dimension": settings.EMBEDDING_DIMENSION,
        "batch_size": settings.EMBEDDING_BATCH_SIZE,
    }


# embedding 차원 검증
def validate_embedding_dimension(
    embedding: list[float],
    expected_dimension: int,
) -> list[float]:
    if len(embedding) != expected_dimension:
        raise EmbeddingProviderError(
            f"Embedding dimension mismatch. expected={expected_dimension} actual={len(embedding)}"
        )

    return embedding
