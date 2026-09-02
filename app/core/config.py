from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    # Database
    DATABASE_URL: str
    
    # Claude API
    CLAUDE_API_KEY: str

    # Embedding
    EMBEDDING_PROVIDER: str = "openai"
    EMBEDDING_MODEL: str = "text-embedding-3-small"
    EMBEDDING_DIMENSION: int = 1536
    EMBEDDING_BATCH_SIZE: int = 64
    OPENAI_API_KEY: str | None = None

    # RAG Search
    RAG_VECTOR_TOP_K: int = 10
    RAG_FTS_TOP_K: int = 10
    RAG_RESULT_TOP_K: int = 5
    RAG_RRF_K: int = 60

    # Queue
    REDIS_URL: str = "redis://localhost:6379/0"
    ANALYSIS_QUEUE_NAME: str = "analysis"
    GITHUB_TOKEN_TTL_SECONDS: int = 3600
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    DEBUG: bool = False


settings = Settings()
