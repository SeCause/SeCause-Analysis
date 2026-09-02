from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    # Database
    DATABASE_URL: str
    
    # Claude API
    CLAUDE_API_KEY: str
    CLAUDE_MODEL: str = "claude-sonnet-4-6"
    CLAUDE_TIMEOUT_SECONDS: float = 30.0
    CLAUDE_MAX_OUTPUT_TOKENS: int = 1200
    CLAUDE_MAX_RETRIES: int = 2

    # LLM Context Budget
    LLM_EVIDENCE_TOP_K: int = 5
    LLM_MAX_EVIDENCE_CHARS: int = 1200
    LLM_MAX_TOTAL_EVIDENCE_CHARS: int = 6000

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

    # Spring Callback
    SPRING_CALLBACK_BASE_URL: str = "http://localhost:8080"
    SPRING_SUCCESS_CALLBACK_PATH: str = "/internal/analysis/callback/success"
    SPRING_FAILURE_CALLBACK_PATH: str = "/internal/analysis/callback/failure"
    SPRING_CALLBACK_TIMEOUT_SECONDS: float = 10.0
    SPRING_CALLBACK_MAX_RETRIES: int = 2
    ANALYSIS_CALLBACK_INTERNAL_TOKEN: str | None = None
    
    # Git clone
    GIT_CLONE_ROOT_DIR: str = "/tmp/secause-analysis"
    GIT_CLONE_TIMEOUT_SECONDS: int = 120
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    DEBUG: bool = False


settings = Settings()
