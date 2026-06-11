from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    # Database
    DATABASE_URL: str
    
    # Claude API
    CLAUDE_API_KEY: str

    # Queue
    REDIS_URL: str = "redis://localhost:6379/0"
    ANALYSIS_QUEUE_NAME: str = "analysis"
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8001
    DEBUG: bool = False


settings = Settings()
