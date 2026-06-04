from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI

from app.api.routes import analyze
from app.core.config import settings
from app.core.database import engine, init_db

# 로깅 설정
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    logger.info("FastAPI Server Starting...")
    try:
        await init_db()
        logger.info("Database connection initialized")
    except Exception as e:
        logger.error("Database connection failed: %s", e)
        raise

    yield

    logger.info("FastAPI Server Shutting down...")
    try:
        await engine.dispose()
        logger.info("Database connections closed")
    except Exception as e:
        logger.error("Error during shutdown: %s", e)


# FastAPI 앱 생성
app = FastAPI(
    title="SeCause Analysis Server",
    description="Security Analysis Pipeline for SeCause",
    version="0.1.0",
    lifespan=lifespan,
)

# 라우터 등록
app.include_router(analyze.router, prefix="/api", tags=["analyze"])


# Health Check 엔드포인트
@app.get("/health", tags=["health"])
async def health_check():
    """
    서버 헬스 체크
    """
    return {
        "status": "ok",
        "service": "SeCause Analysis Server",
        "version": "0.1.0",
    }


# Root 엔드포인트
@app.get("/", tags=["root"])
async def root():
    """
    루트 경로
    """
    return {
        "message": "SeCause Analysis Server",
        "docs": "/docs",
        "health": "/health",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level="info",
    )
