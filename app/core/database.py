from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings
import logging

logger = logging.getLogger(__name__)

# 비동기 엔진 생성
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    pool_pre_ping=True,  # 연결 상태 확인
)

# 비동기 세션 팩토리
AsyncSessionLocal = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

# ORM 모델의 베이스 클래스
Base = declarative_base()


async def init_db():
    """
    데이터베이스 초기화
    (테이블 생성은 하지 않음 — 기존 테이블 사용)
    """
    async with engine.begin() as conn:
        logger.info("Database connection test successful")


async def get_db() -> AsyncSession:
    """
    의존성 주입용 DB 세션 반환
    FastAPI route에서 사용: async def route(db: AsyncSession = Depends(get_db))
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()