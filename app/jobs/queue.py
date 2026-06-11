from functools import lru_cache

from redis import Redis
from rq import Queue

from app.core.config import settings


@lru_cache
def get_redis_connection() -> Redis:
    return Redis.from_url(settings.REDIS_URL)


@lru_cache
def get_analysis_queue() -> Queue:
    return Queue(
        name=settings.ANALYSIS_QUEUE_NAME,
        connection=get_redis_connection(),
    )
