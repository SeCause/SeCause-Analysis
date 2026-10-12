"""Dedicated JSON queue; existing analysis workers do not consume these jobs."""

from functools import lru_cache

from redis import Redis
from rq import Queue
from rq.serializers import JSONSerializer

from app.services.verification.config import get_verification_settings

VERIFICATION_QUEUE_NAME = "answer-verification"


@lru_cache
def get_verification_redis() -> Redis:
    return Redis.from_url(get_verification_settings().REDIS_URL)


def get_verification_queue() -> Queue:
    return Queue(
        VERIFICATION_QUEUE_NAME,
        connection=get_verification_redis(),
        serializer=JSONSerializer,
    )
