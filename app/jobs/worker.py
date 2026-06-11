import logging

from rq import Worker

from app.core.config import settings
from app.jobs.queue import get_analysis_queue, get_redis_connection

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_worker() -> None:
    redis_connection = get_redis_connection()
    queue = get_analysis_queue()
    worker = Worker([queue], connection=redis_connection)

    logger.info("Starting analysis worker. queue=%s", settings.ANALYSIS_QUEUE_NAME)
    worker.work()


if __name__ == "__main__":
    run_worker()
