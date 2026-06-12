from celery import Celery
from argus.core.config import settings

celery_app = Celery(
    "argus",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=["argus.worker.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Seoul",
    enable_utc=True,
)
