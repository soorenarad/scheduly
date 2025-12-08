from celery import Celery
from setting import settings

celery_app = Celery(
    "scheduler",
    broker=f"redis://{settings.Redis_host}:{settings.Redis_port}/0",
    backend=f"redis://{settings.Redis_host}:{settings.Redis_port}/1"
)
celery_app.conf.update(
    timezone="UTC",
    enable_utc=True
)
