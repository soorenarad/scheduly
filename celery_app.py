from celery import Celery

celery_app = Celery(
    "scheduler",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/1"
)
celery_app.conf.update(
    timezone="UTC",
    enable_utc=True
)
