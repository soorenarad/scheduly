from celery import Celery
import os
from dotenv import load_dotenv

load_dotenv()

# Get Redis connection details from environment variables
redis_host = os.getenv("Redis_host", "localhost")
redis_port = os.getenv("Redis_port", "6379")

celery_app = Celery(
    "scheduler",
    broker=f"redis://{redis_host}:{redis_port}/0",
    backend=f"redis://{redis_host}:{redis_port}/1"
)
celery_app.conf.update(
    timezone="UTC",
    enable_utc=True
)
