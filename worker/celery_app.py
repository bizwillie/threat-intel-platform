"""
Celery Application Configuration

Configures Celery for async threat intelligence processing.
"""

import os
from celery import Celery
from dotenv import load_dotenv

load_dotenv()

# Celery app configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

app = Celery(
    "utip_worker",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["tasks.document_processing"]
)

# Celery configuration
app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,

    # Task routing
    task_routes={
        "tasks.document_processing.*": {"queue": "intel"},
    },

    # Task execution
    task_track_started=True,
    task_time_limit=600,  # 10 minutes max per task
    task_soft_time_limit=540,  # 9 minute soft limit

    # Result backend
    result_expires=3600,  # Results expire after 1 hour
    result_extended=True,

    # Worker configuration
    worker_prefetch_multiplier=1,  # One task at a time
    worker_max_tasks_per_child=100,  # Restart worker after 100 tasks
)

if __name__ == "__main__":
    app.start()
