from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "aiinfra",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=["app.worker.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_time_limit=300,
    task_soft_time_limit=240,
    result_expires=86400,
    task_always_eager=settings.celery_task_always_eager,
    # Celery Beat (the "scheduler" service) only emits this heartbeat; schedules live in the database.
    beat_schedule={
        "schedules-tick": {"task": "schedules.tick", "schedule": 60.0},
        "wazuh-sync": {"task": "wazuh.sync", "schedule": 900.0},  # agent list + mapping
        "wazuh-poll": {"task": "wazuh.poll", "schedule": 300.0},  # high-level alerts -> notifications
    },
    timezone="UTC",
)
