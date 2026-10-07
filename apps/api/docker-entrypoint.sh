#!/bin/sh
set -e

case "$1" in
  api)
    alembic upgrade head
    exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips='*'
    ;;
  worker)
    exec celery -A app.worker.celery_app worker --loglevel=INFO --concurrency="${WORKER_CONCURRENCY:-4}"
    ;;
  scheduler)
    exec celery -A app.worker.celery_app beat --loglevel=INFO --schedule /tmp/celerybeat-schedule
    ;;
  migrate)
    exec alembic upgrade head
    ;;
  *)
    exec "$@"
    ;;
esac
