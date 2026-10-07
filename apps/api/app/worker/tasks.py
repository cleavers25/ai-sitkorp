import uuid

from app.db.session import SessionLocal
from app.services.connectivity import check_server_connectivity
from app.worker.celery_app import celery_app


@celery_app.task(name="server.check_connectivity")
def check_connectivity_task(server_id: str, user_id: str | None, source_ip: str | None) -> dict:
    with SessionLocal() as db:
        return check_server_connectivity(
            db, uuid.UUID(server_id), uuid.UUID(user_id) if user_id else None, source_ip
        )


@celery_app.task(name="assessment.run", time_limit=3600, soft_time_limit=3500)
def run_assessment_task(assessment_id: str) -> dict:
    from app.assessment.engine import run_assessment

    with SessionLocal() as db:
        return run_assessment(db, uuid.UUID(assessment_id))


@celery_app.task(name="schedules.tick", ignore_result=True)
def schedules_tick() -> dict:
    from app.services.scheduling import tick

    with SessionLocal() as db:
        result = tick(db)
    for run_id in result["report"]:
        schedule_ai_report.delay(run_id)
    return result


@celery_app.task(name="schedules.ai_report", time_limit=600, soft_time_limit=540)
def schedule_ai_report(run_id: str) -> None:
    from app.ai.report import generate

    with SessionLocal() as db:
        generate(db, uuid.UUID(run_id))


@celery_app.task(name="actions.execute", time_limit=600, soft_time_limit=540)
def execute_action_task(action_id: str) -> dict:
    from app.services.actions import execute

    with SessionLocal() as db:
        return execute(db, uuid.UUID(action_id))


@celery_app.task(name="backups.run", time_limit=4 * 3600, soft_time_limit=4 * 3600 - 60)
def run_backup_task(backup_id: str) -> dict:
    from app.services.backups import run

    with SessionLocal() as db:
        return run(db, uuid.UUID(backup_id))


@celery_app.task(name="notify.deliver", bind=True, max_retries=5, time_limit=120)
def deliver_notification_task(self, delivery_id: str) -> dict:
    from app.services.notify import deliver

    with SessionLocal() as db:
        result = deliver(db, uuid.UUID(delivery_id))
    if result.get("retry_in") and not celery_app.conf.task_always_eager:
        raise self.retry(countdown=result["retry_in"])
    return result


@celery_app.task(name="wazuh.sync", ignore_result=True)
def wazuh_sync_task() -> dict:
    from app.services import wazuh

    with SessionLocal() as db:
        if not wazuh.is_enabled(db):
            return {"skipped": "disabled"}
        try:
            return wazuh.sync_agents(db)
        except wazuh.WazuhError as exc:
            return {"error": str(exc)}


@celery_app.task(name="wazuh.poll", ignore_result=True)
def wazuh_poll_task() -> dict:
    from app.services import wazuh, wazuh_poll

    with SessionLocal() as db:
        try:
            return wazuh_poll.poll(db)
        except wazuh.WazuhError as exc:
            return {"error": str(exc)}
