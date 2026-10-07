"""Queueing assessments; shared by the API (manual/bulk) and the scheduler."""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import AssessmentState, AssetType, RiskLevel
from app.db.base import utcnow
from app.models.assessment import Assessment
from app.models.asset import Asset
from app.models.user import User
from app.services import audit

ACTIVE = (AssessmentState.QUEUED, AssessmentState.RUNNING)
STALE_AFTER = timedelta(hours=2)
SUPPORTED = (AssetType.SERVER, AssetType.WEBSITE)


def as_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)  # SQLite drops tzinfo


def active_assessment(db: Session, asset_id: uuid.UUID) -> Assessment | None:
    """Return the running assessment for an asset, failing stale ones (e.g. worker crashed)."""
    now = utcnow()
    for a in db.scalars(select(Assessment).where(Assessment.asset_id == asset_id, Assessment.state.in_(ACTIVE))):
        if now - as_aware(a.created_at) > STALE_AFTER:
            a.state, a.error, a.finished_at = AssessmentState.FAILED, "Timed out (stale)", now
        else:
            return a
    return None


def enqueue(db: Session, asset: Asset, user: User | None, trigger: str, ip: str | None,
            schedule_run_id: uuid.UUID | None = None) -> Assessment:
    from app.worker.tasks import run_assessment_task  # avoid import cycle with the worker module

    assessment = Assessment(id=uuid.uuid4(), asset_id=asset.id, state=AssessmentState.QUEUED, trigger=trigger,
                            requested_by_id=user.id if user else None, schedule_run_id=schedule_run_id)
    db.add(assessment)
    audit.record(db, "assessment.request", user=user, username=None if user else "scheduler", source_ip=ip,
                 asset_id=asset.id, tool="assessment", risk_level=RiskLevel.SAFE,
                 details={"asset": asset.name, "trigger": trigger, "assessment_id": str(assessment.id)})
    db.commit()
    job = run_assessment_task.delay(str(assessment.id))
    db.refresh(assessment)
    if assessment.task_id is None:
        assessment.task_id = job.id
        db.commit()
    return assessment
