"""Recurring assessments (PRD 22).

`tick()` runs every minute from Celery Beat:
  1. fire schedules whose next_run_at has passed → queue assessments for their targets;
  2. close runs whose assessments have all finished → summarise, then ask the AI for a report.
"""

import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.enums import (
    AssessmentState, AssetType, AuditResult, BackupState, JobKind, RiskLevel, RunState, ScheduleFrequency, ScheduleTarget,
)
from app.db.base import utcnow
from app.models.assessment import Assessment
from app.models.asset import Asset, Website
from app.models.backup import Backup
from app.models.schedule import Schedule, ScheduleRun
from app.models.user import User
from app.services import audit
from app.services.assessments import SUPPORTED, active_assessment, as_aware, enqueue

RUN_TIMEOUT = timedelta(hours=3)  # close a run even if some assessments never reported back


def compute_next_run(s: Schedule, after: datetime) -> datetime:
    """Next firing strictly after `after`, evaluated in the schedule's time zone, returned in UTC."""
    tz = ZoneInfo(s.timezone)
    local = as_aware(after).astimezone(tz)
    if s.frequency == ScheduleFrequency.HOURLY:
        cand = local.replace(minute=s.minute, second=0, microsecond=0)
        if cand <= local:
            cand += timedelta(hours=1)
        return cand.astimezone(timezone.utc)

    hh, mm = (int(x) for x in s.time_of_day.split(":"))
    days = sorted(set(s.weekdays)) if s.frequency == ScheduleFrequency.WEEKLY and s.weekdays else list(range(7))
    for offset in range(8):
        day = (local + timedelta(days=offset)).date()
        cand = datetime(day.year, day.month, day.day, hh, mm, tzinfo=tz)
        if cand > local and cand.weekday() in days:
            return cand.astimezone(timezone.utc)
    raise ValueError("schedule has no valid firing time")


def target_assets(db: Session, s: Schedule) -> list[Asset]:
    stmt = select(Asset)
    if s.target == ScheduleTarget.ALL_WEBSITES:
        stmt = stmt.where(Asset.asset_type == AssetType.WEBSITE)
    elif s.target == ScheduleTarget.ALL_SERVERS:
        stmt = stmt.where(Asset.asset_type == AssetType.SERVER)
    elif s.target == ScheduleTarget.ALL_ASSETS:
        stmt = stmt.where(Asset.asset_type.in_(SUPPORTED))
    else:
        ids = []
        for raw in s.asset_ids:
            try:
                ids.append(uuid.UUID(str(raw)))
            except ValueError:
                continue
        stmt = stmt.where(Asset.id.in_(ids), Asset.asset_type.in_(SUPPORTED))
    return list(db.scalars(stmt.order_by(Asset.name)))


def fire(db: Session, s: Schedule, trigger: str = "SCHEDULED", user: User | None = None,
         ip: str | None = None) -> ScheduleRun:
    """Start a run of `s`: queue one assessment per target asset (skipping ones already running)."""
    now = utcnow()
    wants_report = s.ai_report and s.job == JobKind.ASSESSMENT
    run = ScheduleRun(id=uuid.uuid4(), schedule_id=s.id, schedule_name=s.name, job=s.job, trigger=trigger,
                      state=RunState.RUNNING, started_at=now, ai_state="PENDING" if wants_report else "SKIPPED")
    db.add(run)
    s.last_run_at = now
    audit.record(db, "schedule.run", user=user, username=None if user else "scheduler", source_ip=ip,
                 tool="scheduler", risk_level=RiskLevel.SAFE,
                 details={"schedule": s.name, "run_id": str(run.id), "trigger": trigger})
    db.commit()

    queued = skipped = 0
    if s.job == JobKind.BACKUP:
        from app.services import backups
        for site in target_assets(db, s):
            if not isinstance(site, Website) or not site.document_root or not site.server_id:
                skipped += 1
                continue
            backups.start(db, site, user, "SCHEDULED" if trigger == "SCHEDULED" else "SCHEDULE_MANUAL",
                          schedule_run_id=run.id)
            queued += 1
        run = db.get(ScheduleRun, run.id)
        run.queued, run.skipped = queued, skipped
        db.commit()
        return run
    for asset in target_assets(db, s):
        if active_assessment(db, asset.id):
            skipped += 1
            continue
        enqueue(db, asset, user, "SCHEDULED" if trigger == "SCHEDULED" else "SCHEDULE_MANUAL", ip,
                schedule_run_id=run.id)
        queued += 1
    run = db.get(ScheduleRun, run.id)  # enqueue commits; eager tests may already have closed the run
    run.queued, run.skipped = queued, skipped
    db.commit()
    return run


def _close_backup(db: Session, run: ScheduleRun) -> None:
    rows = list(db.scalars(select(Backup).where(Backup.schedule_run_id == run.id)))
    names = {a.id: a.name for a in db.scalars(select(Asset).where(Asset.id.in_({b.asset_id for b in rows})))}
    run.summary = {
        "backups": len(rows),
        "succeeded": sum(b.state == BackupState.SUCCEEDED for b in rows),
        "verified": sum(b.verified for b in rows),
        "failed": [names.get(b.asset_id) for b in rows if b.state != BackupState.SUCCEEDED],
        "total_bytes": sum(b.size_bytes or 0 for b in rows),
    }
    run.state, run.finished_at = RunState.COMPLETED, utcnow()
    audit.record(db, "schedule.run_complete", AuditResult.SUCCESS, username="scheduler", tool="scheduler",
                 details={"schedule": run.schedule_name, "run_id": str(run.id), "summary": run.summary})
    db.commit()


def _close(db: Session, run: ScheduleRun) -> None:
    if run.job == JobKind.BACKUP:
        return _close_backup(db, run)
    assessments = list(db.scalars(select(Assessment).where(Assessment.schedule_run_id == run.id)))
    names = {a.id: a.name for a in db.scalars(select(Asset).where(Asset.id.in_({x.asset_id for x in assessments})))}
    status_counts: dict[str, int] = {}
    worse, new_total, resolved_total, failed = [], 0, 0, []
    for a in assessments:
        if a.state != AssessmentState.COMPLETED:
            failed.append(names.get(a.asset_id, str(a.asset_id)))
            continue
        status_counts[a.overall_status.value] = status_counts.get(a.overall_status.value, 0) + 1
        diff = (a.summary or {}).get("diff", {})
        new_total += diff.get("new", 0)
        resolved_total += diff.get("resolved", 0)
        prev = db.scalars(select(Assessment).where(
            Assessment.asset_id == a.asset_id, Assessment.state == AssessmentState.COMPLETED,
            Assessment.created_at < a.created_at).order_by(Assessment.created_at.desc()).limit(1)).first()
        order = ["GREEN", "YELLOW", "RED"]
        if prev and prev.overall_status and order.index(a.overall_status.value) > order.index(prev.overall_status.value):
            worse.append({"asset": names.get(a.asset_id), "from": prev.overall_status.value, "to": a.overall_status.value})
    run.summary = {"status": status_counts, "new_findings": new_total, "resolved_findings": resolved_total,
                   "worse": worse, "failed": failed, "assessments": len(assessments)}
    run.state = RunState.COMPLETED
    run.finished_at = utcnow()
    audit.record(db, "schedule.run_complete", AuditResult.SUCCESS, username="scheduler", tool="scheduler",
                 details={"schedule": run.schedule_name, "run_id": str(run.id), "summary": run.summary})
    db.commit()


def close_finished_runs(db: Session) -> list[uuid.UUID]:
    """Close runs whose assessments are all done (or that timed out). Returns runs needing an AI report."""
    closed = []
    for run in db.scalars(select(ScheduleRun).where(ScheduleRun.state == RunState.RUNNING)):
        if run.job == JobKind.BACKUP:
            pending = db.scalar(select(Backup.id).where(Backup.schedule_run_id == run.id,
                                                        Backup.state == BackupState.RUNNING).limit(1))
        else:
            pending = db.scalar(select(Assessment.id).where(
                Assessment.schedule_run_id == run.id,
                Assessment.state.in_([AssessmentState.QUEUED, AssessmentState.RUNNING])).limit(1))
        if pending and utcnow() - as_aware(run.started_at) < RUN_TIMEOUT:
            continue
        _close(db, run)
        if run.ai_state == "PENDING":
            closed.append(run.id)
    return closed


def tick(db: Session, now: datetime | None = None) -> dict:
    now = now or utcnow()
    fired = []
    due = db.scalars(select(Schedule).where(Schedule.enabled, Schedule.next_run_at <= now)
                     .with_for_update(skip_locked=True)).all()
    for s in due:
        s.next_run_at = compute_next_run(s, now)  # advance first so a crash never double-fires
        db.commit()
        fired.append(fire(db, s).id)
    return {"fired": [str(x) for x in fired], "report": [str(x) for x in close_finished_runs(db)]}
