import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DB, client_ip, require
from app.core.enums import RiskLevel, RunState
from app.core.rbac import Permission
from app.db.base import utcnow
from app.models.schedule import Schedule, ScheduleRun
from app.models.user import User
from app.schemas.common import Page
from app.schemas.schedule import RunOut, ScheduleFields, ScheduleOut, ScheduleUpdate
from app.services import audit, scheduling

router = APIRouter(tags=["schedules"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Manager = Annotated[User, Depends(require(Permission.ASSESSMENT_RUN))]


def _get(db: Session, schedule_id: uuid.UUID) -> Schedule:
    s = db.get(Schedule, schedule_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    return s


def _out(db: Session, s: Schedule) -> ScheduleOut:
    last = db.scalars(select(ScheduleRun).where(ScheduleRun.schedule_id == s.id)
                      .order_by(ScheduleRun.started_at.desc()).limit(1)).first()
    return ScheduleOut.model_validate(s).model_copy(update={"last_run": RunOut.model_validate(last) if last else None})


def _reschedule(s: Schedule) -> None:
    s.next_run_at = scheduling.compute_next_run(s, utcnow()) if s.enabled else None


def _audit_view(s: Schedule) -> dict:
    return {"schedule": s.name, "target": s.target.value, "frequency": s.frequency.value,
            "time": s.time_of_day, "weekdays": s.weekdays, "minute": s.minute, "timezone": s.timezone,
            "enabled": s.enabled, "ai_report": s.ai_report}


@router.get("/schedules", response_model=list[ScheduleOut])
def list_schedules(_: Viewer, db: DB):
    return [_out(db, s) for s in db.scalars(select(Schedule).order_by(Schedule.name))]


@router.post("/schedules", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
def create_schedule(body: ScheduleFields, user: Manager, request: Request, db: DB):
    data = body.model_dump()
    data["asset_ids"] = [str(x) for x in data["asset_ids"]]
    s = Schedule(id=uuid.uuid4(), created_by_id=user.id, **data)
    _reschedule(s)
    db.add(s)
    audit.record(db, "schedule.create", user=user, source_ip=client_ip(request), risk_level=RiskLevel.LOW,
                 details=_audit_view(s))
    db.commit()
    return _out(db, s)


@router.patch("/schedules/{schedule_id}", response_model=ScheduleOut)
def update_schedule(schedule_id: uuid.UUID, body: ScheduleUpdate, user: Manager, request: Request, db: DB):
    s = _get(db, schedule_id)
    changes = body.model_dump(exclude_unset=True)
    if "asset_ids" in changes:
        changes["asset_ids"] = [str(x) for x in changes["asset_ids"] or []]
    for k, v in changes.items():
        setattr(s, k, v)
    try:
        ScheduleFields.model_validate({**ScheduleOut.model_validate(s).model_dump(), "asset_ids": s.asset_ids})
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    _reschedule(s)
    audit.record(db, "schedule.update", user=user, source_ip=client_ip(request), risk_level=RiskLevel.LOW,
                 details=_audit_view(s))
    db.commit()
    return _out(db, s)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(schedule_id: uuid.UUID, user: Manager, request: Request, db: DB):
    s = _get(db, schedule_id)
    audit.record(db, "schedule.delete", user=user, source_ip=client_ip(request), risk_level=RiskLevel.LOW,
                 details=_audit_view(s))
    db.delete(s)
    db.commit()


@router.post("/schedules/{schedule_id}/run-now", response_model=RunOut, status_code=status.HTTP_202_ACCEPTED)
def run_now(schedule_id: uuid.UUID, user: Manager, request: Request, db: DB):
    s = _get(db, schedule_id)
    if db.scalar(select(ScheduleRun.id).where(ScheduleRun.schedule_id == s.id,
                                              ScheduleRun.state == RunState.RUNNING).limit(1)):
        raise HTTPException(status.HTTP_409_CONFLICT, "This schedule is already running")
    run = scheduling.fire(db, s, trigger="MANUAL", user=user, ip=client_ip(request))
    return RunOut.model_validate(db.get(ScheduleRun, run.id))


@router.get("/schedule-runs", response_model=Page[RunOut])
def list_runs(
    _: Viewer, db: DB,
    schedule_id: uuid.UUID | None = None,
    with_report: bool = False,
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(ScheduleRun)
    if schedule_id:
        stmt = stmt.where(ScheduleRun.schedule_id == schedule_id)
    if with_report:
        stmt = stmt.where(ScheduleRun.ai_state == "DONE")
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(ScheduleRun.started_at.desc()).limit(limit).offset(offset)).all()
    return Page(items=rows, total=total, limit=limit, offset=offset)


@router.get("/schedule-runs/{run_id}", response_model=RunOut)
def get_run(run_id: uuid.UUID, _: Viewer, db: DB):
    run = db.get(ScheduleRun, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Run not found")
    return run

