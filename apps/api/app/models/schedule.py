import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import JobKind, RunState, ScheduleFrequency, ScheduleTarget
from app.db.base import Base, JSONType, Timestamps, UUIDPrimaryKey, enum_column


class Schedule(UUIDPrimaryKey, Timestamps, Base):
    """Recurring assessment of a set of assets, optionally followed by an AI report (PRD 22)."""

    __tablename__ = "schedules"

    name: Mapped[str] = mapped_column(String(128))
    enabled: Mapped[bool] = mapped_column(default=True)
    job: Mapped[JobKind] = mapped_column(enum_column(JobKind), default=JobKind.ASSESSMENT)
    target: Mapped[ScheduleTarget] = mapped_column(enum_column(ScheduleTarget))
    asset_ids: Mapped[list[str]] = mapped_column(JSONType, default=list)  # for SELECTED
    frequency: Mapped[ScheduleFrequency] = mapped_column(enum_column(ScheduleFrequency))
    time_of_day: Mapped[str] = mapped_column(String(5), default="02:00")  # HH:MM (DAILY/WEEKLY)
    weekdays: Mapped[list[int]] = mapped_column(JSONType, default=list)  # 0=Monday (WEEKLY)
    minute: Mapped[int] = mapped_column(Integer, default=0)  # HOURLY
    timezone: Mapped[str] = mapped_column(String(64), default="Asia/Jakarta")
    ai_report: Mapped[bool] = mapped_column(default=True)
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class ScheduleRun(UUIDPrimaryKey, Timestamps, Base):
    """One firing of a schedule: the assessments it queued and the AI report written afterwards."""

    __tablename__ = "schedule_runs"

    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("schedules.id", ondelete="SET NULL"), index=True
    )
    schedule_name: Mapped[str] = mapped_column(String(128))
    job: Mapped[JobKind] = mapped_column(enum_column(JobKind), default=JobKind.ASSESSMENT)
    trigger: Mapped[str] = mapped_column(String(16), default="SCHEDULED")  # SCHEDULED | MANUAL
    state: Mapped[RunState] = mapped_column(enum_column(RunState), default=RunState.RUNNING, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    queued: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    # Status counts, new/resolved findings, assets that got worse… (computed when the run closes).
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    ai_report: Mapped[str | None] = mapped_column(Text)
    ai_state: Mapped[str | None] = mapped_column(String(16))  # PENDING | DONE | FAILED | SKIPPED
    ai_error: Mapped[str | None] = mapped_column(Text)
    ai_usage: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
