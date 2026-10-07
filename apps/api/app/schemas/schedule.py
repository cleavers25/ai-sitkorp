import re
import uuid
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.enums import JobKind, RunState, ScheduleFrequency, ScheduleTarget
from app.schemas.common import ORMModel

_HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


def _check_tz(v: str | None) -> str | None:
    if v is None:
        return v
    try:
        ZoneInfo(v)
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("unknown time zone (use e.g. Asia/Jakarta)")
    return v


def _check_time(v: str | None) -> str | None:
    if v is not None and not _HHMM.match(v):
        raise ValueError("time_of_day must be HH:MM (24h)")
    return v


def _check_days(v: list[int] | None) -> list[int] | None:
    if v is not None and any(d not in range(7) for d in v):
        raise ValueError("weekdays must be 0 (Monday) … 6 (Sunday)")
    return sorted(set(v)) if v is not None else v


class ScheduleFields(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    job: JobKind = JobKind.ASSESSMENT
    target: ScheduleTarget = ScheduleTarget.ALL_WEBSITES
    asset_ids: list[uuid.UUID] = Field(default_factory=list, max_length=1000)
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY
    time_of_day: str = "02:00"
    weekdays: list[int] = Field(default_factory=list)
    minute: int = Field(default=0, ge=0, le=59)
    timezone: str = "Asia/Jakarta"
    ai_report: bool = True

    _tz = field_validator("timezone")(_check_tz)
    _time = field_validator("time_of_day")(_check_time)
    _days = field_validator("weekdays")(_check_days)

    @model_validator(mode="after")
    def _consistent(self):
        if self.frequency == ScheduleFrequency.WEEKLY and not self.weekdays:
            raise ValueError("weekly schedules need at least one weekday")
        if self.target == ScheduleTarget.SELECTED and not self.asset_ids:
            raise ValueError("choose at least one asset for target SELECTED")
        return self


class ScheduleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    job: JobKind | None = None
    target: ScheduleTarget | None = None
    asset_ids: list[uuid.UUID] | None = None
    frequency: ScheduleFrequency | None = None
    time_of_day: str | None = None
    weekdays: list[int] | None = None
    minute: int | None = Field(default=None, ge=0, le=59)
    timezone: str | None = None
    ai_report: bool | None = None

    _tz = field_validator("timezone")(_check_tz)
    _time = field_validator("time_of_day")(_check_time)
    _days = field_validator("weekdays")(_check_days)


class RunOut(ORMModel):
    id: uuid.UUID
    schedule_id: uuid.UUID | None
    schedule_name: str
    job: JobKind
    trigger: str
    state: RunState
    started_at: datetime
    finished_at: datetime | None
    queued: int
    skipped: int
    summary: dict[str, Any]
    ai_report: str | None
    ai_state: str | None
    ai_error: str | None
    ai_usage: dict[str, Any]


class ScheduleOut(ORMModel):
    id: uuid.UUID
    name: str
    enabled: bool
    job: JobKind
    target: ScheduleTarget
    asset_ids: list[str]
    frequency: ScheduleFrequency
    time_of_day: str
    weekdays: list[int]
    minute: int
    timezone: str
    ai_report: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    created_at: datetime
    last_run: RunOut | None = None
