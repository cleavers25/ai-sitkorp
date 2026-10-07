import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from app.core.enums import (
    AssessmentState, AssetStatus, AssetType, CheckStatus, FindingCategory, FindingStatus, Severity,
)
from app.schemas.common import ORMModel


class AssetRef(ORMModel):
    id: uuid.UUID
    name: str
    asset_type: AssetType


class AssessmentOut(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    state: AssessmentState
    overall_status: AssetStatus | None
    trigger: str
    requested_by_id: uuid.UUID | None
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None
    summary: dict[str, Any]
    created_at: datetime


class AssessmentListItem(AssessmentOut):
    asset: AssetRef | None = None


class CheckOut(ORMModel):
    id: uuid.UUID
    position: int
    check: str
    category: FindingCategory
    target: str | None
    status: CheckStatus
    severity: Severity
    title: str
    value: str | None
    evidence: Any
    recommendation: str | None
    duration_ms: int | None
    finding_id: uuid.UUID | None


class AssessmentDetail(AssessmentOut):
    asset: AssetRef
    checks: list[CheckOut]


class FindingOut(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset: AssetRef | None = None
    check: str
    category: FindingCategory
    severity: Severity
    status: FindingStatus
    confidence: float
    title: str
    description: str | None
    target: str | None
    evidence: Any
    recommendation: str | None
    first_seen: datetime
    last_seen: datetime
    first_assessment_id: uuid.UUID | None
    last_assessment_id: uuid.UUID | None
    occurrence_count: int
    reopened_count: int
    resolved_at: datetime | None
    triaged_by_id: uuid.UUID | None
    triaged_at: datetime | None
    triage_note: str | None


class TriageRequest(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class RunAllRequest(BaseModel):
    asset_type: AssetType | None = None


class RunAllOut(BaseModel):
    queued: int
    skipped_active: int
