import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import (
    AssessmentState, AssetStatus, CheckStatus, FindingCategory, FindingStatus, Severity,
)
from app.db.base import Base, JSONType, Timestamps, UUIDPrimaryKey, enum_column, utcnow


class Assessment(UUIDPrimaryKey, Timestamps, Base):
    """One assessment run against one asset (PRD 9, 40). Kept forever for history/diffing."""

    __tablename__ = "assessments"

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    state: Mapped[AssessmentState] = mapped_column(
        enum_column(AssessmentState), default=AssessmentState.QUEUED, index=True
    )
    overall_status: Mapped[AssetStatus | None] = mapped_column(enum_column(AssetStatus))
    trigger: Mapped[str] = mapped_column(String(32), default="MANUAL")
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    task_id: Mapped[str | None] = mapped_column(String(64))
    schedule_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("schedule_runs.id", ondelete="SET NULL"), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    # Severity counts, check counts and the diff against the previous run.
    summary: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)

    checks: Mapped[list["AssessmentCheck"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", order_by="AssessmentCheck.position"
    )


class AssessmentCheck(UUIDPrimaryKey, Base):
    """Standardised result of a single check (PRD 40)."""

    __tablename__ = "assessment_checks"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer, default=0)
    check: Mapped[str] = mapped_column(String(64))
    category: Mapped[FindingCategory] = mapped_column(enum_column(FindingCategory))
    target: Mapped[str | None] = mapped_column(String(1024))
    status: Mapped[CheckStatus] = mapped_column(enum_column(CheckStatus))
    severity: Mapped[Severity] = mapped_column(enum_column(Severity), default=Severity.INFO)
    title: Mapped[str] = mapped_column(String(255))
    value: Mapped[str | None] = mapped_column(String(255))
    evidence: Mapped[Any] = mapped_column(JSONType, default=dict)
    recommendation: Mapped[str | None] = mapped_column(Text)
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))

    assessment: Mapped[Assessment] = relationship(back_populates="checks")


class Finding(UUIDPrimaryKey, Timestamps, Base):
    """A de-duplicated issue on an asset, tracked across assessments (PRD 39, 51)."""

    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("asset_id", "fingerprint", name="uq_findings_asset_fingerprint"),)

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    check: Mapped[str] = mapped_column(String(64))
    category: Mapped[FindingCategory] = mapped_column(enum_column(FindingCategory), index=True)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity), index=True)
    status: Mapped[FindingStatus] = mapped_column(
        enum_column(FindingStatus), default=FindingStatus.OPEN, index=True
    )
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(String(1024))
    evidence: Mapped[Any] = mapped_column(JSONType, default=dict)
    recommendation: Mapped[str | None] = mapped_column(Text)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    first_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assessments.id", ondelete="SET NULL")
    )
    last_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assessments.id", ondelete="SET NULL")
    )
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1)
    reopened_count: Mapped[int] = mapped_column(Integer, default=0)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    triaged_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    triage_note: Mapped[str | None] = mapped_column(Text)
