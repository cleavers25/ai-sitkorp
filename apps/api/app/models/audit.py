import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import AuditResult, RiskLevel
from app.db.base import Base, JSONType, UUIDPrimaryKey, enum_column, utcnow


class AuditLog(UUIDPrimaryKey, Base):
    """Append-only audit trail (PRD section 26).

    asset_id / user_id are deliberately not foreign keys so history survives deletions.
    On PostgreSQL a trigger rejects UPDATE and DELETE on this table.
    """

    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    username: Mapped[str | None] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    tool: Mapped[str | None] = mapped_column(String(64))
    command_hash: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[AuditResult] = mapped_column(enum_column(AuditResult))
    risk_level: Mapped[RiskLevel | None] = mapped_column(enum_column(RiskLevel))
    approval_id: Mapped[uuid.UUID | None] = mapped_column()
    details: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
