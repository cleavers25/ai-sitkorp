import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import ActionKind, ActionState, RiskLevel
from app.db.base import Base, JSONType, Timestamps, UUIDPrimaryKey, enum_column


class Action(UUIDPrimaryKey, Timestamps, Base):
    """A remediation request that changes a managed server; always approved before it runs (PRD 23-25, 49)."""

    __tablename__ = "actions"

    kind: Mapped[ActionKind] = mapped_column(enum_column(ActionKind))
    state: Mapped[ActionState] = mapped_column(
        enum_column(ActionState), default=ActionState.PENDING_APPROVAL, index=True
    )
    risk_level: Mapped[RiskLevel] = mapped_column(enum_column(RiskLevel))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    server_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("servers.id", ondelete="SET NULL"))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id", ondelete="SET NULL"))
    params: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    reason: Mapped[str] = mapped_column(Text, default="")
    command_preview: Mapped[str] = mapped_column(Text, default="")

    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    decision_note: Mapped[str | None] = mapped_column(Text)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # evidence, verification, outputs
    error: Mapped[str | None] = mapped_column(Text)

    rollback_of_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("actions.id", ondelete="SET NULL"))
    # Plain column (no FK) to avoid a second self-referencing foreign key.
    rolled_back_by_id: Mapped[uuid.UUID | None] = mapped_column()
