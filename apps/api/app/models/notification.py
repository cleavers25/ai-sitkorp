import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import ChannelKind, DeliveryState, Severity
from app.db.base import Base, JSONType, Timestamps, UUIDPrimaryKey, enum_column, utcnow


class NotificationChannel(UUIDPrimaryKey, Timestamps, Base):
    """Where notifications go (PRD 43). Secrets (SMTP password, webhook secret, bot token) live in the secret store."""

    __tablename__ = "notification_channels"

    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[ChannelKind] = mapped_column(enum_column(ChannelKind))
    enabled: Mapped[bool] = mapped_column(default=True)
    config: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)  # non-secret settings
    secret_path: Mapped[str | None] = mapped_column(String(255))
    events: Mapped[list[str]] = mapped_column(JSONType, default=list)  # subscribed event types
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_ok: Mapped[bool | None] = mapped_column()
    last_test_error: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class NotificationEvent(UUIDPrimaryKey, Base):
    """Something worth telling people about; also the in-app notification feed."""

    __tablename__ = "notification_events"

    type: Mapped[str] = mapped_column(String(32), index=True)
    severity: Mapped[Severity] = mapped_column(enum_column(Severity))
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text, default="")
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"), index=True)
    link: Mapped[str | None] = mapped_column(String(512))  # app-relative path, e.g. /websites/<id>
    data: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class NotificationDelivery(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "notification_deliveries"

    event_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notification_events.id", ondelete="CASCADE"), index=True)
    channel_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True
    )
    state: Mapped[DeliveryState] = mapped_column(enum_column(DeliveryState), default=DeliveryState.PENDING, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
