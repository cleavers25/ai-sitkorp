import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AIProviderKind
from app.db.base import Base, JSONType, Timestamps, UUIDPrimaryKey, enum_column, utcnow


class AIProvider(UUIDPrimaryKey, Timestamps, Base):
    """A configured LLM endpoint (PRD 15). The API key lives in the secret backend."""

    __tablename__ = "ai_providers"

    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[AIProviderKind] = mapped_column(enum_column(AIProviderKind))
    base_url: Mapped[str | None] = mapped_column(String(512))
    model: Mapped[str] = mapped_column(String(128))
    secret_path: Mapped[str | None] = mapped_column(String(255))
    max_tokens: Mapped[int] = mapped_column(Integer, default=8000)
    temperature: Mapped[float | None] = mapped_column(Float)
    is_default: Mapped[bool] = mapped_column(default=False)
    enabled: Mapped[bool] = mapped_column(default=True)
    last_test_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_test_ok: Mapped[bool | None] = mapped_column()
    last_test_error: Mapped[str | None] = mapped_column(Text)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class AIConversation(UUIDPrimaryKey, Timestamps, Base):
    """A chat thread: global (asset_id NULL) or scoped to one asset (PRD 17.4, 19)."""

    __tablename__ = "ai_conversations"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(255))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    provider_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("ai_providers.id", ondelete="SET NULL"))

    messages: Mapped[list["AIMessage"]] = relationship(
        back_populates="conversation", cascade="all, delete-orphan", order_by="AIMessage.position"
    )


class AIMessage(UUIDPrimaryKey, Base):
    __tablename__ = "ai_messages"

    conversation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("ai_conversations.id", ondelete="CASCADE"), index=True
    )
    position: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(16))  # user | assistant
    content: Mapped[str] = mapped_column(Text, default="")
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    provider_name: Mapped[str | None] = mapped_column(String(128))
    model: Mapped[str | None] = mapped_column(String(128))
    # Evidence of what the AI looked at: [{name, arguments, summary}] (PRD 17.4 "Evidence").
    tool_calls: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    # Actions the AI suggested; the user must confirm them in the UI.
    proposals: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)
    usage: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
    error: Mapped[str | None] = mapped_column(Text)

    # Provider-native transcript for this turn, replayed unchanged on the next request so the
    # history stays append-only (tool calls, tool results, thinking blocks).
    native_key: Mapped[str | None] = mapped_column(String(160))
    native: Mapped[list[dict[str, Any]]] = mapped_column(JSONType, default=list)

    conversation: Mapped[AIConversation] = relationship(back_populates="messages")
