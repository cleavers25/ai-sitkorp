import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import MemoryKind
from app.db.base import Base, Timestamps, UUIDPrimaryKey, enum_column


class Memory(UUIDPrimaryKey, Timestamps, Base):
    """Durable knowledge the AI should remember about an asset (or globally when asset_id is NULL). PRD 17."""

    __tablename__ = "memories"

    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    kind: Mapped[MemoryKind] = mapped_column(enum_column(MemoryKind))
    content: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(16), default="USER")  # USER | AI (proposed, user-confirmed)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
