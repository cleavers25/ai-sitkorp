import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import BackupState
from app.db.base import Base, Timestamps, UUIDPrimaryKey, enum_column


class Backup(UUIDPrimaryKey, Timestamps, Base):
    """A document-root archive pulled from a website's server and verified (PRD 13)."""

    __tablename__ = "backups"

    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    schedule_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("schedule_runs.id", ondelete="SET NULL"), index=True
    )
    trigger: Mapped[str] = mapped_column(String(16), default="MANUAL")
    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    state: Mapped[BackupState] = mapped_column(enum_column(BackupState), default=BackupState.RUNNING, index=True)
    source_path: Mapped[str | None] = mapped_column(String(1024))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    storage_path: Mapped[str | None] = mapped_column(String(1024))
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(64))
    file_count: Mapped[int | None] = mapped_column(Integer)  # files inside the archive
    remote_file_count: Mapped[int | None] = mapped_column(Integer)  # files counted on the server
    verified: Mapped[bool] = mapped_column(default=False)  # archive fully readable + counts match
    verify_note: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    pruned: Mapped[bool] = mapped_column(default=False)  # file removed by retention
