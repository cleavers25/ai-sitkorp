import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import CredentialKind
from app.db.base import Base, Timestamps, UUIDPrimaryKey, enum_column


class CredentialReference(UUIDPrimaryKey, Timestamps, Base):
    """Metadata about a credential. The secret itself lives in the secret backend (PRD 8.2)."""

    __tablename__ = "credential_references"

    name: Mapped[str] = mapped_column(String(128), unique=True)
    kind: Mapped[CredentialKind] = mapped_column(enum_column(CredentialKind))
    username: Mapped[str | None] = mapped_column(String(128))
    secret_backend: Mapped[str] = mapped_column(String(32))
    secret_path: Mapped[str] = mapped_column(String(255), unique=True)
    access_scope: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    # Public-key fingerprint for SSH keys, so users can identify a key without seeing it.
    public_fingerprint: Mapped[str | None] = mapped_column(String(128))
    last_rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )


class EncryptedSecret(Timestamps, Base):
    """Ciphertext store used by the local AES-GCM secret backend."""

    __tablename__ = "encrypted_secrets"

    path: Mapped[str] = mapped_column(String(255), primary_key=True)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    key_version: Mapped[int] = mapped_column(Integer, default=1)
