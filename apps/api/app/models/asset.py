import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import AssetStatus, AssetType, ConnectivityStatus, Criticality
from app.db.base import Base, JSONType, Timestamps, UUIDPrimaryKey, enum_column
from app.models.credential import CredentialReference


class Asset(UUIDPrimaryKey, Timestamps, Base):
    """Common fields for every managed asset. Subtypes use joined-table inheritance."""

    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("asset_type", "name", name="uq_assets_type_name"),)

    asset_type: Mapped[AssetType] = mapped_column(enum_column(AssetType), index=True)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[AssetStatus] = mapped_column(
        enum_column(AssetStatus), default=AssetStatus.UNKNOWN, index=True
    )
    criticality: Mapped[Criticality] = mapped_column(
        enum_column(Criticality), default=Criticality.MEDIUM
    )
    environment: Mapped[str | None] = mapped_column(String(32))
    owner: Mapped[str | None] = mapped_column(String(128))
    tags: Mapped[list[str]] = mapped_column(JSONType, default=list)
    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Plain column, not a FK: avoids a circular assets <-> assessments dependency.
    last_assessment_id: Mapped[uuid.UUID | None] = mapped_column()

    __mapper_args__ = {"polymorphic_on": "asset_type"}


class Server(Asset):
    __tablename__ = "servers"

    id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    hostname: Mapped[str] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(default=22)
    ssh_username: Mapped[str | None] = mapped_column(String(128))
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("credential_references.id", ondelete="SET NULL")
    )

    # Filled in by the connectivity check.
    os_name: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(128))
    kernel: Mapped[str | None] = mapped_column(String(255))

    # Trust-on-first-use host key; a later mismatch blocks every connection.
    host_key: Mapped[str | None] = mapped_column(Text)
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))

    connectivity_status: Mapped[ConnectivityStatus] = mapped_column(
        enum_column(ConnectivityStatus), default=ConnectivityStatus.UNKNOWN
    )
    last_connectivity_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_connectivity_error: Mapped[str | None] = mapped_column(Text)

    credential: Mapped[CredentialReference | None] = relationship()
    websites: Mapped[list["Website"]] = relationship(
        back_populates="server",
        primaryjoin="Server.id == Website.server_id",
        foreign_keys="Website.server_id",
    )

    __mapper_args__ = {"polymorphic_identity": AssetType.SERVER}


class Website(Asset):
    __tablename__ = "websites"

    id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), primary_key=True
    )
    url: Mapped[str] = mapped_column(String(2048))
    domain: Mapped[str] = mapped_column(String(255), index=True)
    server_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("servers.id", ondelete="SET NULL"), index=True
    )
    application: Mapped[str | None] = mapped_column(String(64))  # wordpress, laravel, static...
    web_server: Mapped[str | None] = mapped_column(String(32))  # nginx, apache, litespeed, caddy
    runtime: Mapped[str | None] = mapped_column(String(64))  # e.g. "PHP 8.3"
    document_root: Mapped[str | None] = mapped_column(String(1024))

    server: Mapped[Server | None] = relationship(
        back_populates="websites",
        primaryjoin="Website.server_id == Server.id",
        foreign_keys=[server_id],
    )

    __mapper_args__ = {
        "polymorphic_identity": AssetType.WEBSITE,
        "inherit_condition": id == Asset.id,
    }
