import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, JSONType, Timestamps, UUIDPrimaryKey


class WazuhConfig(UUIDPrimaryKey, Timestamps, Base):
    """Connection to an existing Wazuh deployment (read-only). A single row. Passwords live in the secret store."""

    __tablename__ = "wazuh_config"

    enabled: Mapped[bool] = mapped_column(default=False)
    api_url: Mapped[str | None] = mapped_column(String(512))  # https://wazuh-manager:55000
    api_user: Mapped[str | None] = mapped_column(String(128))
    indexer_url: Mapped[str | None] = mapped_column(String(512))  # https://wazuh-indexer:9200
    indexer_user: Mapped[str | None] = mapped_column(String(128))
    secret_path: Mapped[str | None] = mapped_column(String(255))  # {"api_password", "indexer_password"}
    verify_tls: Mapped[bool] = mapped_column(default=True)
    ca_cert: Mapped[str | None] = mapped_column(Text)  # optional PEM for a private CA
    min_alert_level: Mapped[int] = mapped_column(Integer, default=10)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_sync_ok: Mapped[bool | None] = mapped_column()
    last_sync_error: Mapped[str | None] = mapped_column(Text)
    last_alert_poll_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class WazuhAgent(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "wazuh_agents"

    agent_id: Mapped[str] = mapped_column(String(16), unique=True)  # "001"
    name: Mapped[str] = mapped_column(String(255))
    ip: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str | None] = mapped_column(String(32))  # active / disconnected / never_connected / pending
    os_name: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(128))
    version: Mapped[str | None] = mapped_column(String(64))
    last_keepalive: Mapped[str | None] = mapped_column(String(64))
    groups: Mapped[list[str]] = mapped_column(JSONType, default=list)
    server_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("servers.id", ondelete="SET NULL"), index=True)
    mapping: Mapped[str] = mapped_column(String(16), default="AUTO")  # AUTO | MANUAL | NONE
    raw: Mapped[dict[str, Any]] = mapped_column(JSONType, default=dict)
