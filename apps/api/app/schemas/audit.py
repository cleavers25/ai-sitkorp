import uuid
from datetime import datetime
from typing import Any

from app.core.enums import AuditResult, RiskLevel
from app.schemas.common import ORMModel


class AuditLogOut(ORMModel):
    id: uuid.UUID
    timestamp: datetime
    user_id: uuid.UUID | None
    username: str | None
    source_ip: str | None
    asset_id: uuid.UUID | None
    action: str
    tool: str | None
    command_hash: str | None
    result: AuditResult
    risk_level: RiskLevel | None
    approval_id: uuid.UUID | None
    details: dict[str, Any]
