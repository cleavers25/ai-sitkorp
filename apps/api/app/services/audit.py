import hashlib
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.enums import AuditResult, RiskLevel
from app.core.redaction import redact
from app.models.audit import AuditLog
from app.models.user import User


def command_hash(command: str) -> str:
    return hashlib.sha256(command.encode()).hexdigest()


def record(
    db: Session,
    action: str,
    result: AuditResult = AuditResult.SUCCESS,
    *,
    user: User | None = None,
    username: str | None = None,
    source_ip: str | None = None,
    asset_id: uuid.UUID | None = None,
    tool: str | None = None,
    command: str | None = None,
    risk_level: RiskLevel | None = None,
    approval_id: uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditLog:
    """Add an audit entry to the session. The caller commits it with its own transaction."""
    entry = AuditLog(
        user_id=user.id if user else None,
        username=user.email if user else username,
        source_ip=source_ip,
        asset_id=asset_id,
        action=action,
        tool=tool,
        command_hash=command_hash(command) if command else None,
        result=result,
        risk_level=risk_level,
        approval_id=approval_id,
        details=redact(details or {}),
    )
    db.add(entry)
    return entry
