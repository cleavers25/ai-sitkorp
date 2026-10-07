import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select

from app.api.deps import DB, require
from app.core.enums import AuditResult
from app.core.rbac import Permission
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.audit import AuditLogOut
from app.schemas.common import Page

router = APIRouter(prefix="/audit-logs", tags=["audit"])
Auditor = Annotated[User, Depends(require(Permission.AUDIT_VIEW))]


@router.get("", response_model=Page[AuditLogOut])
def list_audit_logs(
    _: Auditor, db: DB,
    action: str | None = Query(default=None, max_length=64),
    user_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    result: AuditResult | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action))
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    if asset_id:
        stmt = stmt.where(AuditLog.asset_id == asset_id)
    if result:
        stmt = stmt.where(AuditLog.result == result)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since)
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    items = db.scalars(stmt.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)).all()
    return Page(items=items, total=total, limit=limit, offset=offset)
