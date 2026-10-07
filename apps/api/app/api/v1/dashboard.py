from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import DB, require
from app.core.enums import (
    AssessmentState, AssetStatus, AssetType, ConnectivityStatus, FindingCategory, FindingStatus, Severity,
)
from app.core.rbac import Permission, has_permission
from app.models.assessment import Assessment, Finding
from app.models.asset import Asset, Server
from app.models.audit import AuditLog
from app.models.user import User
from app.schemas.assessment import AssetRef
from app.schemas.audit import AuditLogOut

router = APIRouter(prefix="/dashboard", tags=["dashboard"])
Viewer = Annotated[User, Depends(require(Permission.DASHBOARD_VIEW))]

ACTIVE = (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED)


class RiskyAsset(AssetRef):
    status: AssetStatus
    open_findings: int


class DashboardSummary(BaseModel):
    total_assets: int
    total_servers: int
    total_websites: int
    status_counts: dict[AssetStatus, int]
    connectivity_counts: dict[ConnectivityStatus, int]
    open_findings: dict[Severity, int]
    unresolved_findings: int
    malware_suspected: int
    ssl_expiring: int
    service_down: int
    disk_critical: int
    never_assessed: int
    assessments_running: int
    last_assessment_at: datetime | None
    red_assets: list[RiskyAsset]
    recent_activity: list[AuditLogOut] | None  # only for roles with audit:view


def _count_open(db, *conditions) -> int:
    return db.scalar(select(func.count()).select_from(Finding).where(Finding.status.in_(ACTIVE), *conditions))


@router.get("/summary", response_model=DashboardSummary)
def summary(user: Viewer, db: DB):
    by_type = dict(db.execute(select(Asset.asset_type, func.count()).group_by(Asset.asset_type)).all())
    by_status = dict(db.execute(select(Asset.status, func.count()).group_by(Asset.status)).all())
    by_conn = dict(db.execute(
        select(Server.connectivity_status, func.count()).group_by(Server.connectivity_status)
    ).all())
    by_sev = dict(db.execute(
        select(Finding.severity, func.count()).where(Finding.status.in_(ACTIVE)).group_by(Finding.severity)
    ).all())

    red = db.scalars(select(Asset).where(Asset.status == AssetStatus.RED).order_by(Asset.name).limit(10)).all()
    open_per_asset = dict(db.execute(
        select(Finding.asset_id, func.count()).where(Finding.status.in_(ACTIVE),
                                                     Finding.asset_id.in_([a.id for a in red]))
        .group_by(Finding.asset_id)).all())

    recent = None
    if has_permission(user.role, Permission.AUDIT_VIEW):
        recent = db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(10)).all()

    return DashboardSummary(
        total_assets=sum(by_type.values()),
        total_servers=by_type.get(AssetType.SERVER, 0),
        total_websites=by_type.get(AssetType.WEBSITE, 0),
        status_counts={s: by_status.get(s, 0) for s in AssetStatus},
        connectivity_counts={c: by_conn.get(c, 0) for c in ConnectivityStatus},
        open_findings={s: by_sev.get(s, 0) for s in Severity},
        unresolved_findings=sum(by_sev.values()),
        malware_suspected=_count_open(db, Finding.category == FindingCategory.MALWARE,
                                      Finding.severity.in_([Severity.HIGH, Severity.CRITICAL])),
        ssl_expiring=_count_open(db, Finding.check == "ssl_certificate"),
        service_down=_count_open(db, Finding.check.in_(["http_availability", "ssh_connectivity"]),
                                 Finding.severity.in_([Severity.HIGH, Severity.CRITICAL])),
        disk_critical=_count_open(db, Finding.check.in_(["disk_usage", "inode_usage"]),
                                  Finding.severity.in_([Severity.HIGH, Severity.CRITICAL])),
        never_assessed=db.scalar(select(func.count()).select_from(Asset).where(Asset.last_assessed_at.is_(None))),
        assessments_running=db.scalar(select(func.count()).select_from(Assessment).where(
            Assessment.state.in_([AssessmentState.QUEUED, AssessmentState.RUNNING]))),
        last_assessment_at=db.scalar(select(func.max(Assessment.finished_at))),
        red_assets=[RiskyAsset(id=a.id, name=a.name, asset_type=a.asset_type, status=a.status,
                               open_findings=open_per_asset.get(a.id, 0)) for a in red],
        recent_activity=recent,
    )
