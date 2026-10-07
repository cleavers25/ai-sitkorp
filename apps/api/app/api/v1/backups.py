import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from app.api.deps import DB, client_ip, require
from app.core.config import get_settings
from app.core.enums import BackupState
from app.core.rbac import Permission
from app.models.asset import Website
from app.models.backup import Backup
from app.models.user import User
from app.schemas.common import ORMModel, Page
from app.services import audit, backups

router = APIRouter(prefix="/backups", tags=["backups"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Runner = Annotated[User, Depends(require(Permission.BACKUP_RUN))]
Downloader = Annotated[User, Depends(require(Permission.BACKUP_DOWNLOAD))]


class BackupOut(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    trigger: str
    state: BackupState
    source_path: str | None
    started_at: datetime
    finished_at: datetime | None
    size_bytes: int | None
    sha256: str | None
    file_count: int | None
    remote_file_count: int | None
    verified: bool
    verify_note: str | None
    error: str | None
    pruned: bool


class BackupRequest(BaseModel):
    asset_id: uuid.UUID


class WebsiteBackupStatus(BaseModel):
    asset_id: uuid.UUID
    name: str
    document_root: str | None
    ready: bool  # linked to a server and document root filled in
    latest: BackupOut | None
    backups_kept: int


@router.get("/overview", response_model=list[WebsiteBackupStatus])
def overview(_: Viewer, db: DB):
    out = []
    for site in db.scalars(select(Website).order_by(Website.name)):
        latest = db.scalars(select(Backup).where(Backup.asset_id == site.id)
                            .order_by(Backup.started_at.desc()).limit(1)).first()
        kept = db.scalar(select(func.count()).select_from(Backup).where(
            Backup.asset_id == site.id, Backup.state == BackupState.SUCCEEDED, Backup.pruned.is_(False)))
        out.append(WebsiteBackupStatus(asset_id=site.id, name=site.name, document_root=site.document_root,
                                       ready=bool(site.document_root and site.server_id),
                                       latest=BackupOut.model_validate(latest) if latest else None, backups_kept=kept))
    return out


@router.get("", response_model=Page[BackupOut])
def list_backups(_: Viewer, db: DB, asset_id: uuid.UUID | None = None,
                 limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    stmt = select(Backup)
    if asset_id:
        stmt = stmt.where(Backup.asset_id == asset_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Backup.started_at.desc()).limit(limit).offset(offset)).all()
    return Page(items=rows, total=total, limit=limit, offset=offset)


@router.post("", response_model=BackupOut, status_code=status.HTTP_202_ACCEPTED)
def backup_now(body: BackupRequest, user: Runner, db: DB):
    site = db.get(Website, body.asset_id)
    if site is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Website not found")
    if not site.document_root or not site.server_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Hubungkan website ke server dan isi document root")
    if db.scalar(select(Backup.id).where(Backup.asset_id == site.id, Backup.state == BackupState.RUNNING).limit(1)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A backup is already running for this website")
    b = backups.start(db, site, user, "MANUAL")
    db.refresh(b)
    return b


@router.get("/{backup_id}", response_model=BackupOut)
def get_backup(backup_id: uuid.UUID, _: Viewer, db: DB):
    b = db.get(Backup, backup_id)
    if b is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup not found")
    return b


@router.get("/{backup_id}/download")
def download(backup_id: uuid.UUID, user: Downloader, request: Request, db: DB):
    b = db.get(Backup, backup_id)
    if b is None or b.state != BackupState.SUCCEEDED or b.pruned or not b.storage_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup file not available")
    path = Path(b.storage_path).resolve()
    if not path.is_relative_to(Path(get_settings().backup_dir).resolve()) or not path.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Backup file not available")
    audit.record(db, "backup.download", user=user, source_ip=client_ip(request), asset_id=b.asset_id,
                 details={"backup_id": str(b.id), "sha256": b.sha256, "size_bytes": b.size_bytes})
    db.commit()
    site = db.get(Website, b.asset_id)
    name = f"backup-{site.name if site else b.asset_id}-{b.started_at:%Y%m%d-%H%M}.tar.gz".replace("/", "_")
    return FileResponse(path, media_type="application/gzip", filename=name)
