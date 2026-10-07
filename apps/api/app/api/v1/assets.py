import uuid
from typing import Annotated
from urllib.parse import urlparse

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import DB, client_ip, require
from app.core.enums import AssetStatus, AssetType, ConnectivityStatus, CredentialKind, RiskLevel
from app.core.rbac import Permission
from app.models.asset import Asset, Server, Website
from app.models.credential import CredentialReference
from app.models.user import User
from app.schemas.asset import (
    AssetOut, JobOut, ServerCreate, ServerOut, ServerUpdate, WebsiteCreate, WebsiteOut, WebsiteUpdate,
)
from app.schemas.common import Page
from app.services import audit
from app.worker.celery_app import celery_app
from app.worker.tasks import check_connectivity_task

router = APIRouter(tags=["assets"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Manager = Annotated[User, Depends(require(Permission.ASSET_MANAGE))]
ToolRunner = Annotated[User, Depends(require(Permission.TOOL_RUN_SAFE))]


def _commit_unique(db: Session) -> None:
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An asset of this type with that name already exists")


def _audit_changes(changes: dict) -> dict:
    return {k: (str(v) if isinstance(v, uuid.UUID) else getattr(v, "value", v)) for k, v in changes.items()}


# --- Generic asset listing ------------------------------------------------

@router.get("/assets", response_model=Page[AssetOut])
def list_assets(
    _: Viewer, db: DB,
    asset_type: AssetType | None = None,
    status_: Annotated[AssetStatus | None, Query(alias="status")] = None,
    q: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Asset)
    if asset_type:
        stmt = stmt.where(Asset.asset_type == asset_type)
    if status_:
        stmt = stmt.where(Asset.status == status_)
    if q:
        stmt = stmt.where(Asset.name.ilike(f"%{q}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    items = db.scalars(stmt.order_by(Asset.name).limit(limit).offset(offset)).all()
    return Page(items=items, total=total, limit=limit, offset=offset)


# --- Servers --------------------------------------------------------------

def _get_server(db: Session, server_id: uuid.UUID) -> Server:
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Server not found")
    return server


def _check_ssh_credential(db: Session, credential_id: uuid.UUID | None) -> None:
    if credential_id is None:
        return
    cred = db.get(CredentialReference, credential_id)
    if cred is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "credential_id does not exist")
    if cred.kind not in (CredentialKind.SSH_PRIVATE_KEY, CredentialKind.SSH_PASSWORD):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "credential is not an SSH credential")


def _server_out(db: Session, server: Server) -> ServerOut:
    count = db.scalar(select(func.count()).select_from(Website).where(Website.server_id == server.id))
    return ServerOut.model_validate(server).model_copy(update={"website_count": count})


@router.get("/servers", response_model=Page[ServerOut])
def list_servers(
    _: Viewer, db: DB,
    q: str | None = Query(default=None, max_length=100),
    connectivity: ConnectivityStatus | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Server)
    if q:
        stmt = stmt.where(or_(Server.name.ilike(f"%{q}%"), Server.hostname.ilike(f"%{q}%")))
    if connectivity:
        stmt = stmt.where(Server.connectivity_status == connectivity)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    servers = db.scalars(stmt.order_by(Server.name).limit(limit).offset(offset)).all()
    counts = dict(db.execute(
        select(Website.server_id, func.count()).where(Website.server_id.in_([s.id for s in servers]))
        .group_by(Website.server_id)
    ).all())
    items = [ServerOut.model_validate(s).model_copy(update={"website_count": counts.get(s.id, 0)})
             for s in servers]
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.post("/servers", response_model=ServerOut, status_code=status.HTTP_201_CREATED)
def create_server(body: ServerCreate, user: Manager, request: Request, db: DB):
    _check_ssh_credential(db, body.credential_id)
    server = Server(**body.model_dump(), created_by_id=user.id)
    db.add(server)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A server with that name already exists")
    audit.record(db, "asset.create", user=user, source_ip=client_ip(request), asset_id=server.id,
                 details={"type": "SERVER", "name": server.name, "hostname": server.hostname})
    _commit_unique(db)
    return _server_out(db, server)


@router.get("/servers/{server_id}", response_model=ServerOut)
def get_server(server_id: uuid.UUID, _: Viewer, db: DB):
    return _server_out(db, _get_server(db, server_id))


@router.patch("/servers/{server_id}", response_model=ServerOut)
def update_server(server_id: uuid.UUID, body: ServerUpdate, user: Manager, request: Request, db: DB):
    server = _get_server(db, server_id)
    changes = body.model_dump(exclude_unset=True)
    if "credential_id" in changes:
        _check_ssh_credential(db, changes["credential_id"])
    if ("hostname" in changes and changes["hostname"] != server.hostname) or (
        "ssh_port" in changes and changes["ssh_port"] != server.ssh_port
    ):
        # New endpoint: the pinned host key no longer applies.
        server.host_key = server.host_key_fingerprint = None
        server.connectivity_status = ConnectivityStatus.UNKNOWN
    for field, value in changes.items():
        setattr(server, field, value)
    audit.record(db, "asset.update", user=user, source_ip=client_ip(request), asset_id=server.id,
                 details={"type": "SERVER", "name": server.name, "changes": _audit_changes(changes)})
    _commit_unique(db)
    return _server_out(db, server)


@router.delete("/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_server(server_id: uuid.UUID, user: Manager, request: Request, db: DB):
    server = _get_server(db, server_id)
    for website in server.websites:
        website.server_id = None
    audit.record(db, "asset.delete", user=user, source_ip=client_ip(request), asset_id=server.id,
                 risk_level=RiskLevel.HIGH,
                 details={"type": "SERVER", "name": server.name, "hostname": server.hostname})
    db.delete(server)
    db.commit()


@router.post("/servers/{server_id}/test-connection", response_model=JobOut,
             status_code=status.HTTP_202_ACCEPTED)
def test_connection(server_id: uuid.UUID, user: ToolRunner, request: Request, db: DB):
    server = _get_server(db, server_id)
    if server.credential_id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Assign an SSH credential first")
    if server.connectivity_status == ConnectivityStatus.HOST_KEY_MISMATCH:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "Host key mismatch: verify the server, then reset its host key")
    server.connectivity_status = ConnectivityStatus.PENDING
    db.commit()
    job = check_connectivity_task.delay(str(server.id), str(user.id), client_ip(request))
    return JobOut(job_id=job.id, status=job.status)


@router.post("/servers/{server_id}/reset-host-key", response_model=ServerOut)
def reset_host_key(server_id: uuid.UUID, user: Manager, request: Request, db: DB):
    server = _get_server(db, server_id)
    old = server.host_key_fingerprint
    server.host_key = server.host_key_fingerprint = None
    server.connectivity_status = ConnectivityStatus.UNKNOWN
    server.last_connectivity_error = None
    audit.record(db, "server.reset_host_key", user=user, source_ip=client_ip(request),
                 asset_id=server.id, risk_level=RiskLevel.HIGH,
                 details={"name": server.name, "old_fingerprint": old})
    db.commit()
    return _server_out(db, server)


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(job_id: str, _: Viewer):
    result = AsyncResult(job_id, app=celery_app)
    payload = result.result if result.successful() and isinstance(result.result, dict) else None
    return JobOut(job_id=job_id, status=result.status, result=payload)


# --- Websites -------------------------------------------------------------

def _get_website(db: Session, website_id: uuid.UUID) -> Website:
    website = db.get(Website, website_id)
    if website is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Website not found")
    return website


def _check_server_exists(db: Session, server_id: uuid.UUID | None) -> None:
    if server_id is not None and db.get(Server, server_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "server_id does not exist")


def _domain_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


@router.get("/websites", response_model=Page[WebsiteOut])
def list_websites(
    _: Viewer, db: DB,
    q: str | None = Query(default=None, max_length=100),
    server_id: uuid.UUID | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Website)
    if q:
        stmt = stmt.where(or_(Website.name.ilike(f"%{q}%"), Website.domain.ilike(f"%{q}%")))
    if server_id:
        stmt = stmt.where(Website.server_id == server_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    items = db.scalars(stmt.order_by(Website.name).limit(limit).offset(offset)).all()
    return Page(items=items, total=total, limit=limit, offset=offset)


@router.post("/websites", response_model=WebsiteOut, status_code=status.HTTP_201_CREATED)
def create_website(body: WebsiteCreate, user: Manager, request: Request, db: DB):
    _check_server_exists(db, body.server_id)
    data = body.model_dump()
    data["domain"] = (data.get("domain") or _domain_from_url(body.url)).lower()
    data["name"] = data.get("name") or data["domain"]
    website = Website(**data, created_by_id=user.id)
    db.add(website)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A website with that name already exists")
    audit.record(db, "asset.create", user=user, source_ip=client_ip(request), asset_id=website.id,
                 details={"type": "WEBSITE", "name": website.name, "url": website.url})
    _commit_unique(db)
    return website


@router.get("/websites/{website_id}", response_model=WebsiteOut)
def get_website(website_id: uuid.UUID, _: Viewer, db: DB):
    return _get_website(db, website_id)


@router.patch("/websites/{website_id}", response_model=WebsiteOut)
def update_website(website_id: uuid.UUID, body: WebsiteUpdate, user: Manager, request: Request, db: DB):
    website = _get_website(db, website_id)
    changes = body.model_dump(exclude_unset=True)
    if "server_id" in changes:
        _check_server_exists(db, changes["server_id"])
    if "domain" in changes and changes["domain"]:
        changes["domain"] = changes["domain"].lower()
    for field, value in changes.items():
        setattr(website, field, value)
    audit.record(db, "asset.update", user=user, source_ip=client_ip(request), asset_id=website.id,
                 details={"type": "WEBSITE", "name": website.name, "changes": _audit_changes(changes)})
    _commit_unique(db)
    db.refresh(website)
    return website


@router.delete("/websites/{website_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_website(website_id: uuid.UUID, user: Manager, request: Request, db: DB):
    website = _get_website(db, website_id)
    audit.record(db, "asset.delete", user=user, source_ip=client_ip(request), asset_id=website.id,
                 risk_level=RiskLevel.HIGH,
                 details={"type": "WEBSITE", "name": website.name, "url": website.url})
    db.delete(website)
    db.commit()
