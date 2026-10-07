import uuid
from datetime import datetime
from typing import Annotated, Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.api.deps import DB, client_ip, require
from app.core.rbac import Permission
from app.models.asset import Server
from app.models.user import User
from app.models.wazuh import WazuhAgent
from app.schemas.common import ORMModel
from app.services import audit, wazuh
from app.services.secrets import get_secret_backend

router = APIRouter(prefix="/integrations/wazuh", tags=["integrations"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Manager = Annotated[User, Depends(require(Permission.INTEGRATION_MANAGE))]


def _url(v: str | None) -> str | None:
    if not v:
        return None
    u = urlparse(v)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("must be an absolute http(s) URL")
    return v.rstrip("/")


class WazuhSettings(BaseModel):
    enabled: bool = False
    api_url: str | None = Field(default=None, max_length=512)
    api_user: str | None = Field(default=None, max_length=128)
    api_password: str | None = Field(default=None, max_length=512)  # write-only; omit to keep
    indexer_url: str | None = Field(default=None, max_length=512)
    indexer_user: str | None = Field(default=None, max_length=128)
    indexer_password: str | None = Field(default=None, max_length=512)  # write-only; omit to keep
    verify_tls: bool = True
    ca_cert: str | None = Field(default=None, max_length=20000)
    min_alert_level: int = Field(default=10, ge=3, le=15)

    _u1 = field_validator("api_url")(_url)
    _u2 = field_validator("indexer_url")(_url)

    @field_validator("ca_cert")
    @classmethod
    def _pem(cls, v):
        if v and "BEGIN CERTIFICATE" not in v:
            raise ValueError("ca_cert must be a PEM certificate")
        return v or None


class WazuhSettingsOut(BaseModel):
    enabled: bool
    api_url: str | None
    api_user: str | None
    has_api_password: bool
    indexer_url: str | None
    indexer_user: str | None
    has_indexer_password: bool
    verify_tls: bool
    has_ca_cert: bool
    min_alert_level: int
    last_sync_at: datetime | None
    last_sync_ok: bool | None
    last_sync_error: str | None


class AgentOut(ORMModel):
    agent_id: str
    name: str
    ip: str | None
    status: str | None
    os_name: str | None
    os_version: str | None
    version: str | None
    last_keepalive: str | None
    groups: list[str]
    server_id: uuid.UUID | None
    server_name: str | None = None
    mapping: str


class AgentMapping(BaseModel):
    server_id: uuid.UUID | None = None
    auto: bool = False  # true = let sync map it by name/IP again


def _secrets(db) -> dict:
    cfg = wazuh.get_config(db)
    if not cfg.secret_path:
        return {}
    try:
        return get_secret_backend(db).get(cfg.secret_path)
    except Exception:
        return {}


def _out(db) -> WazuhSettingsOut:
    cfg, sec = wazuh.get_config(db), _secrets(db)
    return WazuhSettingsOut(
        enabled=cfg.enabled, api_url=cfg.api_url, api_user=cfg.api_user, has_api_password=bool(sec.get("api_password")),
        indexer_url=cfg.indexer_url, indexer_user=cfg.indexer_user,
        has_indexer_password=bool(sec.get("indexer_password")), verify_tls=cfg.verify_tls,
        has_ca_cert=bool(cfg.ca_cert), min_alert_level=cfg.min_alert_level, last_sync_at=cfg.last_sync_at,
        last_sync_ok=cfg.last_sync_ok, last_sync_error=cfg.last_sync_error)


@router.get("/status")
def integration_status(_: Viewer, db: DB) -> dict[str, Any]:
    cfg = wazuh.get_config(db)
    return {"enabled": wazuh.is_enabled(db), "last_sync_at": cfg.last_sync_at, "last_sync_ok": cfg.last_sync_ok}


@router.get("", response_model=WazuhSettingsOut)
def get_settings_(_: Manager, db: DB):
    return _out(db)


@router.put("", response_model=WazuhSettingsOut)
def save_settings(body: WazuhSettings, user: Manager, request: Request, db: DB):
    cfg = wazuh.get_config(db)
    data = body.model_dump(exclude={"api_password", "indexer_password"})
    if "ca_cert" not in body.model_fields_set:
        data.pop("ca_cert")  # omitted = keep the stored CA; null clears it
    for k, v in data.items():
        setattr(cfg, k, v)
    sec = _secrets(db)
    changed = {k: getattr(body, k) for k in ("api_password", "indexer_password") if getattr(body, k) is not None}
    if changed:
        sec.update(changed)
        cfg.secret_path = cfg.secret_path or f"integrations/wazuh/{cfg.id}"
        get_secret_backend(db).put(cfg.secret_path, sec)
    if body.enabled and not (cfg.api_url and cfg.api_user):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "API URL dan user wajib diisi untuk mengaktifkan integrasi")
    audit.record(db, "integration.wazuh.update", user=user, source_ip=client_ip(request),
                 details={**{k: v for k, v in data.items() if k != "ca_cert"}, "passwords_changed": sorted(changed)})
    db.commit()
    return _out(db)


@router.post("/test")
def test_connection(user: Manager, request: Request, db: DB) -> dict:
    out: dict[str, Any] = {}
    try:
        client = wazuh.WazuhClient.from_db(db)
        info = client.api_get("/")
        out["api"] = {"ok": True, "version": (info.get("data") or {}).get("api_version")}
    except wazuh.WazuhError as exc:
        out["api"] = {"ok": False, "error": str(exc)}
        client = None
    if client and client.cfg.indexer_url:
        try:
            info = client.indexer_info()
            out["indexer"] = {"ok": True, "version": (info.get("version") or {}).get("number"),
                              "cluster": info.get("cluster_name")}
        except (wazuh.WazuhError, Exception) as exc:
            out["indexer"] = {"ok": False, "error": str(exc)[:300]}
    audit.record(db, "integration.wazuh.test", user=user, source_ip=client_ip(request), details=out)
    db.commit()
    return out


@router.post("/sync")
def sync(user: Manager, request: Request, db: DB) -> dict:
    try:
        result = wazuh.sync_agents(db)
    except wazuh.WazuhError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))
    audit.record(db, "integration.wazuh.sync", user=user, source_ip=client_ip(request), details=result)
    db.commit()
    return result


@router.get("/agents", response_model=list[AgentOut])
def list_agents(_: Viewer, db: DB):
    names = {s.id: s.name for s in db.scalars(select(Server))}
    return [AgentOut.model_validate(a).model_copy(update={"server_name": names.get(a.server_id)})
            for a in db.scalars(select(WazuhAgent).order_by(WazuhAgent.agent_id))]


@router.patch("/agents/{agent_id}", response_model=AgentOut)
def map_agent(agent_id: str, body: AgentMapping, user: Manager, request: Request, db: DB):
    a = db.scalars(select(WazuhAgent).where(WazuhAgent.agent_id == agent_id)).first()
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Agent not found")
    if body.auto:
        a.mapping = "AUTO"
        match = wazuh._auto_match(db, a)
        a.server_id = match.id if match else None
    else:
        if body.server_id and db.get(Server, body.server_id) is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "server_id does not exist")
        a.server_id, a.mapping = body.server_id, "MANUAL" if body.server_id else "NONE"
    audit.record(db, "integration.wazuh.map_agent", user=user, source_ip=client_ip(request),
                 details={"agent_id": agent_id, "server_id": str(a.server_id) if a.server_id else None, "mapping": a.mapping})
    db.commit()
    server = db.get(Server, a.server_id) if a.server_id else None
    return AgentOut.model_validate(a).model_copy(update={"server_name": server.name if server else None})
