import uuid
from datetime import datetime
from typing import Annotated, Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser, client_ip, require
from app.core.enums import ChannelKind, DeliveryState, Severity
from app.core.rbac import Permission
from app.db.base import utcnow
from app.models.notification import NotificationChannel, NotificationDelivery, NotificationEvent
from app.models.user import User
from app.schemas.common import ORMModel, Page
from app.services import audit, notify
from app.services.secrets import get_secret_backend

router = APIRouter(prefix="/notifications", tags=["notifications"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Manager = Annotated[User, Depends(require(Permission.NOTIFY_MANAGE))]

# Non-secret settings allowed per channel kind.
CONFIG_KEYS = {
    ChannelKind.EMAIL: {"host", "port", "security", "username", "from_address", "to", "verify_tls"},
    ChannelKind.WEBHOOK: {"url", "format", "verify_tls"},
    ChannelKind.TELEGRAM: {"chat_id"},
}
SECRET_KEYS = {ChannelKind.EMAIL: "password", ChannelKind.WEBHOOK: "signing_secret", ChannelKind.TELEGRAM: "bot_token"}


def _check_config(kind: ChannelKind, cfg: dict[str, Any]) -> dict[str, Any]:
    unknown = set(cfg) - CONFIG_KEYS[kind]
    if unknown:
        raise ValueError(f"unknown settings for {kind.value}: {', '.join(sorted(unknown))}")
    if kind == ChannelKind.EMAIL:
        if cfg.get("security", "starttls") not in ("starttls", "ssl", "none"):
            raise ValueError("security must be starttls, ssl or none")
        to = cfg.get("to") or []
        if not isinstance(to, list) or any("@" not in str(x) for x in to):
            raise ValueError("to must be a list of email addresses")
        if cfg.get("port") is not None and not (1 <= int(cfg["port"]) <= 65535):
            raise ValueError("invalid port")
    if kind == ChannelKind.WEBHOOK:
        u = urlparse(cfg.get("url") or "")
        if cfg.get("url") and (u.scheme not in ("http", "https") or not u.hostname):
            raise ValueError("url must be an absolute http(s) URL")
        if cfg.get("format", "json") not in ("json", "slack"):
            raise ValueError("format must be json or slack")
    return cfg


class ChannelCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: ChannelKind
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    secret: str | None = Field(default=None, max_length=4096)  # write-only
    events: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _valid(self):
        _check_config(self.kind, self.config)
        bad = set(self.events) - set(notify.EVENT_TYPES)
        if bad:
            raise ValueError(f"unknown events: {', '.join(sorted(bad))}")
        return self


class ChannelUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secret: str | None = Field(default=None, max_length=4096)  # "" removes it
    events: list[str] | None = None


class ChannelOut(ORMModel):
    id: uuid.UUID
    name: str
    kind: ChannelKind
    enabled: bool
    config: dict[str, Any]
    has_secret: bool = False
    events: list[str]
    last_test_at: datetime | None
    last_test_ok: bool | None
    last_test_error: str | None


class EventOut(ORMModel):
    id: uuid.UUID
    type: str
    severity: Severity
    title: str
    body: str
    asset_id: uuid.UUID | None
    link: str | None
    created_at: datetime


class DeliveryOut(ORMModel):
    id: uuid.UUID
    event_id: uuid.UUID
    channel_id: uuid.UUID
    state: DeliveryState
    attempts: int
    last_error: str | None
    sent_at: datetime | None
    created_at: datetime
    event_title: str | None = None
    channel_name: str | None = None


def _out(ch: NotificationChannel) -> ChannelOut:
    return ChannelOut.model_validate(ch).model_copy(update={"has_secret": bool(ch.secret_path)})


def _set_secret(db, ch: NotificationChannel, value: str | None) -> None:
    backend = get_secret_backend(db)
    if value:
        ch.secret_path = ch.secret_path or f"notification-channels/{ch.id}"
        backend.put(ch.secret_path, {SECRET_KEYS[ch.kind]: value})
    elif ch.secret_path:
        backend.delete(ch.secret_path)
        ch.secret_path = None


def _get(db, channel_id: uuid.UUID) -> NotificationChannel:
    ch = db.get(NotificationChannel, channel_id)
    if ch is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    return ch


@router.get("/event-types")
def event_types(_: Viewer) -> dict[str, str]:
    return notify.EVENT_TYPES


@router.get("/channels", response_model=list[ChannelOut])
def list_channels(_: Manager, db: DB):
    return [_out(c) for c in db.scalars(select(NotificationChannel).order_by(NotificationChannel.name))]


@router.post("/channels", response_model=ChannelOut, status_code=status.HTTP_201_CREATED)
def create_channel(body: ChannelCreate, user: Manager, request: Request, db: DB):
    if db.scalar(select(NotificationChannel).where(NotificationChannel.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Channel name already exists")
    ch = NotificationChannel(id=uuid.uuid4(), name=body.name, kind=body.kind, enabled=body.enabled,
                             config=body.config, events=body.events, created_by_id=user.id)
    db.add(ch)
    _set_secret(db, ch, body.secret)
    audit.record(db, "notify.channel.create", user=user, source_ip=client_ip(request),
                 details={"channel": ch.name, "kind": ch.kind.value, "events": ch.events, "config": ch.config})
    db.commit()
    return _out(ch)


@router.patch("/channels/{channel_id}", response_model=ChannelOut)
def update_channel(channel_id: uuid.UUID, body: ChannelUpdate, user: Manager, request: Request, db: DB):
    ch = _get(db, channel_id)
    changes = body.model_dump(exclude_unset=True)
    try:
        if "config" in changes:
            _check_config(ch.kind, changes["config"] or {})
        if "events" in changes and set(changes["events"] or []) - set(notify.EVENT_TYPES):
            raise ValueError("unknown events")
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    secret_changed = "secret" in changes
    secret = changes.pop("secret", None)
    for k, v in changes.items():
        setattr(ch, k, v)
    if secret_changed:
        _set_secret(db, ch, secret)
    audit.record(db, "notify.channel.update", user=user, source_ip=client_ip(request),
                 details={"channel": ch.name, "changes": changes, "secret_changed": secret_changed})
    db.commit()
    return _out(ch)


@router.delete("/channels/{channel_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_channel(channel_id: uuid.UUID, user: Manager, request: Request, db: DB):
    ch = _get(db, channel_id)
    _set_secret(db, ch, None)
    audit.record(db, "notify.channel.delete", user=user, source_ip=client_ip(request), details={"channel": ch.name})
    db.delete(ch)
    db.commit()


@router.post("/channels/{channel_id}/test")
def test_channel(channel_id: uuid.UUID, user: Manager, request: Request, db: DB) -> dict:
    ch = _get(db, channel_id)
    ok, message = notify.test_channel(db, ch)
    ch.last_test_at, ch.last_test_ok, ch.last_test_error = utcnow(), ok, None if ok else message
    audit.record(db, "notify.channel.test", user=user, source_ip=client_ip(request),
                 details={"channel": ch.name, "ok": ok, "message": message})
    db.commit()
    return {"ok": ok, "message": message}


@router.get("/deliveries", response_model=Page[DeliveryOut])
def list_deliveries(_: Manager, db: DB, limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    total = db.scalar(select(func.count()).select_from(NotificationDelivery))
    rows = db.scalars(select(NotificationDelivery).order_by(NotificationDelivery.created_at.desc())
                      .limit(limit).offset(offset)).all()
    events = {e.id: e.title for e in db.scalars(select(NotificationEvent).where(
        NotificationEvent.id.in_({r.event_id for r in rows})))}
    chans = {c.id: c.name for c in db.scalars(select(NotificationChannel))}
    items = [DeliveryOut.model_validate(r).model_copy(update={"event_title": events.get(r.event_id),
                                                              "channel_name": chans.get(r.channel_id)}) for r in rows]
    return Page(items=items, total=total, limit=limit, offset=offset)


# --- in-app feed ---------------------------------------------------------------------------

@router.get("/events", response_model=Page[EventOut])
def list_events(_: Viewer, db: DB, limit: int = Query(default=30, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    total = db.scalar(select(func.count()).select_from(NotificationEvent))
    rows = db.scalars(select(NotificationEvent).order_by(NotificationEvent.created_at.desc())
                      .limit(limit).offset(offset)).all()
    return Page(items=rows, total=total, limit=limit, offset=offset)


@router.get("/unread-count")
def unread_count(user: Viewer, db: DB) -> dict:
    stmt = select(func.count()).select_from(NotificationEvent)
    if user.notifications_seen_at:
        stmt = stmt.where(NotificationEvent.created_at > user.notifications_seen_at)
    return {"unread": db.scalar(stmt)}


@router.post("/seen", status_code=status.HTTP_204_NO_CONTENT)
def mark_seen(user: CurrentUser, db: DB):
    user.notifications_seen_at = utcnow()
    db.commit()
