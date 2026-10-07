import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ai import engine
from app.api.deps import DB, client_ip, require
from app.core.enums import RiskLevel, Role
from app.core.rbac import Permission
from app.db.base import utcnow
from app.models.ai import AIConversation, AIMessage, AIProvider
from app.models.asset import Asset
from app.models.user import User
from app.schemas.ai import (
    ConversationCreate, ConversationDetail, ConversationOut, MessageCreate, MessageOut, ProviderBrief,
    ProviderCreate, ProviderOut, ProviderTestOut, ProviderUpdate, SendResult,
)
from app.schemas.assessment import AssetRef
from app.services import audit
from app.services.secrets import get_secret_backend

router = APIRouter(prefix="/ai", tags=["ai"])
Configurer = Annotated[User, Depends(require(Permission.AI_CONFIG))]
Chatter = Annotated[User, Depends(require(Permission.ASSET_VIEW))]


# --- providers (ADMIN / SECURITY) --------------------------------------------------

def _provider_out(p: AIProvider) -> ProviderOut:
    fields = {f: getattr(p, f) for f in ProviderOut.model_fields if f != "has_api_key"}
    return ProviderOut(**fields, has_api_key=bool(p.secret_path))


def _get_provider(db: Session, provider_id: uuid.UUID) -> AIProvider:
    p = db.get(AIProvider, provider_id)
    if p is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Provider not found")
    return p


def _set_key(db: Session, p: AIProvider, api_key: str | None) -> None:
    backend = get_secret_backend(db)
    if api_key:
        p.secret_path = p.secret_path or f"ai-providers/{p.id}"
        backend.put(p.secret_path, {"api_key": api_key})
    elif p.secret_path:
        backend.delete(p.secret_path)
        p.secret_path = None


def _only_default(db: Session, p: AIProvider) -> None:
    if p.is_default:
        db.execute(update(AIProvider).where(AIProvider.id != p.id).values(is_default=False))


@router.get("/providers", response_model=list[ProviderOut])
def list_providers(_: Configurer, db: DB):
    return [_provider_out(p) for p in db.scalars(select(AIProvider).order_by(AIProvider.name))]


@router.get("/providers/active", response_model=ProviderBrief | None)
def active_provider(_: Chatter, db: DB):
    p = engine.default_provider(db)
    return ProviderBrief(name=p.name, kind=p.kind, model=p.model) if p else None


@router.post("/providers", response_model=ProviderOut, status_code=status.HTTP_201_CREATED)
def create_provider(body: ProviderCreate, user: Configurer, request: Request, db: DB):
    data = body.model_dump(exclude={"api_key"})
    p = AIProvider(id=uuid.uuid4(), created_by_id=user.id, **data)
    if db.scalar(select(func.count()).select_from(AIProvider)) == 0:
        p.is_default = True  # the first provider becomes the default
    db.add(p)
    _set_key(db, p, body.api_key)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Provider name already exists")
    _only_default(db, p)
    audit.record(db, "ai.provider.create", user=user, source_ip=client_ip(request), risk_level=RiskLevel.LOW,
                 details={"provider": p.name, "kind": p.kind.value, "model": p.model, "base_url": p.base_url,
                          "has_api_key": bool(body.api_key)})
    db.commit()
    return _provider_out(p)


@router.patch("/providers/{provider_id}", response_model=ProviderOut)
def update_provider(provider_id: uuid.UUID, body: ProviderUpdate, user: Configurer, request: Request, db: DB):
    p = _get_provider(db, provider_id)
    changes = body.model_dump(exclude_unset=True)
    key_changed = "api_key" in changes
    api_key = changes.pop("api_key", None)
    for k, v in changes.items():
        setattr(p, k, v)
    if key_changed:
        _set_key(db, p, api_key)
    _only_default(db, p)
    audit.record(db, "ai.provider.update", user=user, source_ip=client_ip(request), risk_level=RiskLevel.LOW,
                 details={"provider": p.name, "changes": changes, "api_key_changed": key_changed})
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Provider name already exists")
    return _provider_out(p)


@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(provider_id: uuid.UUID, user: Configurer, request: Request, db: DB):
    p = _get_provider(db, provider_id)
    _set_key(db, p, None)
    db.execute(update(AIConversation).where(AIConversation.provider_id == p.id).values(provider_id=None))
    audit.record(db, "ai.provider.delete", user=user, source_ip=client_ip(request), risk_level=RiskLevel.LOW,
                 details={"provider": p.name})
    db.delete(p)
    db.commit()


@router.post("/providers/{provider_id}/test", response_model=ProviderTestOut)
def test_provider(provider_id: uuid.UUID, user: Configurer, request: Request, db: DB):
    p = _get_provider(db, provider_id)
    ok, message = engine.test_provider(db, p)
    p.last_test_at, p.last_test_ok, p.last_test_error = utcnow(), ok, None if ok else message
    audit.record(db, "ai.provider.test", user=user, source_ip=client_ip(request),
                 details={"provider": p.name, "ok": ok})
    db.commit()
    return ProviderTestOut(ok=ok, message=message)


# --- conversations -----------------------------------------------------------------

def _can_access(conv: AIConversation, user: User) -> bool:
    # Asset chats are shared team history (PRD 19); global chats belong to their author.
    return conv.asset_id is not None or conv.created_by_id == user.id or user.role == Role.ADMIN


def _get_conv(db: Session, conv_id: uuid.UUID, user: User) -> AIConversation:
    conv = db.get(AIConversation, conv_id)
    if conv is None or not _can_access(conv, user):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Conversation not found")
    return conv


def _conv_out(db: Session, conv: AIConversation, count: int | None = None) -> ConversationOut:
    asset = db.get(Asset, conv.asset_id) if conv.asset_id else None
    return ConversationOut(
        id=conv.id, asset_id=conv.asset_id, asset=AssetRef.model_validate(asset) if asset else None,
        title=conv.title, created_by_id=conv.created_by_id, created_at=conv.created_at,
        updated_at=conv.updated_at, message_count=count if count is not None else len(conv.messages))


@router.get("/conversations", response_model=list[ConversationOut])
def list_conversations(
    user: Chatter, db: DB,
    asset_id: uuid.UUID | None = None,
    scope: str = Query(default="global", pattern="^(global|asset)$"),
    limit: int = Query(default=50, ge=1, le=200),
):
    stmt = select(AIConversation)
    if scope == "asset":
        if asset_id is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "asset_id is required for scope=asset")
        stmt = stmt.where(AIConversation.asset_id == asset_id)
    else:
        stmt = stmt.where(AIConversation.asset_id.is_(None), AIConversation.created_by_id == user.id)
    convs = db.scalars(stmt.order_by(AIConversation.updated_at.desc()).limit(limit)).all()
    counts = dict(db.execute(select(AIMessage.conversation_id, func.count()).where(
        AIMessage.conversation_id.in_([c.id for c in convs])).group_by(AIMessage.conversation_id)).all())
    return [_conv_out(db, c, counts.get(c.id, 0)) for c in convs]


@router.post("/conversations", response_model=ConversationOut, status_code=status.HTTP_201_CREATED)
def create_conversation(body: ConversationCreate, user: Chatter, db: DB):
    if body.asset_id and db.get(Asset, body.asset_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "asset_id does not exist")
    return _conv_out(db, engine.new_conversation(db, user, body.asset_id, body.title), 0)


@router.get("/conversations/{conv_id}", response_model=ConversationDetail)
def get_conversation(conv_id: uuid.UUID, user: Chatter, db: DB):
    conv = _get_conv(db, conv_id, user)
    return ConversationDetail(**_conv_out(db, conv).model_dump(), messages=conv.messages)


@router.post("/conversations/{conv_id}/messages", response_model=SendResult)
def send_message(conv_id: uuid.UUID, body: MessageCreate, user: Chatter, request: Request, db: DB):
    conv = _get_conv(db, conv_id, user)
    try:
        user_msg, bot_msg = engine.send(db, conv, user, body.content.strip(), client_ip(request))
    except engine.ChatError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    return SendResult(messages=[MessageOut.model_validate(user_msg), MessageOut.model_validate(bot_msg)])


@router.delete("/conversations/{conv_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_conversation(conv_id: uuid.UUID, user: Chatter, request: Request, db: DB):
    conv = _get_conv(db, conv_id, user)
    if conv.created_by_id != user.id and user.role != Role.ADMIN:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the author or an admin can delete a conversation")
    audit.record(db, "ai.conversation.delete", user=user, source_ip=client_ip(request), asset_id=conv.asset_id,
                 details={"conversation_id": str(conv.id), "title": conv.title})
    db.delete(conv)
    db.commit()
