import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser, client_ip, require
from app.core.enums import ActionKind, ActionState, AuditResult, RiskLevel
from app.core.rbac import Permission, has_permission
from app.db.base import utcnow
from app.models.action import Action
from app.models.asset import Asset
from app.models.user import User
from app.schemas.assessment import AssetRef
from app.schemas.common import ORMModel, Page
from app.services import actions as svc
from app.services import audit
from app.worker.tasks import execute_action_task

router = APIRouter(prefix="/actions", tags=["actions"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Requester = Annotated[User, Depends(require(Permission.ACTION_REQUEST))]
Approver = Annotated[User, Depends(require(Permission.ACTION_APPROVE))]


class ActionCreate(BaseModel):
    asset_id: uuid.UUID
    kind: ActionKind
    params: dict[str, Any] = Field(default_factory=dict)
    reason: str = Field(min_length=3, max_length=2000)
    finding_id: uuid.UUID | None = None


class Decision(BaseModel):
    note: str | None = Field(default=None, max_length=2000)


class ActionOut(ORMModel):
    id: uuid.UUID
    kind: ActionKind
    label: str = ""
    state: ActionState
    risk_level: RiskLevel
    asset_id: uuid.UUID | None
    asset: AssetRef | None = None
    server_id: uuid.UUID | None
    finding_id: uuid.UUID | None
    params: dict[str, Any]
    reason: str
    command_preview: str
    requested_by_id: uuid.UUID | None
    requested_by: str | None = None
    decided_by_id: uuid.UUID | None
    decided_by: str | None = None
    decided_at: datetime | None
    decision_note: str | None
    started_at: datetime | None
    finished_at: datetime | None
    result: dict[str, Any]
    error: str | None
    rollback_of_id: uuid.UUID | None
    rolled_back_by_id: uuid.UUID | None
    created_at: datetime


def _out(db, a: Action) -> ActionOut:
    asset = db.get(Asset, a.asset_id) if a.asset_id else None
    req = db.get(User, a.requested_by_id) if a.requested_by_id else None
    dec = db.get(User, a.decided_by_id) if a.decided_by_id else None
    return ActionOut.model_validate(a).model_copy(update={
        "label": svc.LABEL[a.kind], "asset": AssetRef.model_validate(asset) if asset else None,
        "requested_by": req.email if req else None, "decided_by": dec.email if dec else None})


def _get(db, action_id: uuid.UUID) -> Action:
    a = db.get(Action, action_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")
    return a


@router.get("", response_model=Page[ActionOut])
def list_actions(_: Viewer, db: DB, state: ActionState | None = None, asset_id: uuid.UUID | None = None,
                 limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    stmt = select(Action)
    if state:
        stmt = stmt.where(Action.state == state)
    if asset_id:
        stmt = stmt.where(Action.asset_id == asset_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Action.created_at.desc()).limit(limit).offset(offset)).all()
    return Page(items=[_out(db, a) for a in rows], total=total, limit=limit, offset=offset)


@router.get("/pending-count")
def pending_count(_: Viewer, db: DB) -> dict:
    return {"pending": db.scalar(select(func.count()).select_from(Action).where(
        Action.state == ActionState.PENDING_APPROVAL))}


@router.get("/{action_id}", response_model=ActionOut)
def get_action(action_id: uuid.UUID, _: Viewer, db: DB):
    return _out(db, _get(db, action_id))


@router.post("", response_model=ActionOut, status_code=status.HTTP_201_CREATED)
def request_action(body: ActionCreate, user: Requester, request: Request, db: DB):
    asset = db.get(Asset, body.asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    try:
        params = svc.validate(db, body.kind, asset, body.params)
        action = svc.create(db, kind=body.kind, asset=asset, params=params, reason=body.reason, user=user,
                            ip=client_ip(request), finding_id=body.finding_id)
    except svc.ActionError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))
    return _out(db, action)


@router.post("/{action_id}/approve", response_model=ActionOut)
def approve(action_id: uuid.UUID, body: Decision, user: Approver, request: Request, db: DB):
    a = _get(db, action_id)
    if a.state != ActionState.PENDING_APPROVAL:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Action is {a.state.value}")
    a.state, a.decided_by_id, a.decided_at, a.decision_note = ActionState.APPROVED, user.id, utcnow(), body.note
    audit.record(db, "action.approve", user=user, source_ip=client_ip(request), asset_id=a.asset_id,
                 tool=a.kind.value.lower(), risk_level=a.risk_level, approval_id=a.id,
                 details={"action_id": str(a.id), "note": body.note,
                          "self_approved": a.requested_by_id == user.id})
    db.commit()
    execute_action_task.delay(str(a.id))
    db.refresh(a)
    return _out(db, a)


@router.post("/{action_id}/reject", response_model=ActionOut)
def reject(action_id: uuid.UUID, body: Decision, user: Approver, request: Request, db: DB):
    a = _get(db, action_id)
    if a.state != ActionState.PENDING_APPROVAL:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Action is {a.state.value}")
    a.state, a.decided_by_id, a.decided_at, a.decision_note = ActionState.REJECTED, user.id, utcnow(), body.note
    audit.record(db, "action.reject", AuditResult.DENIED, user=user, source_ip=client_ip(request),
                 asset_id=a.asset_id, tool=a.kind.value.lower(), risk_level=a.risk_level, approval_id=a.id,
                 details={"action_id": str(a.id), "note": body.note})
    db.commit()
    return _out(db, a)


@router.post("/{action_id}/cancel", response_model=ActionOut)
def cancel(action_id: uuid.UUID, user: CurrentUser, request: Request, db: DB):
    a = _get(db, action_id)
    if a.state != ActionState.PENDING_APPROVAL:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Action is {a.state.value}")
    if a.requested_by_id != user.id and not has_permission(user.role, Permission.ACTION_APPROVE):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only the requester or an approver can cancel")
    a.state = ActionState.CANCELLED
    audit.record(db, "action.cancel", user=user, source_ip=client_ip(request), asset_id=a.asset_id,
                 details={"action_id": str(a.id)})
    db.commit()
    return _out(db, a)


@router.post("/{action_id}/rollback", response_model=ActionOut, status_code=status.HTTP_201_CREATED)
def rollback(action_id: uuid.UUID, user: Requester, request: Request, db: DB):
    try:
        new = svc.rollback_request(db, _get(db, action_id), user, client_ip(request))
    except svc.ActionError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc))
    return _out(db, new)
