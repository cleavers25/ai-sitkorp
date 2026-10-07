import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.api.deps import DB, client_ip, require
from app.core.enums import MemoryKind
from app.core.rbac import Permission
from app.models.asset import Asset
from app.models.memory import Memory
from app.models.user import User
from app.schemas.common import ORMModel
from app.services import audit

router = APIRouter(prefix="/memories", tags=["memory"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Manager = Annotated[User, Depends(require(Permission.MEMORY_MANAGE))]
MAX_CONTENT = 2000


class MemoryCreate(BaseModel):
    asset_id: uuid.UUID | None = None
    kind: MemoryKind = MemoryKind.OPERATIONAL
    content: str = Field(min_length=3, max_length=MAX_CONTENT)
    source: str = Field(default="USER", pattern="^(USER|AI)$")


class MemoryUpdate(BaseModel):
    kind: MemoryKind | None = None
    content: str | None = Field(default=None, min_length=3, max_length=MAX_CONTENT)


class MemoryOut(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    kind: MemoryKind
    content: str
    source: str
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime


@router.get("", response_model=list[MemoryOut])
def list_memories(_: Viewer, db: DB, asset_id: uuid.UUID | None = None,
                  scope: str = Query(default="asset", pattern="^(asset|global)$")):
    stmt = select(Memory)
    if scope == "global":
        stmt = stmt.where(Memory.asset_id.is_(None))
    else:
        if asset_id is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "asset_id is required for scope=asset")
        stmt = stmt.where(Memory.asset_id == asset_id)
    return db.scalars(stmt.order_by(Memory.created_at.desc())).all()


@router.post("", response_model=MemoryOut, status_code=status.HTTP_201_CREATED)
def create_memory(body: MemoryCreate, user: Manager, request: Request, db: DB):
    if body.asset_id and db.get(Asset, body.asset_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "asset_id does not exist")
    m = Memory(id=uuid.uuid4(), asset_id=body.asset_id, kind=body.kind, content=body.content.strip(),
               source=body.source, created_by_id=user.id)
    db.add(m)
    audit.record(db, "memory.create", user=user, source_ip=client_ip(request), asset_id=body.asset_id,
                 details={"memory_id": str(m.id), "kind": m.kind.value, "source": m.source, "content": m.content[:300]})
    db.commit()
    return m


def _get(db, memory_id: uuid.UUID) -> Memory:
    m = db.get(Memory, memory_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Memory not found")
    return m


@router.patch("/{memory_id}", response_model=MemoryOut)
def update_memory(memory_id: uuid.UUID, body: MemoryUpdate, user: Manager, request: Request, db: DB):
    m = _get(db, memory_id)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(m, k, v.strip() if isinstance(v, str) else v)
    audit.record(db, "memory.update", user=user, source_ip=client_ip(request), asset_id=m.asset_id,
                 details={"memory_id": str(m.id), "kind": m.kind.value, "content": m.content[:300]})
    db.commit()
    return m


@router.delete("/{memory_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_memory(memory_id: uuid.UUID, user: Manager, request: Request, db: DB):
    m = _get(db, memory_id)
    audit.record(db, "memory.delete", user=user, source_ip=client_ip(request), asset_id=m.asset_id,
                 details={"memory_id": str(m.id), "content": m.content[:300]})
    db.delete(m)
    db.commit()
