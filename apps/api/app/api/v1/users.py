import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select

from app.api.deps import DB, client_ip, require
from app.core.enums import Role
from app.core.rbac import Permission
from app.core.security import hash_password
from app.db.base import utcnow
from app.models.user import User
from app.schemas.user import PasswordReset, UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])
Admin = Annotated[User, Depends(require(Permission.USER_MANAGE))]


def _get(db, user_id: uuid.UUID) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    return user


def _active_admin_count(db) -> int:
    return db.scalar(
        select(func.count()).select_from(User).where(User.role == Role.ADMIN, User.is_active)
    )


@router.get("", response_model=list[UserOut])
def list_users(_: Admin, db: DB):
    return db.scalars(select(User).order_by(User.email)).all()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, admin: Admin, request: Request, db: DB):
    email = body.email.lower()
    if db.scalar(select(User).where(func.lower(User.email) == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
    user = User(email=email, full_name=body.full_name, role=body.role,
                password_hash=hash_password(body.password), password_changed_at=utcnow())
    db.add(user)
    db.flush()
    audit.record(db, "user.create", user=admin, source_ip=client_ip(request),
                 details={"target_user": email, "role": body.role.value})
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: uuid.UUID, body: UserUpdate, admin: Admin, request: Request, db: DB):
    user = _get(db, user_id)
    changes = body.model_dump(exclude_unset=True)
    removes_admin = user.role == Role.ADMIN and user.is_active and (
        changes.get("role", Role.ADMIN) != Role.ADMIN or changes.get("is_active") is False
    )
    if removes_admin and _active_admin_count(db) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot remove the last active admin")

    for field, value in changes.items():
        setattr(user, field, value)
    if "role" in changes or changes.get("is_active") is False:
        user.token_version += 1  # force re-login with the new privileges
    audit.record(db, "user.update", user=admin, source_ip=client_ip(request),
                 details={"target_user": user.email,
                          "changes": {k: getattr(v, "value", v) for k, v in changes.items()}})
    db.commit()
    return user


@router.post("/{user_id}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
def reset_password(user_id: uuid.UUID, body: PasswordReset, admin: Admin, request: Request, db: DB):
    user = _get(db, user_id)
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = utcnow()
    user.token_version += 1
    user.failed_login_count = 0
    user.locked_until = None
    audit.record(db, "user.reset_password", user=admin, source_ip=client_ip(request),
                 details={"target_user": user.email})
    db.commit()
