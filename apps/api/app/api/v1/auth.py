from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from sqlalchemy import func, select

from app.api.deps import DB, CurrentUser, client_ip
from app.core.config import get_settings
from app.core.enums import AuditResult
from app.core.rbac import permissions_for
from app.core.security import create_access_token, hash_password, verify_password
from app.db.base import utcnow
from app.models.user import User
from app.schemas.user import LoginRequest, LoginResponse, MeOut, PasswordChange, UserOut
from app.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])

_INVALID = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")


def me_out(user: User) -> MeOut:
    base = UserOut.model_validate(user).model_dump()
    return MeOut(**base, permissions=permissions_for(user.role))


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request, response: Response, db: DB):
    settings = get_settings()
    ip = client_ip(request)
    email = body.email.lower()
    user = db.scalar(select(User).where(func.lower(User.email) == email))
    now = utcnow()

    password_ok = verify_password(body.password, user.password_hash if user else None)

    def fail(reason: str):
        audit.record(db, "auth.login", AuditResult.FAILURE, user=user, username=email,
                     source_ip=ip, details={"reason": reason})
        db.commit()
        raise _INVALID

    if user is None:
        fail("unknown_user")
    locked_until = user.locked_until
    if locked_until and locked_until.tzinfo is None:  # SQLite drops tzinfo
        locked_until = locked_until.replace(tzinfo=now.tzinfo)
    if locked_until and locked_until > now:
        fail("account_locked")
    if not user.is_active:
        fail("account_disabled")
    if not password_ok:
        user.failed_login_count += 1
        if user.failed_login_count >= settings.login_max_attempts:
            user.locked_until = now + timedelta(minutes=settings.login_lockout_minutes)
            user.failed_login_count = 0
            fail("bad_password_locked")
        fail("bad_password")

    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    token, expires = create_access_token(user.id, user.token_version)
    audit.record(db, "auth.login", user=user, source_ip=ip)
    db.commit()

    response.set_cookie(
        settings.cookie_name, token,
        httponly=True, secure=settings.cookie_secure, samesite="strict",
        max_age=settings.access_token_expire_minutes * 60, path="/",
    )
    return LoginResponse(access_token=token, expires_at=expires, user=me_out(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(user: CurrentUser, request: Request, response: Response, db: DB):
    # Invalidates every token issued to this user so far.
    user.token_version += 1
    audit.record(db, "auth.logout", user=user, source_ip=client_ip(request))
    db.commit()
    response.delete_cookie(get_settings().cookie_name, path="/")


@router.get("/me", response_model=MeOut)
def me(user: CurrentUser):
    return me_out(user)


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(body: PasswordChange, user: CurrentUser, request: Request,
                    response: Response, db: DB):
    if not verify_password(body.current_password, user.password_hash):
        audit.record(db, "auth.change_password", AuditResult.FAILURE, user=user,
                     source_ip=client_ip(request), details={"reason": "bad_current_password"})
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    user.password_changed_at = utcnow()
    user.token_version += 1
    audit.record(db, "auth.change_password", user=user, source_ip=client_ip(request))
    db.commit()
    response.delete_cookie(get_settings().cookie_name, path="/")
