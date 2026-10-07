from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.enums import Role
from app.core.security import hash_password, validate_password_strength
from app.db.base import utcnow
from app.models.user import User
from app.schemas.user import normalize_email
from app.services import audit


def create_user(db: Session, email: str, full_name: str, password: str, role: Role) -> User:
    validate_password_strength(password)
    user = User(email=normalize_email(email), full_name=full_name, role=role,
                password_hash=hash_password(password), password_changed_at=utcnow())
    db.add(user)
    db.flush()
    audit.record(db, "user.create", username="system",
                 details={"target_user": user.email, "role": role.value, "source": "bootstrap"})
    return user


def bootstrap_admin(db: Session, email: str | None, password: str | None) -> User | None:
    """Create the first ADMIN from env vars, only when the users table is empty."""
    if not email or not password:
        return None
    if db.scalar(select(func.count()).select_from(User)):
        return None
    user = create_user(db, email, "Administrator", password, Role.ADMIN)
    db.commit()
    return user
