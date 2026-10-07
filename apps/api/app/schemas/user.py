import re
import uuid
from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field, field_validator

from app.core.enums import Role
from app.core.security import validate_password_strength
from app.schemas.common import ORMModel

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    # Deliberately looser than EmailStr: internal domains such as *.local or *.internal
    # are normal on-premise but rejected by email-validator as special-use names.
    value = value.strip().lower()
    if not _EMAIL.match(value):
        raise ValueError("value is not a valid email address")
    return value


EmailAddress = Annotated[str, Field(max_length=255), AfterValidator(normalize_email)]


class LoginRequest(BaseModel):
    email: EmailAddress
    password: str = Field(min_length=1, max_length=256)


class UserOut(ORMModel):
    id: uuid.UUID
    email: str
    full_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class MeOut(UserOut):
    permissions: list[str]


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime
    user: MeOut


class UserCreate(BaseModel):
    email: EmailAddress
    full_name: str = Field(min_length=1, max_length=255)
    role: Role = Role.VIEWER
    password: str = Field(max_length=256)

    _strong = field_validator("password")(validate_password_strength)


class UserUpdate(BaseModel):
    full_name: str | None = Field(default=None, min_length=1, max_length=255)
    role: Role | None = None
    is_active: bool | None = None


class PasswordReset(BaseModel):
    new_password: str = Field(max_length=256)

    _strong = field_validator("new_password")(validate_password_strength)


class PasswordChange(PasswordReset):
    current_password: str = Field(max_length=256)
