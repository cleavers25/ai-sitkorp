import uuid
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from app.core.enums import AIProviderKind
from app.schemas.assessment import AssetRef
from app.schemas.common import ORMModel


def _check_base_url(v: str | None) -> str | None:
    if not v:
        return None
    p = urlparse(v)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ValueError("base_url must be an absolute http(s) URL")
    return v.rstrip("/")


class ProviderFields(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    kind: AIProviderKind
    base_url: str | None = Field(default=None, max_length=512)
    model: str = Field(min_length=1, max_length=128)
    max_tokens: int = Field(default=8000, ge=256, le=64000)
    temperature: float | None = Field(default=None, ge=0, le=2)
    is_default: bool = False
    enabled: bool = True

    _url = field_validator("base_url")(_check_base_url)


class ProviderCreate(ProviderFields):
    api_key: str | None = Field(default=None, max_length=4096)  # write-only


class ProviderUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    base_url: str | None = Field(default=None, max_length=512)
    model: str | None = Field(default=None, min_length=1, max_length=128)
    max_tokens: int | None = Field(default=None, ge=256, le=64000)
    temperature: float | None = Field(default=None, ge=0, le=2)
    is_default: bool | None = None
    enabled: bool | None = None
    api_key: str | None = Field(default=None, max_length=4096)  # set to rotate; "" removes the key

    _url = field_validator("base_url")(_check_base_url)


class ProviderOut(ORMModel):
    id: uuid.UUID
    name: str
    kind: AIProviderKind
    base_url: str | None
    model: str
    max_tokens: int
    temperature: float | None
    is_default: bool
    enabled: bool
    has_api_key: bool
    last_test_at: datetime | None
    last_test_ok: bool | None
    last_test_error: str | None
    created_at: datetime


class ProviderBrief(BaseModel):
    """What chat users may see about the active provider (no URLs, no key state)."""

    name: str
    kind: AIProviderKind
    model: str


class ProviderTestOut(BaseModel):
    ok: bool
    message: str


class ConversationCreate(BaseModel):
    asset_id: uuid.UUID | None = None
    title: str | None = Field(default=None, max_length=255)


class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=8000)


class MessageOut(ORMModel):
    id: uuid.UUID
    position: int
    role: str
    content: str
    user_id: uuid.UUID | None
    created_at: datetime
    provider_name: str | None
    model: str | None
    tool_calls: list[dict[str, Any]]
    proposals: list[dict[str, Any]]
    usage: dict[str, Any]
    error: str | None


class ConversationOut(ORMModel):
    id: uuid.UUID
    asset_id: uuid.UUID | None
    asset: AssetRef | None = None
    title: str
    created_by_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    message_count: int = 0


class ConversationDetail(ConversationOut):
    messages: list[MessageOut]


class SendResult(BaseModel):
    messages: list[MessageOut]
