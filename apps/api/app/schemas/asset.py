import re
import uuid
from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

from app.core.enums import AssetStatus, AssetType, ConnectivityStatus, Criticality
from app.schemas.common import ORMModel

_HOSTNAME_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-:[]_")


class AssetBase(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    criticality: Criticality = Criticality.MEDIUM
    environment: str | None = Field(default=None, max_length=32)
    owner: str | None = Field(default=None, max_length=128)
    tags: list[str] = Field(default_factory=list, max_length=50)


class AssetUpdateBase(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4000)
    criticality: Criticality | None = None
    environment: str | None = Field(default=None, max_length=32)
    owner: str | None = Field(default=None, max_length=128)
    tags: list[str] | None = Field(default=None, max_length=50)


class AssetOut(ORMModel):
    id: uuid.UUID
    asset_type: AssetType
    name: str
    description: str | None
    status: AssetStatus
    criticality: Criticality
    environment: str | None
    owner: str | None
    tags: list[str]
    created_at: datetime
    updated_at: datetime
    last_assessed_at: datetime | None = None
    last_assessment_id: uuid.UUID | None = None


# --- Server ---------------------------------------------------------------

def _check_hostname(v: str | None) -> str | None:
    if v is not None and (not v or set(v) - _HOSTNAME_CHARS):
        raise ValueError("hostname must be a DNS name or IP address")
    return v


class ServerFields(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    ssh_username: str | None = Field(default=None, max_length=128)
    credential_id: uuid.UUID | None = None

    _host = field_validator("hostname")(_check_hostname)


class ServerCreate(AssetBase, ServerFields):
    pass


class ServerUpdate(AssetUpdateBase):
    hostname: str | None = Field(default=None, min_length=1, max_length=255)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_username: str | None = Field(default=None, max_length=128)
    credential_id: uuid.UUID | None = None

    _host = field_validator("hostname")(_check_hostname)


class ServerOut(AssetOut):
    hostname: str
    ssh_port: int
    ssh_username: str | None
    credential_id: uuid.UUID | None
    os_name: str | None
    os_version: str | None
    kernel: str | None
    host_key_fingerprint: str | None
    connectivity_status: ConnectivityStatus
    last_connectivity_check_at: datetime | None
    last_connectivity_error: str | None
    website_count: int = 0


# --- Website --------------------------------------------------------------

def _check_url(v: str | None) -> str | None:
    if v is None:
        return v
    parsed = urlparse(v)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("url must be an absolute http(s) URL")
    return v


_DOCROOT = re.compile(r"^/[A-Za-z0-9._@+\-/]+$")


def _check_docroot(v: str | None) -> str | None:
    # The path is later used (quoted) in SSH scan commands, so keep it strictly boring.
    if v is None or v == "":
        return None
    if not _DOCROOT.match(v) or "/../" in v + "/" or v.rstrip("/") == "":
        raise ValueError("document_root must be an absolute path (letters, digits, . _ - @ + /) without '..'")
    return v.rstrip("/")


class WebsiteFields(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    domain: str | None = Field(default=None, max_length=255)
    server_id: uuid.UUID | None = None
    application: str | None = Field(default=None, max_length=64)
    web_server: str | None = Field(default=None, max_length=32)
    runtime: str | None = Field(default=None, max_length=64)
    document_root: str | None = Field(default=None, max_length=1024)

    _url = field_validator("url")(_check_url)
    _root = field_validator("document_root")(_check_docroot)


class WebsiteCreate(AssetBase, WebsiteFields):
    name: str | None = Field(default=None, min_length=1, max_length=255)  # defaults to domain


class WebsiteUpdate(AssetUpdateBase):
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    domain: str | None = Field(default=None, max_length=255)
    server_id: uuid.UUID | None = None
    application: str | None = Field(default=None, max_length=64)
    web_server: str | None = Field(default=None, max_length=32)
    runtime: str | None = Field(default=None, max_length=64)
    document_root: str | None = Field(default=None, max_length=1024)

    _url = field_validator("url")(_check_url)
    _root = field_validator("document_root")(_check_docroot)


class ServerRef(ORMModel):
    id: uuid.UUID
    name: str
    hostname: str


class WebsiteOut(AssetOut):
    url: str
    domain: str
    server_id: uuid.UUID | None
    server: ServerRef | None
    application: str | None
    web_server: str | None
    runtime: str | None
    document_root: str | None


class JobOut(BaseModel):
    job_id: str
    status: str
    result: dict | None = None
