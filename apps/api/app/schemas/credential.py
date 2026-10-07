import uuid
from datetime import datetime

from pydantic import BaseModel, Field, model_validator

from app.core.enums import CredentialKind
from app.schemas.common import ORMModel


class SecretPayload(BaseModel):
    """Write-only secret material. Never returned by any endpoint."""

    private_key: str | None = Field(default=None, max_length=16384)
    passphrase: str | None = Field(default=None, max_length=1024)
    password: str | None = Field(default=None, max_length=1024)
    api_key: str | None = Field(default=None, max_length=4096)


class CredentialCreate(SecretPayload):
    name: str = Field(min_length=1, max_length=128)
    kind: CredentialKind
    username: str | None = Field(default=None, max_length=128)
    access_scope: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)

    @model_validator(mode="after")
    def _secret_matches_kind(self):
        required = {
            CredentialKind.SSH_PRIVATE_KEY: "private_key",
            CredentialKind.SSH_PASSWORD: "password",
            CredentialKind.API_KEY: "api_key",
        }[self.kind]
        if not getattr(self, required):
            raise ValueError(f"{required} is required for {self.kind.value}")
        return self


class CredentialRotate(SecretPayload):
    pass


class CredentialOut(ORMModel):
    id: uuid.UUID
    name: str
    kind: CredentialKind
    username: str | None
    secret_backend: str
    access_scope: str | None
    description: str | None
    public_fingerprint: str | None
    last_rotated_at: datetime | None
    created_at: datetime
