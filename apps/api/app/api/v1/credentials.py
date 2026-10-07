import uuid
from typing import Annotated

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select

from app.api.deps import DB, client_ip, require
from app.core.enums import CredentialKind, RiskLevel
from app.core.rbac import Permission
from app.db.base import utcnow
from app.models.asset import Server
from app.models.credential import CredentialReference
from app.models.user import User
from app.schemas.credential import CredentialCreate, CredentialOut, CredentialRotate, SecretPayload
from app.services import audit
from app.services.secrets import get_secret_backend

router = APIRouter(prefix="/credentials", tags=["credentials"])
Viewer = Annotated[User, Depends(require(Permission.CREDENTIAL_VIEW))]
Manager = Annotated[User, Depends(require(Permission.CREDENTIAL_MANAGE))]


def _secret_dict(kind: CredentialKind, body: SecretPayload) -> tuple[dict, str | None]:
    """Validate secret material and return (secret, public fingerprint)."""
    if kind == CredentialKind.SSH_PRIVATE_KEY:
        if not body.private_key:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "private_key is required")
        try:
            key = asyncssh.import_private_key(body.private_key, body.passphrase)
        except (asyncssh.KeyImportError, ValueError):
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "private_key could not be parsed (wrong format or passphrase)")
        return ({"private_key": body.private_key, "passphrase": body.passphrase},
                key.get_fingerprint("sha256"))
    if kind == CredentialKind.SSH_PASSWORD:
        if not body.password:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "password is required")
        return {"password": body.password}, None
    if not body.api_key:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "api_key is required")
    return {"api_key": body.api_key}, None


def _get(db, credential_id: uuid.UUID) -> CredentialReference:
    cred = db.get(CredentialReference, credential_id)
    if cred is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Credential not found")
    return cred


@router.get("", response_model=list[CredentialOut])
def list_credentials(_: Viewer, db: DB):
    return db.scalars(select(CredentialReference).order_by(CredentialReference.name)).all()


@router.get("/{credential_id}", response_model=CredentialOut)
def get_credential(credential_id: uuid.UUID, _: Viewer, db: DB):
    return _get(db, credential_id)


@router.post("", response_model=CredentialOut, status_code=status.HTTP_201_CREATED)
def create_credential(body: CredentialCreate, user: Manager, request: Request, db: DB):
    if db.scalar(select(CredentialReference).where(CredentialReference.name == body.name)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Credential name already exists")
    secret, fingerprint = _secret_dict(body.kind, body)
    backend = get_secret_backend(db)
    cred_id = uuid.uuid4()
    cred = CredentialReference(
        id=cred_id, name=body.name, kind=body.kind, username=body.username,
        secret_backend=backend.name, secret_path=f"credentials/{cred_id}",
        access_scope=body.access_scope, description=body.description,
        public_fingerprint=fingerprint, created_by_id=user.id,
    )
    backend.put(cred.secret_path, secret)
    db.add(cred)
    audit.record(db, "credential.create", user=user, source_ip=client_ip(request),
                 risk_level=RiskLevel.LOW,
                 details={"credential": body.name, "kind": body.kind.value, "fingerprint": fingerprint})
    db.commit()
    return cred


@router.put("/{credential_id}/secret", response_model=CredentialOut)
def rotate_secret(credential_id: uuid.UUID, body: CredentialRotate, user: Manager,
                  request: Request, db: DB):
    cred = _get(db, credential_id)
    secret, fingerprint = _secret_dict(cred.kind, body)
    get_secret_backend(db).put(cred.secret_path, secret)
    cred.public_fingerprint = fingerprint
    cred.last_rotated_at = utcnow()
    audit.record(db, "credential.rotate", user=user, source_ip=client_ip(request),
                 risk_level=RiskLevel.LOW,
                 details={"credential": cred.name, "fingerprint": fingerprint})
    db.commit()
    return cred


@router.delete("/{credential_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_credential(credential_id: uuid.UUID, user: Manager, request: Request, db: DB):
    cred = _get(db, credential_id)
    in_use = db.scalar(select(func.count()).select_from(Server).where(Server.credential_id == cred.id))
    if in_use:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"Credential is used by {in_use} server(s); unassign it first")
    get_secret_backend(db).delete(cred.secret_path)
    db.delete(cred)
    audit.record(db, "credential.delete", user=user, source_ip=client_ip(request),
                 risk_level=RiskLevel.HIGH, details={"credential": cred.name})
    db.commit()
