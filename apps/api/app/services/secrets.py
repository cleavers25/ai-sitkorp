"""Secret storage behind a pluggable backend (PRD 8.2).

Phase 1 ships LocalEncryptedBackend (AES-256-GCM, master key from SECRET_MASTER_KEY).
An OpenBao/Vault backend can implement the same interface later without touching callers.
"""

import json
import os
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.credential import EncryptedSecret


class SecretBackend(Protocol):
    name: str

    def put(self, path: str, value: dict[str, Any]) -> None: ...
    def get(self, path: str) -> dict[str, Any]: ...
    def delete(self, path: str) -> None: ...


class SecretNotFound(Exception):
    pass


class LocalEncryptedBackend:
    name = "local-aes-gcm"
    KEY_VERSION = 1

    def __init__(self, db: Session, master_key: bytes | None = None):
        self.db = db
        self._aead = AESGCM(master_key or get_settings().master_key_bytes)

    def put(self, path: str, value: dict[str, Any]) -> None:
        nonce = os.urandom(12)
        # The path is bound as associated data so ciphertext cannot be swapped between rows.
        ciphertext = self._aead.encrypt(nonce, json.dumps(value).encode(), path.encode())
        row = self.db.get(EncryptedSecret, path)
        if row is None:
            row = EncryptedSecret(path=path)
            self.db.add(row)
        row.nonce = nonce
        row.ciphertext = ciphertext
        row.key_version = self.KEY_VERSION

    def get(self, path: str) -> dict[str, Any]:
        row = self.db.get(EncryptedSecret, path)
        if row is None:
            raise SecretNotFound(path)
        return json.loads(self._aead.decrypt(row.nonce, row.ciphertext, path.encode()))

    def delete(self, path: str) -> None:
        row = self.db.get(EncryptedSecret, path)
        if row is not None:
            self.db.delete(row)


def get_secret_backend(db: Session) -> SecretBackend:
    return LocalEncryptedBackend(db)
