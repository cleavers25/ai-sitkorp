import json

import asyncssh
import pytest
from cryptography.exceptions import InvalidTag

from app.core.redaction import REDACTED, redact
from app.models.audit import AuditLog
from app.models.credential import EncryptedSecret
from app.services.secrets import LocalEncryptedBackend

PRIVATE_KEY = asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()


def _create_key_cred(client, headers, name="deploy-key"):
    r = client.post("/api/v1/credentials", headers=headers, json={
        "name": name, "kind": "SSH_PRIVATE_KEY", "username": "deploy", "private_key": PRIVATE_KEY})
    assert r.status_code == 201, r.text
    return r.json()


def test_secret_never_returned_or_stored_in_plaintext(client, admin, db):
    cred = _create_key_cred(client, admin)
    assert cred["public_fingerprint"].startswith("SHA256:")
    body = json.dumps(client.get("/api/v1/credentials", headers=admin).json())
    assert "PRIVATE KEY" not in body

    row = db.get(EncryptedSecret, f"credentials/{cred['id']}")
    assert b"PRIVATE KEY" not in row.ciphertext
    for entry in db.query(AuditLog).all():
        assert "PRIVATE KEY" not in json.dumps(entry.details)


def test_invalid_key_and_missing_secret_rejected(client, admin):
    r = client.post("/api/v1/credentials", headers=admin, json={
        "name": "bad", "kind": "SSH_PRIVATE_KEY", "private_key": "not a key"})
    assert r.status_code == 422
    r = client.post("/api/v1/credentials", headers=admin, json={"name": "pw", "kind": "SSH_PASSWORD"})
    assert r.status_code == 422


def test_rotate_and_delete_in_use(client, admin):
    cred = _create_key_cred(client, admin)
    new_key = asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()
    r = client.put(f"/api/v1/credentials/{cred['id']}/secret", headers=admin, json={"private_key": new_key})
    assert r.status_code == 200
    assert r.json()["public_fingerprint"] != cred["public_fingerprint"]
    assert r.json()["last_rotated_at"]

    s = client.post("/api/v1/servers", headers=admin, json={
        "name": "web-01", "hostname": "10.0.0.1", "credential_id": cred["id"]}).json()
    assert client.delete(f"/api/v1/credentials/{cred['id']}", headers=admin).status_code == 409
    client.patch(f"/api/v1/servers/{s['id']}", headers=admin, json={"credential_id": None})
    assert client.delete(f"/api/v1/credentials/{cred['id']}", headers=admin).status_code == 204


def test_api_key_cannot_be_used_as_ssh_credential(client, admin):
    r = client.post("/api/v1/credentials", headers=admin, json={
        "name": "openai", "kind": "API_KEY", "api_key": "sk-test"})
    s = client.post("/api/v1/servers", headers=admin, json={
        "name": "web-01", "hostname": "10.0.0.1", "credential_id": r.json()["id"]})
    assert s.status_code == 422


def test_aes_gcm_roundtrip_and_path_binding(db):
    backend = LocalEncryptedBackend(db, b"k" * 32)
    backend.put("a", {"password": "p@ss"})
    db.flush()
    assert backend.get("a") == {"password": "p@ss"}

    # Moving ciphertext to another path must fail authentication.
    src = db.get(EncryptedSecret, "a")
    db.add(EncryptedSecret(path="b", nonce=src.nonce, ciphertext=src.ciphertext, key_version=1))
    db.flush()
    with pytest.raises(InvalidTag):
        backend.get("b")
    # A different master key cannot decrypt.
    with pytest.raises(InvalidTag):
        LocalEncryptedBackend(db, b"z" * 32).get("a")


def test_redaction():
    data = {"user": "x", "password": "p", "nested": {"api_key": "k", "note": PRIVATE_KEY}, "list": [{"token": 1}]}
    out = redact(data)
    assert out["user"] == "x"
    assert out["password"] == REDACTED
    assert out["nested"]["api_key"] == REDACTED
    assert "PRIVATE KEY" not in out["nested"]["note"]
    assert out["list"][0]["token"] == REDACTED
