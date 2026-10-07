import base64
import os
import tempfile

os.environ.update({
    "DATABASE_URL": "sqlite://",
    "JWT_SECRET": "test-jwt-secret-that-is-long-enough-000",
    "SECRET_MASTER_KEY": base64.b64encode(b"k" * 32).decode(),
    "CELERY_TASK_ALWAYS_EAGER": "true",
    "BACKUP_DIR": tempfile.mkdtemp(prefix="aiinfra-backups-"),
    "BOOTSTRAP_ADMIN_EMAIL": "",
    "BOOTSTRAP_ADMIN_PASSWORD": "",
})

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import event  # noqa: E402

from app.core.enums import Role  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.users import create_user  # noqa: E402

PASSWORD = "Str0ng!Passw0rd"


@event.listens_for(engine, "connect")
def _sqlite_fks(dbapi_conn, _):
    # Enforce foreign keys like PostgreSQL does, so insert-order bugs show up in tests.
    dbapi_conn.execute("PRAGMA foreign_keys=ON")


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


def make_user(role: Role, email: str | None = None) -> str:
    email = email or f"{role.value.lower()}@example.com"
    with SessionLocal() as s:
        create_user(s, email, role.value.title(), PASSWORD, role)
        s.commit()
    return email


def login(client: TestClient, email: str, password: str = PASSWORD) -> dict:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def as_role(client):
    """Return auth headers for a freshly created user of the given role."""
    def _as(role: Role) -> dict:
        return login(client, make_user(role))
    return _as


@pytest.fixture
def admin(as_role):
    return as_role(Role.ADMIN)
