import pytest

from app.core.enums import Role
from tests.conftest import login, make_user

SERVER = {"name": "web-01", "hostname": "10.0.0.1"}


@pytest.mark.parametrize("role,expected", [
    (Role.ADMIN, 201), (Role.INFRA, 201),
    (Role.SECURITY, 403), (Role.OPERATOR, 403), (Role.VIEWER, 403), (Role.AUDITOR, 403),
])
def test_asset_manage_permission(client, as_role, role, expected):
    r = client.post("/api/v1/servers", json=SERVER, headers=as_role(role))
    assert r.status_code == expected


@pytest.mark.parametrize("role,expected", [
    (Role.ADMIN, 200), (Role.SECURITY, 200), (Role.AUDITOR, 200),
    (Role.INFRA, 403), (Role.OPERATOR, 403), (Role.VIEWER, 403),
])
def test_audit_view_permission(client, as_role, role, expected):
    assert client.get("/api/v1/audit-logs", headers=as_role(role)).status_code == expected


def test_only_admin_manages_users(client, admin, as_role):
    assert client.get("/api/v1/users", headers=as_role(Role.INFRA)).status_code == 403
    r = client.post("/api/v1/users", headers=admin, json={
        "email": "new@example.com", "full_name": "New", "role": "OPERATOR", "password": "N3w!Password12"})
    assert r.status_code == 201
    assert "password_hash" not in r.json()
    dup = client.post("/api/v1/users", headers=admin, json={
        "email": "NEW@example.com", "full_name": "New", "role": "OPERATOR", "password": "N3w!Password12"})
    assert dup.status_code == 409


def test_role_change_forces_relogin(client, admin):
    make_user(Role.VIEWER, "v@example.com")
    v_headers = login(client, "v@example.com")
    client.cookies.clear()
    users = client.get("/api/v1/users", headers=admin).json()
    vid = next(u["id"] for u in users if u["email"] == "v@example.com")
    assert client.patch(f"/api/v1/users/{vid}", headers=admin, json={"role": "INFRA"}).status_code == 200
    assert client.get("/api/v1/auth/me", headers=v_headers).status_code == 401


def test_cannot_remove_last_admin(client, admin):
    users = client.get("/api/v1/users", headers=admin).json()
    aid = users[0]["id"]
    r = client.patch(f"/api/v1/users/{aid}", headers=admin, json={"role": "VIEWER"})
    assert r.status_code == 400
    r = client.patch(f"/api/v1/users/{aid}", headers=admin, json={"is_active": False})
    assert r.status_code == 400


def test_disabled_user_cannot_login(client, admin):
    make_user(Role.VIEWER, "v@example.com")
    client.cookies.clear()
    vid = next(u["id"] for u in client.get("/api/v1/users", headers=admin).json()
               if u["email"] == "v@example.com")
    client.patch(f"/api/v1/users/{vid}", headers=admin, json={"is_active": False})
    r = client.post("/api/v1/auth/login", json={"email": "v@example.com", "password": "Str0ng!Passw0rd"})
    assert r.status_code == 401
