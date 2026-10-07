from app.core.enums import Role
from tests.conftest import PASSWORD, login, make_user


def test_login_me_and_permissions(client):
    make_user(Role.OPERATOR, "op@example.com")
    headers = login(client, "OP@example.com")  # email is case-insensitive
    me = client.get("/api/v1/auth/me", headers=headers).json()
    assert me["role"] == "OPERATOR"
    assert "tool:run_safe" in me["permissions"]
    assert "asset:manage" not in me["permissions"]


def test_internal_email_domains_accepted(client):
    # *.local / *.internal are common on-prem and must not be rejected as "special-use".
    make_user(Role.VIEWER, "admin@corp.local")
    login(client, "admin@corp.local")


def test_login_sets_httponly_cookie(client):
    make_user(Role.VIEWER, "v@example.com")
    r = client.post("/api/v1/auth/login", json={"email": "v@example.com", "password": PASSWORD})
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=strict" in cookie
    # the cookie alone authenticates
    assert client.get("/api/v1/auth/me").status_code == 200


def test_wrong_password_and_unknown_user_look_identical(client):
    make_user(Role.VIEWER, "v@example.com")
    a = client.post("/api/v1/auth/login", json={"email": "v@example.com", "password": "nope"})
    b = client.post("/api/v1/auth/login", json={"email": "ghost@example.com", "password": "nope"})
    assert a.status_code == b.status_code == 401
    assert a.json() == b.json()


def test_lockout_after_repeated_failures(client):
    make_user(Role.VIEWER, "v@example.com")
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": "v@example.com", "password": "wrong"})
    r = client.post("/api/v1/auth/login", json={"email": "v@example.com", "password": PASSWORD})
    assert r.status_code == 401


def test_logout_revokes_token(client):
    make_user(Role.VIEWER, "v@example.com")
    headers = login(client, "v@example.com")
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 204
    client.cookies.clear()
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_change_password(client):
    make_user(Role.VIEWER, "v@example.com")
    headers = login(client, "v@example.com")
    bad = client.post("/api/v1/auth/change-password", headers=headers,
                      json={"current_password": "wrong", "new_password": "An0ther!Passw0rd"})
    assert bad.status_code == 400
    weak = client.post("/api/v1/auth/change-password", headers=headers,
                       json={"current_password": PASSWORD, "new_password": "short"})
    assert weak.status_code == 422
    ok = client.post("/api/v1/auth/change-password", headers=headers,
                     json={"current_password": PASSWORD, "new_password": "An0ther!Passw0rd"})
    assert ok.status_code == 204
    login(client, "v@example.com", "An0ther!Passw0rd")


def test_unauthenticated_requests_rejected(client):
    assert client.get("/api/v1/servers").status_code == 401
    assert client.get("/api/v1/servers", headers={"Authorization": "Bearer garbage"}).status_code == 401
