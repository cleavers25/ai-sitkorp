import uuid

import pytest

from app.assessment import engine as assessment_engine
from app.assessment.types import passed
from app.core.enums import ActionKind, Role
from app.core.enums import FindingCategory as C
from app.models.asset import Server, Website
from app.services import actions as svc
from app.services.ssh_client import CommandResult

ROOT = "/var/www/site"
SHELL = f"{ROOT}/wp-content/uploads/2026/09/cache.php"


@pytest.fixture
def fake_ssh(monkeypatch):
    calls = {"cmds": [], "replies": None}

    def run(db, server, cmds):
        calls["cmds"].append([c for _, c in cmds])
        replies = calls["replies"] or []
        return [CommandResult(c, code, out, err, False) for (_, c), (code, out, err) in zip(cmds, replies)]

    monkeypatch.setattr(svc, "_run", run)
    monkeypatch.setattr(assessment_engine._Collector, "collect",
                        lambda self, asset: [passed("http_availability", C.WEB, "ok")])
    return calls


def setup_site(client, headers, db, pinned=True):
    cred = client.post("/api/v1/credentials", headers=headers, json={
        "name": "ops", "kind": "SSH_PASSWORD", "username": "ops", "password": "x-secret"}).json()
    srv = client.post("/api/v1/servers", headers=headers, json={
        "name": "lab", "hostname": "10.0.0.7", "credential_id": cred["id"]}).json()
    if pinned:
        s = db.get(Server, uuid.UUID(srv["id"]))
        s.host_key, s.host_key_fingerprint = "ssh-ed25519 AAAA", "SHA256:x"
        db.commit()
    site = client.post("/api/v1/websites", headers=headers, json={
        "url": "https://toko.example", "server_id": srv["id"], "document_root": ROOT}).json()
    return srv, site


# --- validation ----------------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/etc/passwd", "/var/www/other/x.php", f"{ROOT}/../../etc/shadow", f"{ROOT}/a;rm -rf /", f"{ROOT}/$(id)",
    f"{ROOT}/", "relative.php", f"{ROOT}/.ssh/authorized_keys", f"{ROOT}//x.php",
])
def test_website_paths_are_confined_to_docroot(path):
    site = Website(name="w", url="https://w", domain="w", document_root=ROOT)
    with pytest.raises(svc.ActionError):
        svc.validate_path(site, path)


def test_server_paths_and_service_names():
    srv = Server(name="s", hostname="h")
    assert svc.validate_path(srv, "/tmp/xmrig") == "/tmp/xmrig"
    for bad in ("/usr/bin/sudo", "/root/x", "/home/ops/.ssh/id_rsa"):
        with pytest.raises(svc.ActionError):
            svc.validate_path(srv, bad)
    assert svc.validate(None, ActionKind.RESTART_SERVICE, srv, {"service": "php8.2-fpm.service"})
    for bad in ("nginx; reboot", "-x", "a b", ""):
        with pytest.raises(svc.ActionError):
            svc.validate(None, ActionKind.RESTART_SERVICE, srv, {"service": bad})


def test_preview_quotes_paths():
    a = svc.Action(id=uuid.uuid4(), kind=ActionKind.QUARANTINE_FILE, params={"path": f"{ROOT}/file with space.php"})
    prev = svc.preview(a)
    assert f"'{ROOT}/file with space.php'" in prev and "rm " not in prev and "mv --" in prev


# --- workflow -----------------------------------------------------------------------

def test_quarantine_request_approve_execute_and_rollback(client, admin, db, fake_ssh):
    srv, site = setup_site(client, admin, db)
    r = client.post("/api/v1/actions", headers=admin, json={
        "asset_id": site["id"], "kind": "QUARANTINE_FILE", "params": {"path": SHELL}, "reason": "webshell terdeteksi"})
    assert r.status_code == 201, r.text
    a = r.json()
    assert a["state"] == "PENDING_APPROVAL" and a["risk_level"] == "HIGH" and "aiinfra-quarantine" in a["command_preview"]
    assert fake_ssh["cmds"] == []  # nothing runs before approval

    fake_ssh["replies"] = [
        (0, f"{SHELL}|181|1790000000|ops|ops|644\n{'b' * 64}  {SHELL}\n", ""),
        (0, "/home/ops/.aiinfra-quarantine/abc\n", ""),
        (0, "OK\n", ""),
    ]
    done = client.post(f"/api/v1/actions/{a['id']}/approve", headers=admin, json={"note": "ok, sudah dicek"}).json()
    done = client.get(f"/api/v1/actions/{a['id']}", headers=admin).json()
    assert done["state"] == "SUCCEEDED", done["error"]
    assert done["result"]["original_mode"] == "644" and done["result"]["sha256"] == "b" * 64
    assert done["decided_by"] == "admin@example.com"
    # re-assessment queued automatically after the change (PRD 49)
    assert client.get(f"/api/v1/assessments?asset_id={site['id']}", headers=admin).json()["items"][0]["trigger"] == "POST_ACTION"

    rb = client.post(f"/api/v1/actions/{a['id']}/rollback", headers=admin).json()
    assert rb["kind"] == "RESTORE_QUARANTINE" and rb["params"]["mode"] == "644" and rb["state"] == "PENDING_APPROVAL"
    assert client.post(f"/api/v1/actions/{a['id']}/rollback", headers=admin).status_code == 409  # only once

    logs = [e["action"] for e in client.get("/api/v1/audit-logs?action=action.", headers=admin).json()["items"]]
    assert {"action.request", "action.approve", "action.execute"} <= set(logs)

    # The AI sees remediation history, so a deliberate rollback is not mistaken for reinfection.
    from app.ai import tools
    ctx = tools.ToolContext(db=db, scope_asset_id=uuid.UUID(site["id"]), proposals=[])
    history = tools.get_asset(ctx, {})["recent_actions"]
    assert history[0].split(" ", 2)[2].startswith("RESTORE_QUARANTINE") and "QUARANTINE_FILE" in history[1]


def test_failed_verification_marks_failed(client, admin, db, fake_ssh):
    _, site = setup_site(client, admin, db)
    a = client.post("/api/v1/actions", headers=admin, json={
        "asset_id": site["id"], "kind": "RESTRICT_FILE", "params": {"path": f"{ROOT}/.env"}, "reason": ".env bocor"}).json()
    fake_ssh["replies"] = [(0, "644|ops|ops\n", ""), (1, "", "chmod: Operation not permitted"), (0, "", "")]
    client.post(f"/api/v1/actions/{a['id']}/approve", headers=admin, json={})
    got = client.get(f"/api/v1/actions/{a['id']}", headers=admin).json()
    assert got["state"] == "FAILED" and "Operation not permitted" in got["error"]


def test_unpinned_host_key_refuses_to_execute(client, admin, db, fake_ssh, monkeypatch):
    monkeypatch.undo()  # use the real _run guard
    _, site = setup_site(client, admin, db, pinned=False)
    monkeypatch.setattr(assessment_engine._Collector, "collect", lambda self, asset: [])
    a = client.post("/api/v1/actions", headers=admin, json={
        "asset_id": site["id"], "kind": "RESTART_SERVICE", "params": {"service": "nginx"}, "reason": "nginx mati"}).json()
    client.post(f"/api/v1/actions/{a['id']}/approve", headers=admin, json={})
    got = client.get(f"/api/v1/actions/{a['id']}", headers=admin).json()
    assert got["state"] == "FAILED" and "Tes koneksi" in got["error"]


def test_permissions_reject_and_cancel(client, admin, as_role, db, fake_ssh):
    _, site = setup_site(client, admin, db)
    body = {"asset_id": site["id"], "kind": "RESTART_SERVICE", "params": {"service": "nginx"}, "reason": "nginx failed"}
    assert client.post("/api/v1/actions", headers=as_role(Role.OPERATOR), json=body).status_code == 403
    infra = as_role(Role.INFRA)
    a = client.post("/api/v1/actions", headers=infra, json=body).json()
    assert client.post(f"/api/v1/actions/{a['id']}/approve", headers=infra, json={}).status_code == 403
    security = as_role(Role.SECURITY)
    rej = client.post(f"/api/v1/actions/{a['id']}/reject", headers=security, json={"note": "bukan jam maintenance"}).json()
    assert rej["state"] == "REJECTED" and fake_ssh["cmds"] == []
    b = client.post("/api/v1/actions", headers=infra, json=body).json()
    assert client.post(f"/api/v1/actions/{b['id']}/cancel", headers=infra).json()["state"] == "CANCELLED"
    assert client.get("/api/v1/actions/pending-count", headers=admin).json() == {"pending": 0}


def test_invalid_path_rejected_at_request_time(client, admin, db, fake_ssh):
    _, site = setup_site(client, admin, db)
    r = client.post("/api/v1/actions", headers=admin, json={
        "asset_id": site["id"], "kind": "QUARANTINE_FILE", "params": {"path": "/etc/passwd"}, "reason": "coba"})
    assert r.status_code == 422
