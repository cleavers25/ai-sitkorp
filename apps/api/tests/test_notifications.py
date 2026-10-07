import hashlib
import hmac
import json

import httpx
import pytest

from app.assessment import engine as assessment_engine
from app.assessment.types import issue
from app.core.enums import FindingCategory as C
from app.core.enums import Role
from app.core.enums import Severity as S
from app.services import notify

SCRIPT: list = []


@pytest.fixture(autouse=True)
def scripted(monkeypatch):
    SCRIPT.clear()
    monkeypatch.setattr(assessment_engine._Collector, "collect", lambda self, asset: SCRIPT.pop(0))


@pytest.fixture
def hook(monkeypatch):
    """Capture outgoing HTTP (webhook/Telegram) and SMTP traffic."""
    sent = {"http": [], "smtp": [], "status": 200}

    def handler(request: httpx.Request):
        sent["http"].append(request)
        if "api.telegram.org" in str(request.url):
            return httpx.Response(sent["status"], json={"ok": sent["status"] == 200, "description": "Bad Request: chat not found"})
        return httpx.Response(sent["status"], text="ok")

    class FakeSMTP:
        def __init__(self, host, port, timeout=None, context=None):
            sent["smtp"].append({"host": host, "port": port, "calls": []})

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self, context=None):
            sent["smtp"][-1]["calls"].append("starttls")

        def login(self, user, password):
            sent["smtp"][-1]["calls"].append(("login", user, password))

        def send_message(self, msg):
            sent["smtp"][-1]["msg"] = msg

    monkeypatch.setattr(notify, "HTTP_TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(notify.smtplib, "SMTP", FakeSMTP)
    return sent


def channel(client, headers, **kw):
    r = client.post("/api/v1/notifications/channels", headers=headers, json=kw)
    assert r.status_code == 201, r.text
    return r.json()


def red_results():
    return [issue("malware_file", C.MALWARE, "Dugaan malware: /x.php", S.CRITICAL, target="/x.php"),
            issue("ssl_certificate", C.SSL, "SSL kedaluwarsa dalam 5 hari", S.HIGH, target="https://a"),
            issue("exposed_file", C.CONFIGURATION, "File .env terekspos", S.CRITICAL, target="https://a/.env")]


def test_channel_validation_secret_and_permissions(client, admin, as_role):
    ch = channel(client, admin, name="SMTP kantor", kind="EMAIL", events=["asset_red"], secret="smtp-pass-123",
                 config={"host": "smtp.corp.local", "port": 587, "security": "starttls", "username": "noreply",
                         "from_address": "noreply@corp.local", "to": ["soc@corp.local"]})
    assert ch["has_secret"] and "smtp-pass-123" not in json.dumps(ch)
    bad = [{"name": "a", "kind": "EMAIL", "config": {"evil": 1}},
           {"name": "b", "kind": "EMAIL", "config": {"security": "tls13"}},
           {"name": "c", "kind": "WEBHOOK", "config": {"url": "ftp://x"}},
           {"name": "d", "kind": "WEBHOOK", "events": ["nope"]}]
    for b in bad:
        assert client.post("/api/v1/notifications/channels", headers=admin, json=b).status_code == 422, b
    assert client.get("/api/v1/notifications/channels", headers=as_role(Role.INFRA)).status_code == 403
    logs = client.get("/api/v1/audit-logs?action=notify.", headers=admin).json()
    assert "smtp-pass-123" not in json.dumps(logs)


def test_email_and_signed_webhook_on_asset_turning_red(client, admin, hook):
    channel(client, admin, name="SMTP", kind="EMAIL", events=["asset_red", "malware"], secret="pw",
            config={"host": "smtp.corp.local", "port": 587, "username": "bot", "from_address": "bot@corp.local",
                    "to": ["soc@corp.local", "infra@corp.local"]})
    channel(client, admin, name="SOAR", kind="WEBHOOK", events=["malware", "ssl", "new_findings"],
            secret="s3cret-sign", config={"url": "https://soar.corp.local/hook"})
    s = client.post("/api/v1/servers", headers=admin, json={"name": "web-01", "hostname": "10.0.0.1"}).json()

    SCRIPT.append(red_results())
    client.post(f"/api/v1/assets/{s['id']}/assess", headers=admin)

    # Email: asset_red + malware, via STARTTLS with the stored password.
    subjects = sorted(m["msg"]["Subject"] for m in hook["smtp"])
    assert subjects == ["[AI Infra][CRITICAL] Dugaan malware di web-01", "[AI Infra][HIGH] web-01 berubah menjadi RED"]
    assert hook["smtp"][0]["calls"][:2] == ["starttls", ("login", "bot", "pw")]
    assert hook["smtp"][0]["msg"]["To"] == "soc@corp.local, infra@corp.local"

    # Webhook: malware + ssl + new_findings (.env), each signed with HMAC-SHA256.
    types = sorted(r.headers["X-AIInfra-Event"] for r in hook["http"])
    assert types == ["malware", "new_findings", "ssl"]
    for r in hook["http"]:
        expected = "sha256=" + hmac.new(b"s3cret-sign", r.content, hashlib.sha256).hexdigest()
        assert r.headers["X-AIInfra-Signature"] == expected
    payload = json.loads(next(r for r in hook["http"] if r.headers["X-AIInfra-Event"] == "malware").content)
    assert payload["severity"] == "CRITICAL" and "/x.php" in payload["body"]

    # Same results again: nothing new → nothing sent (change-based, no spam).
    before = (len(hook["smtp"]), len(hook["http"]))
    SCRIPT.append(red_results())
    client.post(f"/api/v1/assets/{s['id']}/assess", headers=admin)
    assert (len(hook["smtp"]), len(hook["http"])) == before

    deliveries = client.get("/api/v1/notifications/deliveries", headers=admin).json()
    assert deliveries["total"] == 5 and {d["state"] for d in deliveries["items"]} == {"SENT"}


def test_in_app_feed_and_unread(client, admin, hook):
    s = client.post("/api/v1/servers", headers=admin, json={"name": "web-02", "hostname": "10.0.0.2"}).json()
    SCRIPT.append(red_results())
    client.post(f"/api/v1/assets/{s['id']}/assess", headers=admin)
    events = client.get("/api/v1/notifications/events", headers=admin).json()
    assert {e["type"] for e in events["items"]} == {"asset_red", "malware", "ssl", "new_findings"}
    assert client.get("/api/v1/notifications/unread-count", headers=admin).json()["unread"] == 4
    client.post("/api/v1/notifications/seen", headers=admin)
    assert client.get("/api/v1/notifications/unread-count", headers=admin).json()["unread"] == 0


def test_slack_format_telegram_and_failures(client, admin, hook):
    slack = channel(client, admin, name="Mattermost", kind="WEBHOOK", events=["asset_red"],
                    config={"url": "https://chat.corp.local/hooks/x", "format": "slack"})
    tg = channel(client, admin, name="Telegram SOC", kind="TELEGRAM", events=["asset_red"], secret="123456:SECRET-TOKEN",
                 config={"chat_id": "-100200300"})
    assert client.post(f"/api/v1/notifications/channels/{slack['id']}/test", headers=admin).json()["ok"]
    assert json.loads(hook["http"][-1].content)["text"].startswith("[INFO] Tes notifikasi")
    t = client.post(f"/api/v1/notifications/channels/{tg['id']}/test", headers=admin).json()
    assert t["ok"] and json.loads(hook["http"][-1].content)["chat_id"] == "-100200300"

    hook["status"] = 400
    t = client.post(f"/api/v1/notifications/channels/{tg['id']}/test", headers=admin).json()
    assert not t["ok"] and "chat not found" in t["message"] and "SECRET-TOKEN" not in t["message"]
    smtp_incomplete = channel(client, admin, name="SMTP kosong", kind="EMAIL", config={})
    t = client.post(f"/api/v1/notifications/channels/{smtp_incomplete['id']}/test", headers=admin).json()
    assert not t["ok"] and "belum lengkap" in t["message"]


def test_action_pending_notifies(client, admin, hook, db):
    import uuid

    from app.models.asset import Server
    channel(client, admin, name="Approvers", kind="WEBHOOK", events=["action_pending"],
            config={"url": "https://hooks.corp.local/approve"})
    cred = client.post("/api/v1/credentials", headers=admin, json={
        "name": "c", "kind": "SSH_PASSWORD", "username": "u", "password": "p"}).json()
    srv = client.post("/api/v1/servers", headers=admin, json={"name": "s", "hostname": "10.0.0.3", "credential_id": cred["id"]}).json()
    db.get(Server, uuid.UUID(srv["id"])).host_key = "k"
    db.commit()
    client.post("/api/v1/actions", headers=admin, json={
        "asset_id": srv["id"], "kind": "RESTART_SERVICE", "params": {"service": "nginx"}, "reason": "nginx mati"})
    body = json.loads(hook["http"][-1].content)
    assert body["type"] == "action_pending" and "Restart service" in body["title"] and "nginx" in body["body"]


def test_event_types_listed(client, admin):
    types = client.get("/api/v1/notifications/event-types", headers=admin).json()
    assert {"asset_red", "malware", "backup_failed", "action_pending", "daily_report"} <= set(types)
