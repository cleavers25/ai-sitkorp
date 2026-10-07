import base64
import json

import httpx
import pytest

from app.ai import tools as ai_tools
from app.core.enums import Role
from app.services import notify, wazuh, wazuh_poll

API, IDX = "https://wazuh.corp.local:55000", "https://wazuh-indexer.corp.local:9200"


def _alert_hit(rule_id, level, desc, log, srcip=None, agent=("001", "web-prod-01")):
    return {"_source": {"timestamp": "2026-09-25T10:00:00.000+0000", "agent": {"id": agent[0], "name": agent[1]},
                        "rule": {"id": rule_id, "level": level, "description": desc, "groups": ["web", "attack"]},
                        "data": {"srcip": srcip} if srcip else {}, "full_log": log}}


class FakeWazuh:
    """Answers like Wazuh 4.x Server API + Indexer (formats from the official documentation)."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.token_valid = True
        self.agent_status = "active"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url, path = str(request.url), request.url.path
        if path == "/security/user/authenticate":
            creds = request.headers.get("authorization", "")
            if creds.startswith("Basic ") and base64.b64decode(creds[6:]).startswith(b"wazuh-wui:"):
                self.token_valid = True
                return httpx.Response(200, text="jwt-token-123")
            return httpx.Response(401, json={"title": "Unauthorized"})
        if url.startswith(API):
            if request.headers.get("authorization") != "Bearer jwt-token-123" or not self.token_valid:
                return httpx.Response(401, json={"title": "Unauthorized"})
            if path == "/":
                return httpx.Response(200, json={"data": {"title": "Wazuh API REST", "api_version": "4.14.5"}, "error": 0})
            if path == "/agents":
                items = [
                    {"id": "000", "name": "wazuh-manager", "ip": "127.0.0.1", "status": "active"},
                    {"id": "001", "name": "web-prod-01", "ip": "10.0.0.1", "status": self.agent_status,
                     "os": {"name": "Ubuntu", "version": "24.04"}, "version": "Wazuh v4.14.5", "group": ["web"],
                     "lastKeepAlive": "2026-09-25T10:00:00+00:00"},
                    {"id": "002", "name": "db-01", "ip": "10.0.0.9", "status": "disconnected"},
                ]
                return httpx.Response(200, json={"data": {"affected_items": items, "total_affected_items": 3,
                                                          "total_failed_items": 0, "failed_items": []}, "error": 0})
            if path.startswith("/sca/"):
                return httpx.Response(200, json={"data": {"affected_items": [
                    {"policy_id": "cis_ubuntu24-04", "name": "CIS Ubuntu 24.04", "pass": 90, "fail": 110,
                     "invalid": 0, "total_checks": 200, "score": 45, "end_scan": "2026-09-25T09:00:00+00:00"}],
                    "total_affected_items": 1}, "error": 0})
        if url.startswith(IDX):
            if path == "/":
                return httpx.Response(200, json={"cluster_name": "wazuh-cluster", "version": {"number": "2.19.1"}})
            body = json.loads(request.content)
            filters = json.dumps(body.get("query", {}))
            if "wazuh-states-vulnerabilities" in path:
                return httpx.Response(200, json={
                    "hits": {"total": {"value": 5}, "hits": [
                        {"_source": {"agent": {"id": "001"}, "package": {"name": "openssl", "version": "3.0.2"},
                                     "vulnerability": {"id": "CVE-2025-0001", "severity": "Critical", "score": {"base": 9.8}}}}]},
                    "aggregations": {"by_severity": {"buckets": [{"key": "Critical", "doc_count": 2},
                                                                 {"key": "High", "doc_count": 3}]}}})
            if "multi_match" in filters:
                return httpx.Response(200, json={"hits": {"total": {"value": 2}, "hits": [
                    _alert_hit("31151", 10, "Multiple web server 400 errors from same source", "GET /wp-login.php", "203.0.113.9")]},
                    "aggregations": {"agents": {"buckets": [{"key": "web-prod-01", "doc_count": 2}]}}})
            if "rule.groups" in filters and "syscheck" in filters:
                return httpx.Response(200, json={"hits": {"hits": [
                    {"_source": {"timestamp": "2026-09-25T03:00:00Z",
                                 "syscheck": {"path": "/var/www/site/wp-content/uploads/x.php", "event": "added",
                                              "sha256_after": "ab" * 32}}},
                    {"_source": {"timestamp": "2026-09-25T03:01:00Z",
                                 "syscheck": {"path": "/etc/hosts", "event": "modified"}}}]}})
            if "multi_terms" in json.dumps(body.get("aggs", {})):
                return httpx.Response(200, json={"aggregations": {"pairs": {"buckets": [
                    {"key": ["001", "31106"], "doc_count": 4, "max_level": {"value": 12},
                     "latest": {"hits": {"hits": [_alert_hit("31106", 12, "Web attack returned code 200", "GET /x.php?cmd=id")]}}}]}}})
            return httpx.Response(200, json={
                "hits": {"total": {"value": 7}, "hits": []},
                "aggregations": {"rules": {"buckets": [
                    {"key": "31106", "doc_count": 4, "max_level": {"value": 12},
                     "latest": {"hits": {"hits": [_alert_hit("31106", 12, "Web attack returned code 200", "GET /x.php?cmd=id", "203.0.113.9")]}}},
                    {"key": "5710", "doc_count": 3, "max_level": {"value": 5},
                     "latest": {"hits": {"hits": [_alert_hit("5710", 5, "sshd: invalid user", "Invalid user admin")]}}}]}}})
        return httpx.Response(404)


@pytest.fixture
def fake(monkeypatch):
    f = FakeWazuh()
    monkeypatch.setattr(wazuh, "HTTP_TRANSPORT", httpx.MockTransport(f))
    return f


def configure(client, headers, **kw):
    body = {"enabled": True, "api_url": API, "api_user": "wazuh-wui", "api_password": "api-pass",
            "indexer_url": IDX, "indexer_user": "admin", "indexer_password": "idx-pass", "verify_tls": False, **kw}
    r = client.put("/api/v1/integrations/wazuh", headers=headers, json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_settings_are_write_only_and_permissioned(client, admin, as_role, fake):
    out = configure(client, admin)
    assert out["has_api_password"] and out["has_indexer_password"] and "api-pass" not in json.dumps(out)
    assert client.get("/api/v1/integrations/wazuh", headers=as_role(Role.INFRA)).status_code == 403
    t = client.post("/api/v1/integrations/wazuh/test", headers=admin).json()
    assert t["api"] == {"ok": True, "version": "4.14.5"} and t["indexer"]["version"] == "2.19.1"
    # keeping passwords: PUT without them does not erase them
    out = configure(client, admin, api_password=None, indexer_password=None, min_alert_level=12)
    assert out["has_api_password"] and out["min_alert_level"] == 12
    logs = json.dumps(client.get("/api/v1/audit-logs?action=integration.", headers=admin).json())
    assert "api-pass" not in logs and "idx-pass" not in logs
    # CA: omitted keeps the stored one, null clears it
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"
    assert configure(client, admin, ca_cert=pem)["has_ca_cert"]
    assert configure(client, admin)["has_ca_cert"]
    assert not configure(client, admin, ca_cert=None)["has_ca_cert"]


def test_wrong_password_is_reported(client, admin, fake):
    configure(client, admin, api_user="wrong")
    t = client.post("/api/v1/integrations/wazuh/test", headers=admin).json()
    assert not t["api"]["ok"] and "401" in t["api"]["error"]


def test_sync_maps_agents_and_manual_override(client, admin, fake):
    web = client.post("/api/v1/servers", headers=admin, json={"name": "web-prod-01", "hostname": "10.0.0.1"}).json()
    other = client.post("/api/v1/servers", headers=admin, json={"name": "legacy", "hostname": "192.168.1.5"}).json()
    configure(client, admin)
    assert client.post("/api/v1/integrations/wazuh/sync", headers=admin).json() == {"agents": 2, "mapped": 1}
    agents = {a["agent_id"]: a for a in client.get("/api/v1/integrations/wazuh/agents", headers=admin).json()}
    assert "000" not in agents  # the manager itself is skipped
    assert agents["001"]["server_name"] == "web-prod-01" and agents["002"]["server_id"] is None
    m = client.patch("/api/v1/integrations/wazuh/agents/002", headers=admin, json={"server_id": other["id"]}).json()
    assert m["mapping"] == "MANUAL" and m["server_name"] == "legacy"
    client.post("/api/v1/integrations/wazuh/sync", headers=admin)  # manual mapping survives a re-sync
    agents = {a["agent_id"]: a for a in client.get("/api/v1/integrations/wazuh/agents", headers=admin).json()}
    assert agents["002"]["server_name"] == "legacy" and web["id"]


def test_server_assessment_includes_wazuh_checks(client, admin, fake):
    s = client.post("/api/v1/servers", headers=admin, json={"name": "web-prod-01", "hostname": "10.0.0.1"}).json()
    configure(client, admin)
    client.post("/api/v1/integrations/wazuh/sync", headers=admin)
    a = client.post(f"/api/v1/assets/{s['id']}/assess", headers=admin).json()
    a = client.get(f"/api/v1/assessments/{a['id']}", headers=admin).json()
    checks = {(c["check"], c["target"]): c for c in a["checks"] if c["check"].startswith("wazuh")}
    assert checks[("wazuh_agent", None)]["status"] == "PASS"
    alert = checks[("wazuh_alerts", "rule:31106")]
    assert alert["severity"] == "HIGH" and "Web attack" in alert["title"]
    assert ("wazuh_alerts", "rule:5710") not in checks  # below min_alert_level (10)
    fim = checks[("wazuh_fim", None)]
    assert fim["status"] == "WARNING" and "/var/www/site/wp-content/uploads/x.php" in fim["value"]
    assert checks[("wazuh_vulnerabilities", "severity:Critical")]["severity"] == "HIGH"
    assert checks[("wazuh_vulnerabilities", "severity:High")]["severity"] == "MEDIUM"
    assert checks[("wazuh_sca", "cis_ubuntu24-04")]["value"] == "45%"
    assert a["overall_status"] == "RED"


def test_wazuh_down_is_an_error_check_not_a_crash(client, admin, fake, monkeypatch):
    s = client.post("/api/v1/servers", headers=admin, json={"name": "web-prod-01", "hostname": "10.0.0.1"}).json()
    configure(client, admin)
    client.post("/api/v1/integrations/wazuh/sync", headers=admin)

    def down(request):
        raise httpx.ConnectError("connection refused")
    monkeypatch.setattr(wazuh, "HTTP_TRANSPORT", httpx.MockTransport(down))
    a = client.post(f"/api/v1/assets/{s['id']}/assess", headers=admin).json()
    a = client.get(f"/api/v1/assessments/{a['id']}", headers=admin).json()
    err = [c for c in a["checks"] if c["check"] == "wazuh"][0]
    assert err["status"] == "ERROR" and "connection refused" in err["title"] and a["state"] == "COMPLETED"


def test_poll_sends_near_real_time_notifications(client, admin, fake, monkeypatch, db):
    sent = []
    monkeypatch.setattr(notify, "HTTP_TRANSPORT", httpx.MockTransport(lambda r: sent.append(r) or httpx.Response(200)))
    client.post("/api/v1/notifications/channels", headers=admin, json={
        "name": "SOC hook", "kind": "WEBHOOK", "events": ["wazuh_alert"], "config": {"url": "https://soc.corp.local/h"}})
    client.post("/api/v1/servers", headers=admin, json={"name": "web-prod-01", "hostname": "10.0.0.1"})
    configure(client, admin)
    client.post("/api/v1/integrations/wazuh/sync", headers=admin)
    assert wazuh_poll.poll(db) == {"events": 1}
    body = json.loads(sent[-1].content)
    assert body["type"] == "wazuh_alert" and body["severity"] == "HIGH" and "web-prod-01" in body["title"]
    first_until = wazuh.get_config(db).last_alert_poll_at
    wazuh_poll.poll(db)
    q = json.loads([r for r in fake.requests if "multi_terms" in r.content.decode()][-1].content)
    since = q["query"]["bool"]["filter"][0]["range"]["timestamp"]["gt"]
    assert since.startswith(first_until.isoformat()[:19])  # the next poll starts where the last one stopped


def test_ai_wazuh_tools_and_availability(client, admin, fake, db):
    assert "search_ioc" not in {t.name for t in ai_tools.available_tools(db)}
    client.post("/api/v1/servers", headers=admin, json={"name": "web-prod-01", "hostname": "10.0.0.1"})
    configure(client, admin)
    client.post("/api/v1/integrations/wazuh/sync", headers=admin)
    assert {"wazuh_alerts", "wazuh_vulnerabilities", "search_ioc"} <= {t.name for t in ai_tools.available_tools(db)}
    ctx = ai_tools.ToolContext(db=db, scope_asset_id=None, proposals=[])
    out, err = ai_tools.execute(ctx, "search_ioc", {"value": "203.0.113.9"})
    data = json.loads(out)
    assert not err and data["total"] == 2 and data["agents"] == {"web-prod-01": 2}
    out, err = ai_tools.execute(ctx, "wazuh_vulnerabilities", {"asset": "web-prod-01"})
    assert json.loads(out)["top"][0]["cve"] == "CVE-2025-0001"
    out, err = ai_tools.execute(ctx, "search_ioc", {"value": "x"})
    assert err


def test_token_is_refreshed_after_401(client, admin, fake, db):
    configure(client, admin)
    c = wazuh.WazuhClient.from_db(db)
    c.agents()
    fake.token_valid = False  # expire the token server-side
    assert len(c.agents()) == 3
    assert sum(1 for r in fake.requests if r.url.path == "/security/user/authenticate") == 2

