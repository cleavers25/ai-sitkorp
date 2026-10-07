from app.core.enums import Role


def _server(client, headers, name="web-01", **extra):
    r = client.post("/api/v1/servers", headers=headers,
                    json={"name": name, "hostname": "10.0.0.1", **extra})
    assert r.status_code == 201, r.text
    return r.json()


def test_server_crud_and_status(client, admin):
    s = _server(client, admin, criticality="HIGH", tags=["prod"])
    assert s["status"] == "UNKNOWN"  # not assessed yet
    assert s["connectivity_status"] == "UNKNOWN"
    assert s["criticality"] == "HIGH"

    r = client.patch(f"/api/v1/servers/{s['id']}", headers=admin, json={"owner": "Team A"})
    assert r.json()["owner"] == "Team A"

    assert client.get("/api/v1/servers", headers=admin).json()["total"] == 1
    assert client.delete(f"/api/v1/servers/{s['id']}", headers=admin).status_code == 204
    assert client.get(f"/api/v1/servers/{s['id']}", headers=admin).status_code == 404


def test_duplicate_server_name_conflicts(client, admin):
    _server(client, admin)
    r = client.post("/api/v1/servers", headers=admin, json={"name": "web-01", "hostname": "10.0.0.2"})
    assert r.status_code == 409


def test_invalid_hostname_rejected(client, admin):
    r = client.post("/api/v1/servers", headers=admin, json={"name": "x", "hostname": "a;rm -rf /"})
    assert r.status_code == 422


def test_website_linked_to_server(client, admin):
    s = _server(client, admin)
    r = client.post("/api/v1/websites", headers=admin, json={
        "url": "https://Example.com/", "server_id": s["id"], "application": "wordpress"})
    assert r.status_code == 201, r.text
    w = r.json()
    assert w["domain"] == "example.com" and w["name"] == "example.com"
    assert w["server"]["name"] == "web-01"
    assert client.get(f"/api/v1/servers/{s['id']}", headers=admin).json()["website_count"] == 1
    assert client.get(f"/api/v1/websites?server_id={s['id']}", headers=admin).json()["total"] == 1

    # Deleting the server keeps the website but unlinks it.
    client.delete(f"/api/v1/servers/{s['id']}", headers=admin)
    w2 = client.get(f"/api/v1/websites/{w['id']}", headers=admin).json()
    assert w2["server_id"] is None


def test_website_requires_valid_url_and_server(client, admin):
    assert client.post("/api/v1/websites", headers=admin, json={"url": "ftp://x"}).status_code == 422
    r = client.post("/api/v1/websites", headers=admin, json={
        "url": "https://a.com", "server_id": "00000000-0000-0000-0000-000000000000"})
    assert r.status_code == 422


def test_asset_listing_and_dashboard(client, admin, as_role):
    _server(client, admin)
    client.post("/api/v1/websites", headers=admin, json={"url": "https://a.com"})
    client.post("/api/v1/websites", headers=admin, json={"url": "https://b.com"})

    assets = client.get("/api/v1/assets", headers=admin).json()
    assert assets["total"] == 3
    only_web = client.get("/api/v1/assets?asset_type=WEBSITE", headers=admin).json()
    assert only_web["total"] == 2

    summary = client.get("/api/v1/dashboard/summary", headers=admin).json()
    assert summary["total_servers"] == 1 and summary["total_websites"] == 2
    assert summary["status_counts"]["UNKNOWN"] == 3
    assert summary["recent_activity"]  # admin has audit:view

    viewer = client.get("/api/v1/dashboard/summary", headers=as_role(Role.VIEWER)).json()
    assert viewer["recent_activity"] is None


def test_asset_changes_are_audited(client, admin):
    s = _server(client, admin)
    logs = client.get(f"/api/v1/audit-logs?asset_id={s['id']}", headers=admin).json()
    assert [e["action"] for e in logs["items"]] == ["asset.create"]
    assert logs["items"][0]["username"] == "admin@example.com"
