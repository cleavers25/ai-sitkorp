import json

from app.core.enums import Role
from tests.test_ai_chat import add_provider, chat, llm, server_with_finding  # noqa: F401


def test_memory_crud_and_permissions(client, admin, as_role, db):
    s = server_with_finding(client, admin, db)
    r = client.post("/api/v1/memories", headers=admin,
                    json={"asset_id": s["id"], "kind": "SECURITY", "content": "Pernah kena webshell Maret 2026"})
    assert r.status_code == 201
    mid = r.json()["id"]
    viewer = as_role(Role.VIEWER)
    assert client.post("/api/v1/memories", headers=viewer, json={"content": "x x x"}).status_code == 403
    assert len(client.get(f"/api/v1/memories?asset_id={s['id']}", headers=viewer).json()) == 1
    client.patch(f"/api/v1/memories/{mid}", headers=admin, json={"content": "Pernah kena webshell (Mar 2026)"})
    client.post("/api/v1/memories", headers=admin, json={"kind": "OPERATIONAL", "content": "Maintenance tiap Sabtu"})
    assert len(client.get("/api/v1/memories?scope=global", headers=admin).json()) == 1
    assert client.delete(f"/api/v1/memories/{mid}", headers=admin).status_code == 204
    logs = client.get("/api/v1/audit-logs?action=memory.", headers=admin).json()
    assert logs["total"] == 4


def test_memory_reaches_the_ai_and_ai_can_propose_new_memory(client, admin, db, llm):  # noqa: F811
    add_provider(client, admin)
    s = server_with_finding(client, admin, db)
    client.post("/api/v1/memories", headers=admin,
                json={"asset_id": s["id"], "kind": "ASSET", "content": "Server ini milik Tim Legal, jam sibuk 08-17"})
    conv = client.post("/api/v1/ai/conversations", headers=admin, json={"asset_id": s["id"]}).json()
    llm.script = [("tool", "propose_action", {"action": "save_memory", "kind": "OPERATIONAL",
                                              "content": "Disk / sering penuh karena log nginx", "reason": "info dari user"}),
                  ("text", "Siap, saya usulkan untuk dicatat.")]
    _, bot = chat(client, admin, conv["id"], "Tolong ingat: disk sering penuh karena log nginx")
    scope_block = llm.requests[0]["messages"][1]["content"]
    assert "Tim Legal" in scope_block  # memory injected into the per-conversation system block
    [p] = bot["proposals"]
    assert p["action"] == "save_memory" and p["content"].startswith("Disk")
    # proposing does not save anything
    assert len(client.get(f"/api/v1/memories?asset_id={s['id']}", headers=admin).json()) == 1

    from app.ai import tools
    ctx = tools.ToolContext(db=db, scope_asset_id=None, proposals=[])
    out, _ = tools.execute(ctx, "get_asset", {"asset": "web-01"})
    assert "Tim Legal" in json.loads(out)["memory"][0]
