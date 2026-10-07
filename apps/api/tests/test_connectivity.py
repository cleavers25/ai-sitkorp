import asyncssh
import pytest

from app.core.enums import Role
from app.services import ssh_client

HOST_KEY = asyncssh.generate_private_key("ssh-ed25519")
HOST_PUB = HOST_KEY.export_public_key().decode().strip()
OS_RELEASE = 'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\n'


@pytest.fixture
def fake_ssh(monkeypatch):
    calls = {"fetch": 0, "run": []}

    async def fetch(host, port, timeout):
        calls["fetch"] += 1
        return HOST_PUB, HOST_KEY.get_fingerprint("sha256")

    async def run(target, commands, **kw):
        calls["run"].append((target, commands))
        if calls.get("mismatch"):
            raise ssh_client.HostKeyMismatch("mismatch")
        return [
            ssh_client.CommandResult(commands[0], 0, "Linux 6.1.0-18-amd64 x86_64\n", "", False),
            ssh_client.CommandResult(commands[1], 0, OS_RELEASE, "", False),
        ]

    monkeypatch.setattr(ssh_client, "fetch_host_key", fetch)
    monkeypatch.setattr(ssh_client, "run_commands", run)
    return calls


def _server_with_password(client, headers):
    cred = client.post("/api/v1/credentials", headers=headers, json={
        "name": "root-pw", "kind": "SSH_PASSWORD", "username": "root", "password": "hunter2"}).json()
    return client.post("/api/v1/servers", headers=headers, json={
        "name": "web-01", "hostname": "10.0.0.1", "credential_id": cred["id"]}).json()


def test_connectivity_check_pins_host_key_and_reads_os(client, admin, fake_ssh):
    s = _server_with_password(client, admin)
    r = client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=admin)
    assert r.status_code == 202

    server = client.get(f"/api/v1/servers/{s['id']}", headers=admin).json()
    assert server["connectivity_status"] == "OK"
    assert server["os_name"] == "Debian GNU/Linux" and server["os_version"] == "12"
    assert server["host_key_fingerprint"] == HOST_KEY.get_fingerprint("sha256")
    target, commands = fake_ssh["run"][0]
    assert target.username == "root" and target.password == "hunter2"
    assert target.known_host_key == HOST_PUB
    assert commands == ["uname -srm", "cat /etc/os-release"]

    # Second run reuses the pinned key instead of fetching again.
    client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=admin)
    assert fake_ssh["fetch"] == 1

    logs = client.get(f"/api/v1/audit-logs?action=server.connectivity_check", headers=admin).json()
    entry = logs["items"][0]
    assert entry["tool"] == "check_connectivity" and entry["risk_level"] == "SAFE"
    assert entry["command_hash"] and len(entry["command_hash"]) == 64
    assert "hunter2" not in str(entry)


def test_host_key_mismatch_blocks_until_reset(client, admin, fake_ssh):
    s = _server_with_password(client, admin)
    client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=admin)
    fake_ssh["mismatch"] = True
    client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=admin)
    server = client.get(f"/api/v1/servers/{s['id']}", headers=admin).json()
    assert server["connectivity_status"] == "HOST_KEY_MISMATCH"

    assert client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=admin).status_code == 409
    reset = client.post(f"/api/v1/servers/{s['id']}/reset-host-key", headers=admin).json()
    assert reset["host_key_fingerprint"] is None and reset["connectivity_status"] == "UNKNOWN"


def test_connection_requires_credential_and_permission(client, admin, as_role):
    s = client.post("/api/v1/servers", headers=admin, json={"name": "x", "hostname": "10.0.0.9"}).json()
    assert client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=admin).status_code == 400
    viewer = as_role(Role.VIEWER)
    assert client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=viewer).status_code == 403


def test_network_failure_is_recorded(client, admin, fake_ssh, monkeypatch):
    async def boom(*a, **kw):
        raise OSError("Connection refused")
    monkeypatch.setattr(ssh_client, "fetch_host_key", boom)
    s = _server_with_password(client, admin)
    client.post(f"/api/v1/servers/{s['id']}/test-connection", headers=admin)
    server = client.get(f"/api/v1/servers/{s['id']}", headers=admin).json()
    assert server["connectivity_status"] == "FAILED"
    assert "Connection refused" in server["last_connectivity_error"]
