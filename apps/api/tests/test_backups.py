import asyncio
import contextlib
import hashlib
import io
import tarfile
import threading
import uuid
from datetime import timedelta
from pathlib import Path

import asyncssh
import pytest
from sqlalchemy import select

from app.core.config import get_settings
from app.core.enums import Role, Severity
from app.models.asset import Server, Website
from app.models.backup import Backup
from app.services import backups, ssh_client
from app.services.ssh_client import CommandResult
from app.worker.tasks import schedules_tick
from tests.conftest import login, make_user

ROOT = "/var/www/site"


def make_tar(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(f"./{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


ARCHIVE = make_tar({"index.php": b"<?php echo 1;", "wp-config.php": b"<?php define('DB_PASSWORD','x');",
                    "img/logo.png": b"\x89PNG" + b"0" * 5000})


class FakeSession:
    def __init__(self, count="3\n", archive=ARCHIVE, tar_status=0):
        self.count, self.archive, self.tar_status, self.cmds = count, archive, tar_status, []

    async def run(self, cmd, **kw):
        self.cmds.append(cmd)
        return CommandResult(cmd, 0, self.count, "", False)

    async def stream_to_file(self, cmd, sink, *, timeout, max_bytes):
        self.cmds.append(cmd)
        for i in range(0, len(self.archive), 1000):
            sink(self.archive[i:i + 1000])
        return self.tar_status, "tar: fatal" if self.tar_status == 2 else "", len(self.archive)


@pytest.fixture
def fake_ssh(monkeypatch):
    holder = {"session": FakeSession()}

    @contextlib.asynccontextmanager
    async def open_session(target, **kw):
        yield holder["session"]

    monkeypatch.setattr(ssh_client, "open_session", open_session)
    return holder


def site_with_server(client, headers, db, docroot=ROOT, criticality="MEDIUM"):
    cred = client.post("/api/v1/credentials", headers=headers, json={
        "name": f"c-{uuid.uuid4().hex[:6]}", "kind": "SSH_PASSWORD", "username": "ops", "password": "pw"}).json()
    srv = client.post("/api/v1/servers", headers=headers, json={
        "name": f"s-{uuid.uuid4().hex[:6]}", "hostname": "10.0.0.8", "credential_id": cred["id"]}).json()
    s = db.get(Server, uuid.UUID(srv["id"]))
    s.host_key = "ssh-ed25519 AAAA"
    db.commit()
    return client.post("/api/v1/websites", headers=headers, json={
        "url": f"https://{uuid.uuid4().hex[:6]}.example", "server_id": srv["id"], "document_root": docroot,
        "criticality": criticality}).json()


# --- units ------------------------------------------------------------------------------

def test_commands_are_quoted_and_exclude_caches():
    t = backups.tar_command("/var/www/my site")
    assert t.startswith("tar -czf - -C '/var/www/my site' ") and "--exclude=./wp-content/cache" in t
    assert "'/var/www/my site'" in backups.count_command("/var/www/my site")


def test_verify_archive_detects_corruption(tmp_path):
    good = tmp_path / "ok.tar.gz"
    good.write_bytes(ARCHIVE)
    assert backups.verify_archive(good) == 3
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(ARCHIVE[: len(ARCHIVE) // 2])
    with pytest.raises((tarfile.TarError, EOFError, OSError)):
        backups.verify_archive(bad)


# --- flow ------------------------------------------------------------------------------

def test_backup_now_streams_verifies_and_is_auditable(client, admin, db, fake_ssh):
    site = site_with_server(client, admin, db)
    r = client.post("/api/v1/backups", headers=admin, json={"asset_id": site["id"]})
    assert r.status_code == 202, r.text
    b = client.get(f"/api/v1/backups/{r.json()['id']}", headers=admin).json()
    assert b["state"] == "SUCCEEDED" and b["verified"] and b["file_count"] == 3 and b["remote_file_count"] == 3
    assert b["sha256"] == hashlib.sha256(ARCHIVE).hexdigest() and b["size_bytes"] == len(ARCHIVE)
    stored = db.get(Backup, uuid.UUID(b["id"])).storage_path
    assert Path(stored).read_bytes() == ARCHIVE and Path(stored).is_relative_to(get_settings().backup_dir)
    assert any(c.startswith("tar -czf - -C /var/www/site") for c in fake_ssh["session"].cmds)

    dl = client.get(f"/api/v1/backups/{b['id']}/download", headers=admin)
    assert dl.status_code == 200 and dl.content == ARCHIVE
    infra = login(client, make_user(Role.INFRA))  # INFRA can run backups but not download them
    assert client.get(f"/api/v1/backups/{b['id']}/download", headers=infra).status_code == 403
    logs = [e["action"] for e in client.get("/api/v1/audit-logs?action=backup.", headers=admin).json()["items"]]
    assert {"backup.request", "backup.run", "backup.download"} <= set(logs)


def test_count_mismatch_is_not_verified_and_tar_failure_removes_file(client, admin, db, fake_ssh):
    site = site_with_server(client, admin, db)
    fake_ssh["session"] = FakeSession(count="10\n")
    b = client.post("/api/v1/backups", headers=admin, json={"asset_id": site["id"]}).json()
    got = client.get(f"/api/v1/backups/{b['id']}", headers=admin).json()
    assert got["state"] == "SUCCEEDED" and not got["verified"] and "tidak cocok" in got["verify_note"]

    fake_ssh["session"] = FakeSession(tar_status=2)
    b2 = client.post("/api/v1/backups", headers=admin, json={"asset_id": site["id"]}).json()
    got2 = client.get(f"/api/v1/backups/{b2['id']}", headers=admin).json()
    assert got2["state"] == "FAILED" and "exit 2" in got2["error"]
    assert not list((Path(get_settings().backup_dir) / site["id"]).glob(f"*{b2['id'][:8]}*"))


def test_retention_keeps_newest(client, admin, db, fake_ssh, monkeypatch):
    monkeypatch.setattr(get_settings(), "backup_retention", 2)
    site = site_with_server(client, admin, db)
    ids = []
    for i in range(4):
        b = client.post("/api/v1/backups", headers=admin, json={"asset_id": site["id"]}).json()
        row = db.get(Backup, uuid.UUID(b["id"]))
        db.refresh(row)
        row.started_at = row.started_at + timedelta(minutes=i)  # distinct ordering
        db.commit()
        ids.append(b["id"])
    backups.prune(db, uuid.UUID(site["id"]))
    kept = [x for x in client.get(f"/api/v1/backups?asset_id={site['id']}", headers=admin).json()["items"] if not x["pruned"]]
    assert len(kept) == 2


def test_backup_requires_docroot(client, admin, db):
    r = client.post("/api/v1/websites", headers=admin, json={"url": "https://nodocroot.example"}).json()
    assert client.post("/api/v1/backups", headers=admin, json={"asset_id": r["id"]}).status_code == 422


def test_status_check_levels(client, admin, db, fake_ssh):
    site_json = site_with_server(client, admin, db, criticality="HIGH")
    site = db.get(Website, uuid.UUID(site_json["id"]))
    assert backups.status_check(db, site).severity == Severity.HIGH  # critical site without backup
    client.post("/api/v1/backups", headers=admin, json={"asset_id": site_json["id"]})
    assert not backups.status_check(db, site).is_issue
    row = db.scalars(select(Backup).where(Backup.asset_id == site.id)).first()
    row.started_at = row.started_at - timedelta(days=3)
    db.commit()
    aged = backups.status_check(db, site)
    assert aged.is_issue and aged.severity == Severity.MEDIUM and "hari" in aged.title


def test_backup_schedule_run(client, admin, db, fake_ssh):
    site_with_server(client, admin, db)
    client.post("/api/v1/websites", headers=admin, json={"url": "https://tanpa-docroot.example"})
    sid = client.post("/api/v1/schedules", headers=admin, json={"name": "Backup harian", "job": "BACKUP"}).json()["id"]
    run = client.post(f"/api/v1/schedules/{sid}/run-now", headers=admin).json()
    assert run["job"] == "BACKUP" and run["queued"] == 1 and run["skipped"] == 1 and run["ai_state"] == "SKIPPED"
    schedules_tick()
    run = client.get(f"/api/v1/schedule-runs/{run['id']}", headers=admin).json()
    assert run["state"] == "COMPLETED" and run["summary"]["succeeded"] == 1 and run["summary"]["verified"] == 1


# --- real SSH streaming (in-process server, no mocks) ------------------------------------

class _Srv(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return password == "pw"


async def _handle(process):
    if process.command.startswith("tar "):
        process.stdout.write(ARCHIVE)
        process.exit(0)
    else:
        process.stdout.write(b"3\n")
        process.exit(0)


def test_stream_to_file_over_real_ssh(tmp_path):
    loop = asyncio.new_event_loop()
    key = asyncssh.generate_private_key("ssh-ed25519")
    server = loop.run_until_complete(asyncssh.create_server(
        _Srv, "127.0.0.1", 0, server_host_keys=[key], process_factory=_handle, encoding=None))
    port = server.sockets[0].getsockname()[1]
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    try:
        target = ssh_client.SSHTarget("127.0.0.1", port, "ops", password="pw",
                                      known_host_key=key.export_public_key().decode())
        out = tmp_path / "b.tar.gz"

        async def go():
            async with ssh_client.open_session(target, connect_timeout=5, command_timeout=5,
                                               max_output_bytes=1024) as s:
                with open(out, "wb") as fh:
                    return await s.stream_to_file(backups.tar_command(ROOT), fh.write, timeout=10, max_bytes=10**6)

        status, _, size = asyncio.run(go())
        assert status == 0 and size == len(ARCHIVE) and out.read_bytes() == ARCHIVE
        assert backups.verify_archive(out) == 3

        async def too_big():
            async with ssh_client.open_session(target, connect_timeout=5, command_timeout=5,
                                               max_output_bytes=1024) as s:
                return await s.stream_to_file("tar x", lambda c: None, timeout=10, max_bytes=100)

        with pytest.raises(ValueError):
            asyncio.run(too_big())
    finally:
        async def shutdown():
            server.close()
            await server.wait_closed()
            for task in asyncio.all_tasks() - {asyncio.current_task()}:
                task.cancel()
        asyncio.run_coroutine_threadsafe(shutdown(), loop).result(timeout=5)
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5)
        loop.close()
