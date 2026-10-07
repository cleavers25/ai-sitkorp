"""Exercise the real AsyncSSH client against an in-process SSH server (no mocks)."""

import asyncio
import threading

import asyncssh
import pytest

from app.services import ssh_client

OS_RELEASE = 'NAME="Ubuntu"\nVERSION_ID="24.04"\n'
CLIENT_KEY = asyncssh.generate_private_key("ssh-ed25519")


class _Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "ops" and password == "s3cret"

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return username == "ops" and key.get_fingerprint() == CLIENT_KEY.get_fingerprint()


async def _handle(process: asyncssh.SSHServerProcess):
    output = {"uname -srm": "Linux 6.8.0 x86_64\n", "cat /etc/os-release": OS_RELEASE}
    process.stdout.write(output.get(process.command, ""))
    process.exit(0 if process.command in output else 127)


@pytest.fixture
def ssh_server():
    """Start a throwaway SSH server; yields (port, host_key)."""
    loop = asyncio.new_event_loop()
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = loop.run_until_complete(asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=_handle))
    port = server.sockets[0].getsockname()[1]

    thread = threading.Thread(target=loop.run_forever, daemon=True)
    thread.start()
    yield port, host_key

    async def _shutdown():
        server.close()
        await server.wait_closed()
        for task in asyncio.all_tasks() - {asyncio.current_task()}:
            task.cancel()

    asyncio.run_coroutine_threadsafe(_shutdown(), loop).result(timeout=5)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(timeout=5)
    loop.close()


def _run(target, commands=("uname -srm", "cat /etc/os-release")):
    return asyncio.run(ssh_client.run_commands(
        target, list(commands), connect_timeout=5, command_timeout=5, max_output_bytes=1024))


def test_fetch_host_key_then_password_auth(ssh_server):
    port, host_key = ssh_server
    pub, fp = asyncio.run(ssh_client.fetch_host_key("127.0.0.1", port, timeout=5))
    assert fp == host_key.get_fingerprint("sha256")

    results = _run(ssh_client.SSHTarget("127.0.0.1", port, "ops", password="s3cret", known_host_key=pub))
    assert results[0].stdout.startswith("Linux 6.8.0")
    assert 'VERSION_ID="24.04"' in results[1].stdout
    assert all(r.exit_status == 0 for r in results)


def test_private_key_auth(ssh_server):
    port, host_key = ssh_server
    pub = host_key.export_public_key().decode()
    target = ssh_client.SSHTarget(
        "127.0.0.1", port, "ops",
        private_key=CLIENT_KEY.export_private_key().decode(), known_host_key=pub)
    assert _run(target)[0].exit_status == 0


def test_wrong_pinned_key_is_rejected(ssh_server):
    port, _ = ssh_server
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
    with pytest.raises(ssh_client.HostKeyMismatch):
        _run(ssh_client.SSHTarget("127.0.0.1", port, "ops", password="s3cret", known_host_key=other))


def test_bad_password_fails(ssh_server):
    port, host_key = ssh_server
    pub = host_key.export_public_key().decode()
    with pytest.raises(asyncssh.PermissionDenied):
        _run(ssh_client.SSHTarget("127.0.0.1", port, "ops", password="wrong", known_host_key=pub))


def test_output_is_truncated(ssh_server):
    port, host_key = ssh_server
    pub = host_key.export_public_key().decode()
    results = asyncio.run(ssh_client.run_commands(
        ssh_client.SSHTarget("127.0.0.1", port, "ops", password="s3cret", known_host_key=pub),
        ["cat /etc/os-release"], connect_timeout=5, command_timeout=5, max_output_bytes=8))
    assert results[0].truncated and len(results[0].stdout.encode()) <= 8


def test_connecting_without_pinned_key_is_refused():
    with pytest.raises(ValueError):
        _run(ssh_client.SSHTarget("127.0.0.1", 22, "ops", password="x"))
