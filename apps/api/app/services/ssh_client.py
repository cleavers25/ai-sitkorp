"""Thin AsyncSSH wrapper. Callers pass fixed, predefined commands only (PRD 33, 47)."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import asyncssh


@dataclass
class SSHTarget:
    host: str
    port: int
    username: str
    private_key: str | None = None
    passphrase: str | None = None
    password: str | None = None
    known_host_key: str | None = None  # OpenSSH public key line


@dataclass
class CommandResult:
    command: str
    exit_status: int | None
    stdout: str
    stderr: str
    truncated: bool


class HostKeyMismatch(Exception):
    pass


def fingerprint(public_key: str) -> str:
    return asyncssh.import_public_key(public_key).get_fingerprint("sha256")


async def fetch_host_key(host: str, port: int, timeout: int) -> tuple[str, str]:
    """Return (openssh_public_key, sha256_fingerprint) without authenticating."""
    key = await asyncio.wait_for(asyncssh.get_server_host_key(host, port), timeout=timeout)
    if key is None:
        raise ConnectionError("Server did not present a host key")
    return key.export_public_key().decode().strip(), key.get_fingerprint("sha256")


def _truncate(text: str, limit: int) -> tuple[str, bool]:
    data = text.encode(errors="replace")
    if len(data) <= limit:
        return text, False
    return data[:limit].decode(errors="ignore"), True


class SSHSession:
    """One authenticated connection that runs fixed commands. Records every command it runs."""

    def __init__(self, conn: asyncssh.SSHClientConnection, command_timeout: int, max_output_bytes: int):
        self._conn = conn
        self.command_timeout = command_timeout
        self.max_output_bytes = max_output_bytes
        self.executed: list[CommandResult] = []

    async def run(self, command: str, *, input: str | None = None, timeout: int | None = None,
                  max_output_bytes: int | None = None) -> CommandResult:
        limit = max_output_bytes or self.max_output_bytes
        proc = await self._conn.run(command, input=input, check=False,
                                    timeout=timeout or self.command_timeout)
        stdout, t1 = _truncate(str(proc.stdout or ""), limit)
        stderr, t2 = _truncate(str(proc.stderr or ""), limit)
        result = CommandResult(command, proc.exit_status, stdout, stderr, t1 or t2)
        self.executed.append(result)
        return result

    async def stream_to_file(self, command: str, sink, *, timeout: int, max_bytes: int) -> tuple[int | None, str, int]:
        """Run `command` and pass raw stdout chunks to `sink(bytes)`. Returns (exit_status, stderr, bytes).

        Used for backups: the archive streams straight to local disk, nothing is staged on the server.
        """
        total = 0

        async def pump(proc):
            nonlocal total
            while chunk := await proc.stdout.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"output exceeds the {max_bytes} byte limit")
                sink(chunk)
            return await proc.stderr.read(65536)

        async with self._conn.create_process(command, encoding=None) as proc:
            stderr = await asyncio.wait_for(pump(proc), timeout=timeout)
            await proc.wait_closed()
            status = proc.exit_status
        self.executed.append(CommandResult(command, status, f"<{total} bytes streamed>", "", False))
        return status, stderr.decode(errors="replace")[:4000], total


def _connect_options(target: SSHTarget, connect_timeout: int) -> dict:
    if not target.known_host_key:
        raise ValueError("A pinned host key is required before connecting")
    options: dict = {
        "username": target.username,
        "known_hosts": ([asyncssh.import_public_key(target.known_host_key)], [], []),
        "connect_timeout": connect_timeout,
        "agent_path": None,
    }
    if target.private_key:
        options["client_keys"] = [asyncssh.import_private_key(target.private_key, target.passphrase)]
        options["password"] = None
    else:
        options["client_keys"] = None
        options["password"] = target.password
    return options


@asynccontextmanager
async def open_session(target: SSHTarget, *, connect_timeout: int, command_timeout: int,
                       max_output_bytes: int) -> AsyncIterator[SSHSession]:
    options = _connect_options(target, connect_timeout)
    try:
        async with asyncssh.connect(target.host, target.port, **options) as conn:
            yield SSHSession(conn, command_timeout, max_output_bytes)
    except asyncssh.HostKeyNotVerifiable as exc:
        raise HostKeyMismatch(str(exc)) from exc


async def run_commands(
    target: SSHTarget,
    commands: list[str],
    *,
    connect_timeout: int,
    command_timeout: int,
    max_output_bytes: int,
) -> list[CommandResult]:
    async with open_session(target, connect_timeout=connect_timeout, command_timeout=command_timeout,
                            max_output_bytes=max_output_bytes) as session:
        return [await session.run(cmd) for cmd in commands]
