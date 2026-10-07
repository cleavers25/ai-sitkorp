import asyncio
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import AuditResult, ConnectivityStatus, CredentialKind
from app.db.base import utcnow
from app.models.asset import Server
from app.models.user import User
from app.services import audit, ssh_client
from app.services.secrets import SecretNotFound, get_secret_backend
from app.tools.registry import CHECK_CONNECTIVITY


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            key, _, val = line.partition("=")
            values[key.strip()] = val.strip().strip('"')
    return values


def _build_target(db: Session, server: Server) -> ssh_client.SSHTarget:
    cred = server.credential
    if cred is None:
        raise ValueError("Server has no credential assigned")
    if cred.kind not in (CredentialKind.SSH_PRIVATE_KEY, CredentialKind.SSH_PASSWORD):
        raise ValueError(f"Credential kind {cred.kind.value} cannot be used for SSH")
    username = server.ssh_username or cred.username
    if not username:
        raise ValueError("No SSH username on server or credential")

    secret = get_secret_backend(db).get(cred.secret_path)
    return ssh_client.SSHTarget(
        host=server.hostname,
        port=server.ssh_port,
        username=username,
        private_key=secret.get("private_key"),
        passphrase=secret.get("passphrase"),
        password=secret.get("password"),
        known_host_key=server.host_key,
    )


def check_server_connectivity(
    db: Session, server_id: uuid.UUID, user_id: uuid.UUID | None, source_ip: str | None
) -> dict[str, Any]:
    settings = get_settings()
    server = db.get(Server, server_id)
    if server is None:
        return {"status": "NOT_FOUND"}
    user = db.get(User, user_id) if user_id else None

    details: dict[str, Any] = {"hostname": server.hostname, "port": server.ssh_port}
    status = ConnectivityStatus.FAILED
    error: str | None = None
    try:
        target = _build_target(db, server)

        if not server.host_key:
            host_key, fp = asyncio.run(
                ssh_client.fetch_host_key(server.hostname, server.ssh_port, settings.ssh_connect_timeout)
            )
            server.host_key, server.host_key_fingerprint = host_key, fp
            target.known_host_key = host_key
            details["host_key_pinned"] = fp

        results = asyncio.run(ssh_client.run_commands(
            target,
            list(CHECK_CONNECTIVITY.commands),
            connect_timeout=settings.ssh_connect_timeout,
            command_timeout=settings.ssh_command_timeout,
            max_output_bytes=settings.ssh_max_output_bytes,
        ))
        uname, os_release = results[0], results[1]
        server.kernel = uname.stdout.strip()[:255] or None
        info = parse_os_release(os_release.stdout)
        server.os_name = info.get("NAME") or info.get("ID")
        server.os_version = info.get("VERSION_ID") or info.get("VERSION")
        status = ConnectivityStatus.OK
        details.update({"os": server.os_name, "os_version": server.os_version, "kernel": server.kernel})
    except ssh_client.HostKeyMismatch:
        status = ConnectivityStatus.HOST_KEY_MISMATCH
        error = (
            "Host key does not match the pinned key. Possible man-in-the-middle or server rebuild; "
            "verify out-of-band, then reset the host key."
        )
    except SecretNotFound:
        error = "Credential secret is missing from the secret store"
    except Exception as exc:  # network errors, auth failures, timeouts
        error = f"{type(exc).__name__}: {exc}"[:1000]

    server.connectivity_status = status
    server.last_connectivity_check_at = utcnow()
    server.last_connectivity_error = error
    if error:
        details["error"] = error

    audit.record(
        db, "server.connectivity_check",
        AuditResult.SUCCESS if status == ConnectivityStatus.OK else AuditResult.FAILURE,
        user=user, source_ip=source_ip, asset_id=server.id,
        tool=CHECK_CONNECTIVITY.name, command=" && ".join(CHECK_CONNECTIVITY.commands),
        risk_level=CHECK_CONNECTIVITY.risk_level, details=details,
    )
    db.commit()
    return {"status": status.value, "error": error}
