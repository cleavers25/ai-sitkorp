"""Remediation actions (PRD 23-25, 49): validate → preview → approve → execute over SSH → verify → audit.

Commands are built only from fixed templates and strictly validated parameters (quoted with shlex).
Nothing is ever deleted: quarantine moves the file into ~/.aiinfra-quarantine/<id>/ with its metadata,
and every write action has a rollback.
"""

import asyncio
import re
import shlex
import uuid
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.enums import ActionKind, ActionState, AuditResult, RiskLevel
from app.db.base import utcnow
from app.models.action import Action
from app.models.asset import Asset, Server, Website
from app.models.user import User
from app.services import audit, ssh_client
from app.services.connectivity import _build_target
from app.services.secrets import SecretNotFound

SAFE_PATH = re.compile(r"^/[A-Za-z0-9._@+\-/ ]+$")
SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@._-]{0,120}$")
MODE = re.compile(r"^[0-7]{3,4}$")
# Where files may be quarantined/restricted when the target is a server (not a website docroot).
SERVER_WRITABLE_ROOTS = ("/var/www/", "/srv/", "/home/", "/opt/", "/tmp/", "/var/tmp/", "/dev/shm/", "/usr/share/nginx/")
FORBIDDEN_PARTS = ("/.ssh/", "/etc/", "/.aiinfra-quarantine/")

RISK = {
    ActionKind.QUARANTINE_FILE: RiskLevel.HIGH,
    ActionKind.RESTRICT_FILE: RiskLevel.HIGH,
    ActionKind.RESTART_SERVICE: RiskLevel.LOW,
    ActionKind.RESTORE_QUARANTINE: RiskLevel.HIGH,
    ActionKind.RESTORE_PERMISSIONS: RiskLevel.HIGH,
}
REQUESTABLE = (ActionKind.QUARANTINE_FILE, ActionKind.RESTRICT_FILE, ActionKind.RESTART_SERVICE)
LABEL = {
    ActionKind.QUARANTINE_FILE: "Karantina file",
    ActionKind.RESTRICT_FILE: "Batasi akses file (chmod 600)",
    ActionKind.RESTART_SERVICE: "Restart service",
    ActionKind.RESTORE_QUARANTINE: "Kembalikan file dari karantina",
    ActionKind.RESTORE_PERMISSIONS: "Kembalikan permission file",
}


class ActionError(ValueError):
    pass


def resolve_server(db: Session, asset: Asset) -> Server:
    if isinstance(asset, Server):
        return asset
    if isinstance(asset, Website) and asset.server_id:
        return db.get(Server, asset.server_id)
    raise ActionError("Website ini belum dihubungkan ke server.")


def validate_path(asset: Asset, path: str) -> str:
    path = (path or "").strip()
    if not SAFE_PATH.match(path) or "/../" in path + "/" or "//" in path or path.endswith("/"):
        raise ActionError("Path harus absolut, menunjuk ke file, tanpa '..' atau karakter khusus.")
    if any(part in path + "/" for part in FORBIDDEN_PARTS):
        raise ActionError("Path berada di lokasi sistem yang tidak boleh diubah.")
    if isinstance(asset, Website):
        if not asset.document_root:
            raise ActionError("Isi document root website terlebih dahulu.")
        if not path.startswith(asset.document_root.rstrip("/") + "/"):
            raise ActionError(f"File harus berada di dalam document root ({asset.document_root}).")
    elif not path.startswith(SERVER_WRITABLE_ROOTS):
        raise ActionError("Untuk target server, file harus berada di " + ", ".join(SERVER_WRITABLE_ROOTS))
    return path


def validate(db: Session, kind: ActionKind, asset: Asset, params: dict[str, Any]) -> dict[str, Any]:
    if kind in (ActionKind.QUARANTINE_FILE, ActionKind.RESTRICT_FILE):
        return {"path": validate_path(asset, params.get("path", ""))}
    if kind == ActionKind.RESTART_SERVICE:
        name = str(params.get("service", "")).strip()
        if not SERVICE_NAME.match(name):
            raise ActionError("Nama service tidak valid.")
        return {"service": name}
    raise ActionError(f"Aksi {kind.value} tidak bisa diajukan langsung.")


def _q(path: str) -> str:
    return shlex.quote(path)


def commands(action: Action) -> list[tuple[str, str]]:
    """(label, command) pairs. Shown to the approver as the dry-run preview, then executed in order."""
    p, qid = action.params, action.id.hex[:12]
    qdir = f'"$HOME/.aiinfra-quarantine/{qid}"'
    if action.kind == ActionKind.QUARANTINE_FILE:
        f = _q(p["path"])
        return [
            ("bukti", f"test -f {f} && test ! -L {f} && stat -c '%n|%s|%Y|%U|%G|%a' -- {f} && sha256sum -- {f}"),
            ("karantina", f'set -e; q={qdir}; mkdir -p "$q"; chmod 700 "$HOME/.aiinfra-quarantine" "$q"; '
                          f"stat -c '%n|%s|%Y|%U|%G|%a' -- {f} > \"$q/meta.txt\"; sha256sum -- {f} >> \"$q/meta.txt\"; "
                          f'mv -- {f} "$q/file"; chmod 000 "$q/file"; echo "$q"'),
            ("verifikasi", f'test ! -e {f} && test -f {qdir}/file && echo OK'),
        ]
    if action.kind == ActionKind.RESTORE_QUARANTINE:
        f, src = _q(p["path"]), f'"$HOME/.aiinfra-quarantine/{p["quarantine_id"]}/file"'
        return [
            ("pengecekan", f"test ! -e {f} && test -f {src} && echo OK"),
            ("kembalikan", f"mv -- {src} {f} && chmod {p['mode']} -- {f}"),
            ("verifikasi", f"stat -c '%a' -- {f} && sha256sum -- {f}"),
        ]
    if action.kind == ActionKind.RESTRICT_FILE:
        f = _q(p["path"])
        return [
            ("bukti", f"test -f {f} && stat -c '%a|%U|%G' -- {f}"),
            ("batasi", f"chmod 600 -- {f}"),
            ("verifikasi", f"stat -c '%a' -- {f}"),
        ]
    if action.kind == ActionKind.RESTORE_PERMISSIONS:
        f = _q(p["path"])
        return [("kembalikan", f"chmod {p['mode']} -- {f}"), ("verifikasi", f"stat -c '%a' -- {f}")]
    if action.kind == ActionKind.RESTART_SERVICE:
        s = p["service"]
        return [
            ("status awal", f"systemctl is-active {s} || true"),
            ("restart", f"systemctl restart {s}"),
            ("verifikasi", f"sleep 2; systemctl is-active {s}"),
        ]
    raise ActionError(f"unknown action {action.kind}")


def preview(action: Action) -> str:
    return "\n".join(f"# {label}\n{cmd}" for label, cmd in commands(action))


def create(db: Session, *, kind: ActionKind, asset: Asset, params: dict, reason: str, user: User,
           ip: str | None, finding_id: uuid.UUID | None = None, rollback_of: Action | None = None) -> Action:
    server = resolve_server(db, asset)
    action = Action(id=uuid.uuid4(), kind=kind, state=ActionState.PENDING_APPROVAL, risk_level=RISK[kind],
                    asset_id=asset.id, server_id=server.id, finding_id=finding_id, params=params,
                    reason=reason.strip()[:2000], requested_by_id=user.id,
                    rollback_of_id=rollback_of.id if rollback_of else None)
    action.command_preview = preview(action)
    db.add(action)
    db.flush()
    audit.record(db, "action.request", user=user, source_ip=ip, asset_id=asset.id, tool=kind.value.lower(),
                 risk_level=action.risk_level,
                 details={"action_id": str(action.id), "kind": kind.value, "params": params, "reason": action.reason,
                          "server": server.name})
    db.commit()
    try:
        from app.core.enums import Severity
        from app.services.notify import emit
        emit(db, "action_pending", Severity.HIGH if action.risk_level == RiskLevel.HIGH else Severity.MEDIUM,
             f"Menunggu approval: {LABEL[kind]} di {asset.name}",
             f"Diajukan oleh {user.email}. Alasan: {action.reason}\n"
             f"Target: {params.get('path') or params.get('service')}",
             asset_id=asset.id, link="/actions", data={"action_id": str(action.id)})
    except Exception:
        db.rollback()
    return action


def rollback_request(db: Session, original: Action, user: User, ip: str | None) -> Action:
    if original.state != ActionState.SUCCEEDED or original.rolled_back_by_id:
        raise ActionError("Hanya tindakan yang berhasil dan belum di-rollback yang bisa dikembalikan.")
    asset = db.get(Asset, original.asset_id)
    if original.kind == ActionKind.QUARANTINE_FILE:
        mode = original.result.get("original_mode", "644")
        params = {"path": original.params["path"], "quarantine_id": original.id.hex[:12], "mode": mode}
        kind = ActionKind.RESTORE_QUARANTINE
    elif original.kind == ActionKind.RESTRICT_FILE:
        params = {"path": original.params["path"], "mode": original.result.get("original_mode", "644")}
        kind = ActionKind.RESTORE_PERMISSIONS
    else:
        raise ActionError("Tindakan ini tidak punya rollback.")
    if not MODE.match(params["mode"]):
        raise ActionError("Permission asli tidak tercatat dengan benar; rollback manual diperlukan.")
    action = create(db, kind=kind, asset=asset, params=params, user=user, ip=ip,
                    reason=f"Rollback dari tindakan {original.id}", rollback_of=original)
    original.rolled_back_by_id = action.id
    db.commit()
    return action


# --- execution ---------------------------------------------------------------------

def _run(db: Session, server: Server, cmds: list[tuple[str, str]]) -> list[ssh_client.CommandResult]:
    settings = get_settings()
    if not server.host_key:
        raise ActionError("Host key server belum di-pin; jalankan Tes koneksi terlebih dahulu.")
    target = _build_target(db, server)

    async def go():
        async with ssh_client.open_session(target, connect_timeout=settings.ssh_connect_timeout,
                                           command_timeout=120, max_output_bytes=16384) as session:
            out = []
            for _, cmd in cmds:
                r = await session.run(cmd)
                out.append(r)
                if r.exit_status != 0:
                    break  # stop at the first failing step
            return out

    return asyncio.run(go())


def _interpret(action: Action, labels: list[str], results: list[ssh_client.CommandResult]) -> dict:
    steps = [{"step": lab, "exit": r.exit_status, "stdout": r.stdout.strip()[:2000], "stderr": r.stderr.strip()[:1000]}
             for lab, r in zip(labels, results)]
    info: dict[str, Any] = {"steps": steps}
    first = results[0].stdout.strip().splitlines() if results else []
    if action.kind == ActionKind.QUARANTINE_FILE and first:
        parts = first[0].rsplit("|", 5)
        if len(parts) == 6:
            info.update(original_path=parts[0], size=int(parts[1]), mtime=int(parts[2]), owner=parts[3],
                        group=parts[4], original_mode=parts[5])
        if len(first) > 1:
            info["sha256"] = first[1].split()[0]
        if len(results) > 1:
            info["quarantine_dir"] = results[1].stdout.strip()
    if action.kind == ActionKind.RESTRICT_FILE and first:
        mode, owner, group = (first[0].split("|") + ["", ""])[:3]
        info.update(original_mode=mode, owner=owner, group=group)
    return info


def _verified(action: Action, results: list[ssh_client.CommandResult], expected_steps: int) -> bool:
    if len(results) < expected_steps or any(r.exit_status != 0 for r in results):
        return False
    last = results[-1].stdout.strip()
    return {
        ActionKind.QUARANTINE_FILE: last == "OK",
        ActionKind.RESTRICT_FILE: last == "600",
        ActionKind.RESTORE_PERMISSIONS: last == action.params.get("mode"),
        ActionKind.RESTORE_QUARANTINE: last.startswith(action.params.get("mode", "?")),
        ActionKind.RESTART_SERVICE: last == "active",
    }[action.kind]


def execute(db: Session, action_id: uuid.UUID) -> dict:
    action = db.get(Action, action_id)
    if action is None or action.state != ActionState.APPROVED:
        return {"state": "SKIPPED"}
    action.state, action.started_at = ActionState.RUNNING, utcnow()
    db.commit()
    server = db.get(Server, action.server_id)
    cmds = commands(action)
    try:
        results = _run(db, server, cmds)
        action.result = _interpret(action, [lab for lab, _ in cmds], results)
        ok = _verified(action, results, len(cmds))
        action.state = ActionState.SUCCEEDED if ok else ActionState.FAILED
        if not ok:
            failed = next((s for s in action.result["steps"] if s["exit"] != 0), action.result["steps"][-1])
            action.error = f"Langkah '{failed['step']}' gagal: {failed['stderr'] or failed['stdout'] or 'verifikasi tidak cocok'}"[:1000]
    except (ActionError, ValueError, SecretNotFound, ssh_client.HostKeyMismatch) as exc:
        action.state, action.error = ActionState.FAILED, str(exc)[:1000] or type(exc).__name__
        results = []
    except Exception as exc:  # network/auth errors
        action.state, action.error = ActionState.FAILED, f"{type(exc).__name__}: {exc}"[:1000]
        results = []
    action.finished_at = utcnow()
    audit.record(db, "action.execute", AuditResult.SUCCESS if action.state == ActionState.SUCCEEDED else AuditResult.FAILURE,
                 username="executor", asset_id=action.asset_id, tool=action.kind.value.lower(),
                 risk_level=action.risk_level, approval_id=action.id,
                 details={"action_id": str(action.id), "state": action.state.value, "error": action.error,
                          "commands": [{"step": lab, "sha256": audit.command_hash(cmd)} for lab, cmd in cmds],
                          "result": {k: v for k, v in action.result.items() if k != "steps"}})
    db.commit()

    if action.state == ActionState.SUCCEEDED:
        _reassess(db, action)  # PRD 49: re-scan and verify the asset after the change
    return {"state": action.state.value}


def _reassess(db: Session, action: Action) -> None:
    from app.services.assessments import active_assessment, enqueue
    asset = db.get(Asset, action.asset_id)
    if asset and not active_assessment(db, asset.id):
        enqueue(db, asset, None, "POST_ACTION", None)
