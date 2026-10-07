"""Website backups (PRD 13): stream a tar.gz of the document root over SSH to local disk, then verify.

Read-only on the target: `tar` only reads the document root and writes to stdout.
Verification = the archive is read end to end (gzip CRC catches corruption) and its file count
matches a `find` count taken on the server with the same exclusions.
"""

import asyncio
import hashlib
import shlex
import tarfile
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment.types import CheckResult, issue, passed, skipped
from app.core.config import get_settings
from app.core.enums import AuditResult, BackupState, Criticality, FindingCategory, RiskLevel, Severity
from app.db.base import utcnow
from app.models.asset import Server, Website
from app.models.backup import Backup
from app.models.user import User
from app.services import audit, ssh_client
from app.services.assessments import as_aware
from app.services.connectivity import _build_target

EXCLUDES = ("wp-content/cache", "node_modules", "cache", ".cache", "tmp")
COUNT_TOLERANCE = 0.01  # files may legitimately change between the count and the archive


class BackupError(Exception):
    pass


def _validated_root(site: Website) -> str:
    from app.assessment.malware_scan import validate_docroot
    if not site.document_root:
        raise BackupError("Document root website belum diisi.")
    return validate_docroot(site.document_root)


def tar_command(root: str) -> str:
    ex = " ".join(f"--exclude={shlex.quote('./' + e)}" for e in EXCLUDES)
    return f"tar -czf - -C {shlex.quote(root)} {ex} ."


def count_command(root: str) -> str:
    prune = " -o ".join(f"-path {shlex.quote('./' + e)}" for e in EXCLUDES)
    return f"cd {shlex.quote(root)} && find . \\( {prune} \\) -prune -o -type f -print | wc -l"


def start(db: Session, site: Website, user: User | None, trigger: str, schedule_run_id=None) -> Backup:
    from app.worker.tasks import run_backup_task
    b = Backup(id=uuid.uuid4(), asset_id=site.id, trigger=trigger, requested_by_id=user.id if user else None,
               state=BackupState.RUNNING, started_at=utcnow(), source_path=site.document_root,
               schedule_run_id=schedule_run_id)
    db.add(b)
    audit.record(db, "backup.request", user=user, username=None if user else "scheduler", asset_id=site.id,
                 tool="backup", risk_level=RiskLevel.SAFE,
                 details={"backup_id": str(b.id), "website": site.name, "trigger": trigger})
    db.commit()
    run_backup_task.delay(str(b.id))
    return b


def verify_archive(path: Path) -> int:
    """Read every member fully; raises on corruption. Returns the number of regular files."""
    files = 0
    with tarfile.open(path, "r:gz") as tar:
        for member in tar:
            if member.isfile():
                files += 1
                f = tar.extractfile(member)
                while f and f.read(1024 * 1024):
                    pass
    return files


def run(db: Session, backup_id: uuid.UUID) -> dict:
    settings = get_settings()
    b = db.get(Backup, backup_id)
    if b is None or b.state != BackupState.RUNNING or b.finished_at:
        return {"state": "SKIPPED"}
    site = db.get(Website, b.asset_id)
    dest = Path(settings.backup_dir) / str(site.id) / f"{b.started_at:%Y%m%d-%H%M%S}-{b.id.hex[:8]}.tar.gz"
    digest = hashlib.sha256()
    try:
        root = _validated_root(site)
        server = db.get(Server, site.server_id) if site.server_id else None
        if server is None:
            raise BackupError("Website belum dihubungkan ke server.")
        if not server.host_key:
            raise BackupError("Host key server belum di-pin; jalankan Tes koneksi terlebih dahulu.")
        target = _build_target(db, server)
        dest.parent.mkdir(parents=True, exist_ok=True)

        async def go():
            async with ssh_client.open_session(target, connect_timeout=settings.ssh_connect_timeout,
                                               command_timeout=600, max_output_bytes=65536) as s:
                count = await s.run(count_command(root))
                with open(dest, "wb") as fh:
                    def sink(chunk: bytes):
                        digest.update(chunk)
                        fh.write(chunk)
                    status, stderr, size = await s.stream_to_file(
                        tar_command(root), sink, timeout=settings.backup_timeout, max_bytes=settings.backup_max_bytes)
                return count, status, stderr, size

        count, status, stderr, size = asyncio.run(go())
        # GNU tar: 0 = ok, 1 = some files changed while being read (archive still usable), 2 = fatal.
        if status not in (0, 1):
            raise BackupError(f"tar gagal (exit {status}): {stderr.strip()[:500]}")
        b.size_bytes, b.sha256 = size, digest.hexdigest()
        b.storage_path = str(dest)
        b.remote_file_count = int(count.stdout.strip() or 0) if count.exit_status == 0 else None
        try:
            b.file_count = verify_archive(dest)
        except (tarfile.TarError, OSError, EOFError) as exc:
            raise BackupError(f"Verifikasi gagal: arsip rusak ({exc})")
        notes = []
        if status == 1:
            notes.append("beberapa file berubah saat dibaca (tar exit 1)")
        if b.remote_file_count is None:
            notes.append("jumlah file di server tidak dapat dihitung")
            b.verified = True
        else:
            diff = abs(b.file_count - b.remote_file_count)
            b.verified = diff <= max(1, int(b.remote_file_count * COUNT_TOLERANCE))
            if not b.verified:
                notes.append(f"jumlah file tidak cocok: arsip {b.file_count}, server {b.remote_file_count} "
                             f"(kemungkinan ada file yang tidak bisa dibaca user SSH)")
        b.verify_note = "; ".join(notes) or "arsip terbaca utuh dan jumlah file cocok"
        b.state = BackupState.SUCCEEDED
    except Exception as exc:
        b.state, b.error = BackupState.FAILED, (str(exc) or type(exc).__name__)[:1000]
        dest.unlink(missing_ok=True)
    b.finished_at = utcnow()
    audit.record(db, "backup.run", AuditResult.SUCCESS if b.state == BackupState.SUCCEEDED else AuditResult.FAILURE,
                 username="executor", asset_id=site.id, tool="backup", risk_level=RiskLevel.SAFE,
                 details={"backup_id": str(b.id), "website": site.name, "state": b.state.value,
                          "size_bytes": b.size_bytes, "sha256": b.sha256, "files": b.file_count,
                          "remote_files": b.remote_file_count, "verified": b.verified, "error": b.error})
    db.commit()
    if b.state == BackupState.SUCCEEDED:
        prune(db, site.id)
    if b.state == BackupState.FAILED or not b.verified:
        try:
            from app.services.notify import emit
            emit(db, "backup_failed", Severity.HIGH if b.state == BackupState.FAILED else Severity.MEDIUM,
                 f"Backup {site.name} {'gagal' if b.state == BackupState.FAILED else 'tidak lolos verifikasi'}",
                 b.error or b.verify_note or "", asset_id=site.id, link="/backups", data={"backup_id": str(b.id)})
        except Exception:
            db.rollback()
    return {"state": b.state.value}


def prune(db: Session, asset_id: uuid.UUID) -> int:
    keep = get_settings().backup_retention
    done = db.scalars(select(Backup).where(Backup.asset_id == asset_id, Backup.state == BackupState.SUCCEEDED,
                                           Backup.pruned.is_(False)).order_by(Backup.started_at.desc())).all()
    removed = 0
    for old in done[keep:]:
        if old.storage_path:
            Path(old.storage_path).unlink(missing_ok=True)
        old.pruned, removed = True, removed + 1
    db.commit()
    return removed


def status_check(db: Session, site: Website) -> CheckResult:
    """Backup health for the website assessment (PRD 13: GREEN recent+valid, YELLOW aging, RED failed/missing)."""
    important = site.criticality in (Criticality.HIGH, Criticality.CRITICAL)
    latest = db.scalars(select(Backup).where(Backup.asset_id == site.id, Backup.state != BackupState.RUNNING)
                        .order_by(Backup.started_at.desc()).limit(1)).first()
    last_ok = db.scalars(select(Backup).where(Backup.asset_id == site.id, Backup.state == BackupState.SUCCEEDED)
                         .order_by(Backup.started_at.desc()).limit(1)).first()
    rec = "Aktifkan jadwal backup (menu Jadwal → jenis Backup) dan pastikan backup terakhir berhasil & terverifikasi."
    if latest is None:
        if not site.document_root or not site.server_id:
            return skipped("backup_status", FindingCategory.BACKUP, "Backup belum bisa dijalankan (server/document root belum diisi)")
        return issue("backup_status", FindingCategory.BACKUP, "Belum ada backup untuk website ini",
                     Severity.HIGH if important else Severity.LOW, recommendation=rec)
    ev = {"last_backup": latest.started_at.isoformat(), "state": latest.state.value, "verified": latest.verified,
          "size_bytes": latest.size_bytes, "note": latest.verify_note or latest.error}
    if latest.state == BackupState.FAILED:
        return issue("backup_status", FindingCategory.BACKUP, "Backup terakhir gagal",
                     Severity.HIGH if important else Severity.MEDIUM, value=(latest.error or "")[:255],
                     evidence=ev, recommendation=rec)
    if not latest.verified:
        return issue("backup_status", FindingCategory.BACKUP, "Backup terakhir tidak lolos verifikasi", Severity.HIGH,
                     value=(latest.verify_note or "")[:255], evidence=ev, recommendation=rec)
    age = utcnow() - as_aware(last_ok.started_at)
    if age > timedelta(hours=48):
        return issue("backup_status", FindingCategory.BACKUP, f"Backup terakhir sudah {age.days} hari",
                     Severity.MEDIUM, value=f"{age.days} hari", evidence=ev, recommendation=rec)
    return passed("backup_status", FindingCategory.BACKUP, "Backup terbaru valid & terverifikasi",
                  value=f"{(latest.size_bytes or 0) // 1024} KB", evidence=ev)
