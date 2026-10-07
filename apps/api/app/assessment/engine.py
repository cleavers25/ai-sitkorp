"""Assessment orchestration: collect → store checks → reconcile findings → status (PRD 9, 12, 40, 51)."""

import asyncio
import hashlib
import uuid
from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.assessment import malware_scan, server_checks, web_checks
from app.assessment.types import CheckResult, clip, issue, passed, skipped
from app.core.config import get_settings
from app.core.enums import (
    AssessmentState, AssetStatus, AuditResult, CheckStatus, ConnectivityStatus, FindingCategory,
    FindingStatus, RiskLevel, Severity,
)
from app.db.base import utcnow
from app.models.assessment import Assessment, AssessmentCheck, Finding
from app.models.asset import Asset, Server, Website
from app.models.user import User
from app.services import audit, ssh_client
from app.services.connectivity import _build_target
from app.services.secrets import SecretNotFound

SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
MALWARE_ENGINES = {"malware_scan", "webshell_heuristic", "php_in_uploads", "clamav_scan", "yara_scan"}
ACTIVE_FINDING = (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED)


def fingerprint(check: str, target: str | None) -> str:
    return hashlib.sha256(f"{check}\x00{target or ''}".encode()).hexdigest()


def overall_status(results: list[CheckResult], suppressed: set[str] = frozenset()) -> AssetStatus:
    """RED if any CRITICAL/HIGH issue, YELLOW if any MEDIUM/LOW issue or a check errored, else GREEN."""
    status = AssetStatus.GREEN
    for r in results:
        if r.is_issue and fingerprint(r.check, r.target) not in suppressed:
            if r.severity in (Severity.CRITICAL, Severity.HIGH):
                return AssetStatus.RED
            if r.severity in (Severity.MEDIUM, Severity.LOW):
                status = AssetStatus.YELLOW
        elif r.status == CheckStatus.ERROR:
            status = AssetStatus.YELLOW
    return status


# --- collection ---------------------------------------------------------------

class _Collector:
    def __init__(self, db: Session):
        self.db = db
        self.settings = get_settings()
        self.commands: list[ssh_client.CommandResult] = []
        self.ssh_status: ConnectivityStatus | None = None
        self.ssh_error: str | None = None

    def _pin_host_key(self, server: Server, target: ssh_client.SSHTarget) -> None:
        if not server.host_key:
            key, fp = asyncio.run(ssh_client.fetch_host_key(
                server.hostname, server.ssh_port, self.settings.ssh_connect_timeout))
            server.host_key, server.host_key_fingerprint = key, fp
        target.known_host_key = server.host_key

    def over_ssh(self, server: Server, work) -> list[CheckResult]:
        """Open one SSH session to `server` and run `work(session)`; map connection problems to results."""
        if server.connectivity_status == ConnectivityStatus.HOST_KEY_MISMATCH:
            return [self._mismatch()]
        try:
            target = _build_target(self.db, server)
            self._pin_host_key(server, target)
        except (ValueError, SecretNotFound) as exc:
            return [skipped("ssh_connectivity", FindingCategory.CONNECTIVITY, f"Tidak bisa SSH: {exc}")]
        except Exception as exc:
            self.ssh_status, self.ssh_error = ConnectivityStatus.FAILED, f"{type(exc).__name__}: {exc}"
            return [server_checks.unreachable(self.ssh_error)]

        async def go():
            async with ssh_client.open_session(
                target, connect_timeout=self.settings.ssh_connect_timeout,
                command_timeout=self.settings.ssh_command_timeout,
                max_output_bytes=self.settings.ssh_max_output_bytes,
            ) as session:
                try:
                    return await work(session)
                finally:
                    self.commands += session.executed

        try:
            results = asyncio.run(go())
            self.ssh_status, self.ssh_error = ConnectivityStatus.OK, None
            return [passed("ssh_connectivity", FindingCategory.CONNECTIVITY, "Koneksi SSH berhasil",
                           target=f"{server.hostname}:{server.ssh_port}")] + results
        except ssh_client.HostKeyMismatch:
            self.ssh_status = ConnectivityStatus.HOST_KEY_MISMATCH
            return [self._mismatch()]
        except Exception as exc:
            self.ssh_status, self.ssh_error = ConnectivityStatus.FAILED, f"{type(exc).__name__}: {exc}"[:1000]
            return [server_checks.unreachable(self.ssh_error)]

    @staticmethod
    def _mismatch() -> CheckResult:
        return issue("ssh_connectivity", FindingCategory.CONNECTIVITY,
                     "Host key SSH berubah — koneksi diblokir", Severity.CRITICAL,
                     description="Kunci host server berbeda dari yang di-pin. Bisa berarti server di-install ulang "
                                 "atau ada serangan man-in-the-middle.",
                     recommendation="Verifikasi fingerprint langsung di server, lalu reset host key di halaman server.")

    def collect(self, asset: Asset) -> list[CheckResult]:
        if isinstance(asset, Server):
            from app.assessment.wazuh_checks import run_wazuh_checks
            return self.over_ssh(asset, server_checks.run_server_checks) + run_wazuh_checks(self.db, asset)
        if isinstance(asset, Website):
            return self._website(asset)
        return [skipped("unsupported", FindingCategory.SYSTEM, f"Asset {asset.asset_type.value} belum didukung")]

    def _website(self, site: Website) -> list[CheckResult]:
        async def web():
            async with web_checks.make_client() as client:
                return await web_checks.run_web_checks(site.url, client)

        results = asyncio.run(web())
        from app.services.backups import status_check
        results.append(status_check(self.db, site))
        server = site.server
        cat = FindingCategory.MALWARE
        if server is None:
            results.append(skipped("malware_scan", cat, "Website belum dihubungkan ke server; scan file dilewati",
                                   recommendation="Hubungkan website ke server-nya dan isi document root."))
        elif not site.document_root:
            results.append(skipped("malware_scan", cat, "Document root belum diisi; scan file dilewati",
                                   recommendation="Isi document root website (mis. /var/www/example)."))
        elif server.credential_id is None:
            results.append(skipped("malware_scan", cat, "Server belum punya credential SSH; scan file dilewati"))
        else:
            results += self.over_ssh(server, lambda s: malware_scan.run_malware_scan(s, site.document_root))
            if self.ssh_status:
                server.connectivity_status = self.ssh_status
                server.last_connectivity_check_at = utcnow()
                server.last_connectivity_error = self.ssh_error
        return results


# --- persistence & reconciliation --------------------------------------------

def _resolvable_checks(results: list[CheckResult]) -> set[str]:
    """Checks that ran cleanly, so a finding that is absent this time really means 'fixed'."""
    statuses: dict[str, set[CheckStatus]] = {}
    for r in results:
        statuses.setdefault(r.check, set()).add(r.status)
    ok = {c for c, st in statuses.items() if CheckStatus.ERROR not in st and st != {CheckStatus.SKIPPED}}
    # A file flagged earlier by e.g. ClamAV must not be auto-resolved just because ClamAV errored now.
    if any(r.check in MALWARE_ENGINES and r.status == CheckStatus.ERROR for r in results):
        ok.discard("malware_file")
    return ok


def reconcile(db: Session, assessment: Assessment, results: list[CheckResult]) -> tuple[dict[str, Any], list[Finding]]:
    now = utcnow()
    existing = {f.fingerprint: f for f in db.scalars(select(Finding).where(Finding.asset_id == assessment.asset_id))}
    seen: set[str] = set()
    diff = Counter()
    changed: list[Finding] = []  # new or reopened this run -> notifications

    for pos, r in enumerate(results):
        row = AssessmentCheck(
            position=pos, check=r.check, category=r.category, target=r.target, status=r.status,
            severity=r.severity, title=r.title[:255], value=(r.value or None) and r.value[:255],
            evidence=r.evidence, recommendation=r.recommendation, duration_ms=r.duration_ms,
        )
        assessment.checks.append(row)
        if not r.is_issue:
            continue
        fp = fingerprint(r.check, r.target)
        seen.add(fp)
        f = existing.get(fp)
        if f is None:
            f = Finding(asset_id=assessment.asset_id, fingerprint=fp, check=r.check, category=r.category,
                        severity=r.severity, status=FindingStatus.OPEN, confidence=r.confidence,
                        title=r.title[:255], description=r.description, target=r.target, evidence=r.evidence,
                        recommendation=r.recommendation, first_seen=now, last_seen=now,
                        first_assessment_id=assessment.id, last_assessment_id=assessment.id)
            db.add(f)
            existing[fp] = f
            diff["new"] += 1
            changed.append(f)
        else:
            if f.status == FindingStatus.RESOLVED:
                f.status = FindingStatus.OPEN
                f.reopened_count += 1
                f.resolved_at = None
                diff["reopened"] += 1
                changed.append(f)
            elif f.status == FindingStatus.FALSE_POSITIVE:
                diff["suppressed"] += 1
            else:
                diff["persistent"] += 1
            if SEVERITY_ORDER.index(r.severity) != SEVERITY_ORDER.index(f.severity):
                diff["severity_changed"] += 1
            f.severity, f.confidence, f.title = r.severity, r.confidence, r.title[:255]
            f.description, f.evidence, f.recommendation = r.description, r.evidence, r.recommendation
            f.last_seen, f.last_assessment_id = now, assessment.id
            f.occurrence_count += 1
        db.flush()
        row.finding_id = f.id

    resolvable = _resolvable_checks(results)
    for fp, f in existing.items():
        if fp not in seen and f.status in ACTIVE_FINDING and f.check in resolvable:
            f.status, f.resolved_at, f.last_assessment_id = FindingStatus.RESOLVED, now, assessment.id
            diff["resolved"] += 1

    suppressed = {fp for fp, f in existing.items() if f.status == FindingStatus.FALSE_POSITIVE}
    assessment.overall_status = overall_status(results, suppressed)
    sev = Counter(r.severity.value for r in results if r.is_issue and fingerprint(r.check, r.target) not in suppressed)
    return {
        "checks": dict(Counter(r.status.value for r in results)),
        "severity": {s.value: sev.get(s.value, 0) for s in SEVERITY_ORDER},
        "diff": {k: diff.get(k, 0) for k in ("new", "persistent", "resolved", "reopened", "suppressed")},
        "malware_suspected": sum(1 for r in results if r.check == "malware_file" and r.is_issue),
    }, changed


def run_assessment(db: Session, assessment_id: uuid.UUID) -> dict:
    assessment = db.get(Assessment, assessment_id)
    if assessment is None or assessment.state not in (AssessmentState.QUEUED, AssessmentState.RUNNING):
        return {"state": "SKIPPED"}
    asset = db.get(Asset, assessment.asset_id)
    user = db.get(User, assessment.requested_by_id) if assessment.requested_by_id else None
    assessment.state, assessment.started_at = AssessmentState.RUNNING, utcnow()
    db.commit()

    collector = _Collector(db)
    prev_status, changed = asset.status, []
    try:
        results = collector.collect(asset)
        if isinstance(asset, Server) and collector.ssh_status:
            asset.connectivity_status = collector.ssh_status
            asset.last_connectivity_check_at = utcnow()
            asset.last_connectivity_error = collector.ssh_error
        assessment.summary, changed = reconcile(db, assessment, results)
        assessment.state = AssessmentState.COMPLETED
        asset.status = assessment.overall_status
        asset.last_assessed_at = utcnow()
        asset.last_assessment_id = assessment.id
        result = AuditResult.SUCCESS
    except Exception as exc:
        db.rollback()
        assessment = db.get(Assessment, assessment_id)
        asset = db.get(Asset, assessment.asset_id)
        assessment.state = AssessmentState.FAILED
        assessment.error = clip(f"{type(exc).__name__}: {exc}", 2000)
        result = AuditResult.FAILURE

    assessment.finished_at = utcnow()
    audit.record(
        db, "assessment.run", result, user=user, username=None if user else "scheduler",
        asset_id=asset.id, tool="assessment", risk_level=RiskLevel.SAFE,
        details={
            "assessment_id": str(assessment.id), "asset": asset.name, "state": assessment.state.value,
            "overall_status": assessment.overall_status.value if assessment.overall_status else None,
            "error": assessment.error,
            "commands": [{"sha256": audit.command_hash(c.command), "exit": c.exit_status}
                         for c in collector.commands],
        },
    )
    db.commit()
    try:
        from app.services.notify_hooks import after_assessment
        after_assessment(db, assessment, asset, prev_status, changed)
    except Exception:  # notifications must never break an assessment
        db.rollback()
    return {"state": assessment.state.value,
            "overall_status": assessment.overall_status.value if assessment.overall_status else None}
