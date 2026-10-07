"""Turn domain changes into notification events (PRD 43 triggers). Only changes notify, never steady state."""

from sqlalchemy.orm import Session

from app.core.enums import AssessmentState, AssetStatus, FindingCategory, Severity
from app.models.assessment import Assessment, Finding
from app.models.asset import Asset
from app.services.notify import emit

HIGH = (Severity.HIGH, Severity.CRITICAL)
SEV_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def _asset_link(asset: Asset) -> str:
    return f"/{'servers' if asset.asset_type.value == 'SERVER' else 'websites'}/{asset.id}"


def _max_sev(findings: list[Finding]) -> Severity:
    return max((f.severity for f in findings), key=SEV_ORDER.index)


def _lines(findings: list[Finding]) -> str:
    return "\n".join(f"- [{f.severity.value}] {f.title}" + (f" ({f.target})" if f.target else "") for f in findings[:20])


def after_assessment(db: Session, assessment: Assessment, asset: Asset, prev_status: AssetStatus,
                     changed: list[Finding]) -> None:
    link = _asset_link(asset)
    if assessment.state == AssessmentState.FAILED:
        emit(db, "assessment_failed", Severity.MEDIUM, f"Assessment {asset.name} gagal",
             assessment.error or "", asset_id=asset.id, link=f"/assessments/{assessment.id}")
        return

    if assessment.overall_status == AssetStatus.RED and prev_status != AssetStatus.RED:
        emit(db, "asset_red", Severity.HIGH, f"{asset.name} berubah menjadi RED",
             f"Status sebelumnya: {prev_status.value}.\nTemuan:\n{_lines(changed) or '- (lihat detail assessment)'}",
             asset_id=asset.id, link=link, data={"from": prev_status.value})

    malware = [f for f in changed if f.category == FindingCategory.MALWARE and f.severity in HIGH]
    ssl_issues = [f for f in changed if f.check in ("ssl_certificate", "tls_protocol")]
    down = [f for f in changed if f.check in ("ssh_connectivity", "http_availability") and f.severity in HIGH]
    # Announced elsewhere, not repeated here: backup problems by the backup run (services.backups),
    # Wazuh alerts within minutes by the poller (services.wazuh_poll).
    announced_elsewhere = [f for f in changed if f.check in ("backup_status", "wazuh_alerts")]
    grouped = {id(f) for f in malware + ssl_issues + down + announced_elsewhere}
    other = [f for f in changed if f.severity in HIGH and id(f) not in grouped]

    for type_, items, title in (
        ("malware", malware, f"Dugaan malware di {asset.name}"),
        ("ssl", ssl_issues, f"Masalah SSL di {asset.name}"),
        ("unreachable", down, f"{asset.name} tidak terjangkau"),
        ("new_findings", other, f"{len(other)} temuan HIGH/CRITICAL baru di {asset.name}"),
    ):
        if items:
            emit(db, type_, _max_sev(items), title, _lines(items), asset_id=asset.id, link=link,
                 data={"findings": [str(f.id) for f in items], "assessment_id": str(assessment.id)})
