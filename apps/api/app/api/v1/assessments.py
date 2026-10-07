import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DB, client_ip, require
from app.core.enums import (
    AssessmentState, AssetType, AuditResult, FindingCategory, FindingStatus, RiskLevel, Severity,
)
from app.core.rbac import Permission
from app.db.base import utcnow
from app.models.assessment import Assessment, Finding
from app.models.asset import Asset
from app.models.user import User
from app.reports import render
from app.schemas.assessment import (
    AssessmentDetail, AssessmentListItem, AssessmentOut, AssetRef, FindingOut, RunAllOut,
    RunAllRequest, TriageRequest,
)
from app.schemas.common import Page
from app.services import audit
from app.services.assessments import SUPPORTED, active_assessment as _active_assessment, enqueue

router = APIRouter(tags=["assessments"])
Viewer = Annotated[User, Depends(require(Permission.ASSET_VIEW))]
Runner = Annotated[User, Depends(require(Permission.ASSESSMENT_RUN))]
Triager = Annotated[User, Depends(require(Permission.FINDING_TRIAGE))]

def _asset_ref(db: Session, asset_id: uuid.UUID) -> AssetRef | None:
    asset = db.get(Asset, asset_id)
    return AssetRef.model_validate(asset) if asset else None


# --- running -------------------------------------------------------------------

@router.post("/assets/{asset_id}/assess", response_model=AssessmentOut, status_code=status.HTTP_202_ACCEPTED)
def assess_asset(asset_id: uuid.UUID, user: Runner, request: Request, db: DB):
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    if asset.asset_type not in SUPPORTED:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Assessment is not supported for this asset type")
    if _active_assessment(db, asset.id):
        db.commit()
        raise HTTPException(status.HTTP_409_CONFLICT, "An assessment is already running for this asset")
    return enqueue(db, asset, user, "MANUAL", client_ip(request))


@router.post("/assessments/run-all", response_model=RunAllOut, status_code=status.HTTP_202_ACCEPTED)
def run_all(body: RunAllRequest, user: Runner, request: Request, db: DB):
    types = [body.asset_type] if body.asset_type else list(SUPPORTED)
    assets = db.scalars(select(Asset).where(Asset.asset_type.in_(types)).order_by(Asset.name)).all()
    queued = skipped = 0
    for asset in assets:
        if _active_assessment(db, asset.id):
            skipped += 1
            continue
        enqueue(db, asset, user, "BULK", client_ip(request))
        queued += 1
    db.commit()
    return RunAllOut(queued=queued, skipped_active=skipped)


# --- history -------------------------------------------------------------------

@router.get("/assessments", response_model=Page[AssessmentListItem])
def list_assessments(
    _: Viewer, db: DB,
    asset_id: uuid.UUID | None = None,
    state: AssessmentState | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Assessment)
    if asset_id:
        stmt = stmt.where(Assessment.asset_id == asset_id)
    if state:
        stmt = stmt.where(Assessment.state == state)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Assessment.created_at.desc()).limit(limit).offset(offset)).all()
    names = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_({r.asset_id for r in rows})))}
    items = [AssessmentListItem.model_validate(r).model_copy(
        update={"asset": AssetRef.model_validate(names[r.asset_id]) if r.asset_id in names else None})
        for r in rows]
    return Page(items=items, total=total, limit=limit, offset=offset)


def _get_assessment(db: Session, assessment_id: uuid.UUID) -> Assessment:
    a = db.get(Assessment, assessment_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Assessment not found")
    return a


@router.get("/assessments/{assessment_id}", response_model=AssessmentDetail)
def get_assessment(assessment_id: uuid.UUID, _: Viewer, db: DB):
    a = _get_assessment(db, assessment_id)
    return AssessmentDetail(**AssessmentOut.model_validate(a).model_dump(),
                            asset=_asset_ref(db, a.asset_id), checks=list(a.checks))


# --- report --------------------------------------------------------------------

REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"


@router.get("/assessments/{assessment_id}/report")
def report(assessment_id: uuid.UUID, user: Viewer, request: Request, db: DB,
           format: Literal["html", "markdown", "json"] = "html"):
    a = _get_assessment(db, assessment_id)
    if a.state != AssessmentState.COMPLETED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Assessment has not completed")
    asset = db.get(Asset, a.asset_id)
    findings = db.scalars(select(Finding).where(Finding.asset_id == a.asset_id)).all()
    previous = db.scalars(
        select(Assessment).where(Assessment.asset_id == a.asset_id, Assessment.state == AssessmentState.COMPLETED,
                                 Assessment.created_at < a.created_at)
        .order_by(Assessment.created_at.desc()).limit(1)).first()
    ctx = render.build_context(a, asset, list(findings), previous)
    audit.record(db, "report.generate", user=user, source_ip=client_ip(request), asset_id=asset.id,
                 details={"assessment_id": str(a.id), "format": format})
    db.commit()

    stamp = (a.finished_at or a.created_at).strftime("%Y%m%d-%H%M")
    base = f"report-{asset.name}-{stamp}".replace(" ", "_").replace("/", "_")
    if format == "json":
        return JSONResponse(render.render_json(ctx),
                            headers={"Content-Disposition": f'attachment; filename="{base}.json"'})
    if format == "markdown":
        return Response(render.render_markdown(ctx), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="{base}.md"'})
    return HTMLResponse(render.render_html(ctx), headers={"Content-Security-Policy": REPORT_CSP,
                                                         "X-Frame-Options": "SAMEORIGIN"})


# --- findings ------------------------------------------------------------------

@router.get("/findings", response_model=Page[FindingOut])
def list_findings(
    _: Viewer, db: DB,
    asset_id: uuid.UUID | None = None,
    status_: Annotated[list[FindingStatus] | None, Query(alias="status")] = None,
    severity: Annotated[list[Severity] | None, Query()] = None,
    category: FindingCategory | None = None,
    q: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    stmt = select(Finding)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    if status_:
        stmt = stmt.where(Finding.status.in_(status_))
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity))
    if category:
        stmt = stmt.where(Finding.category == category)
    if q:
        stmt = stmt.where(Finding.title.ilike(f"%{q}%"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Finding.last_seen.desc()).limit(limit).offset(offset)).all()
    assets = {a.id: a for a in db.scalars(select(Asset).where(Asset.id.in_({r.asset_id for r in rows})))}
    items = [FindingOut.model_validate(r).model_copy(
        update={"asset": AssetRef.model_validate(assets[r.asset_id]) if r.asset_id in assets else None})
        for r in rows]
    return Page(items=items, total=total, limit=limit, offset=offset)


def _get_finding(db: Session, finding_id: uuid.UUID) -> Finding:
    f = db.get(Finding, finding_id)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return f


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: uuid.UUID, _: Viewer, db: DB):
    f = _get_finding(db, finding_id)
    return FindingOut.model_validate(f).model_copy(update={"asset": _asset_ref(db, f.asset_id)})


def _triage(db: Session, finding_id: uuid.UUID, user: User, request: Request, new: FindingStatus,
            allowed_from: tuple[FindingStatus, ...], note: str | None, action: str) -> FindingOut:
    f = _get_finding(db, finding_id)
    if f.status not in allowed_from:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Cannot change a {f.status.value} finding to {new.value}")
    old = f.status
    f.status, f.triaged_by_id, f.triaged_at, f.triage_note = new, user.id, utcnow(), note
    if new == FindingStatus.OPEN:
        f.resolved_at = None
    audit.record(db, action, AuditResult.SUCCESS, user=user, source_ip=client_ip(request), asset_id=f.asset_id,
                 risk_level=RiskLevel.LOW,
                 details={"finding_id": str(f.id), "title": f.title, "from": old.value, "to": new.value,
                          "note": note})
    db.commit()
    return FindingOut.model_validate(f).model_copy(update={"asset": _asset_ref(db, f.asset_id)})


@router.post("/findings/{finding_id}/acknowledge", response_model=FindingOut)
def acknowledge(finding_id: uuid.UUID, body: TriageRequest, user: Triager, request: Request, db: DB):
    return _triage(db, finding_id, user, request, FindingStatus.ACKNOWLEDGED, (FindingStatus.OPEN,),
                   body.note, "finding.acknowledge")


@router.post("/findings/{finding_id}/false-positive", response_model=FindingOut)
def false_positive(finding_id: uuid.UUID, body: TriageRequest, user: Triager, request: Request, db: DB):
    if not body.note:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A note explaining the false positive is required")
    return _triage(db, finding_id, user, request, FindingStatus.FALSE_POSITIVE,
                   (FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED), body.note, "finding.false_positive")


@router.post("/findings/{finding_id}/reopen", response_model=FindingOut)
def reopen(finding_id: uuid.UUID, body: TriageRequest, user: Triager, request: Request, db: DB):
    return _triage(db, finding_id, user, request, FindingStatus.OPEN,
                   (FindingStatus.ACKNOWLEDGED, FindingStatus.FALSE_POSITIVE), body.note, "finding.reopen")
