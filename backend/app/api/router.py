import uuid
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response, JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.db import models
from app.schemas import ScanCreate, ScanOut, ScanSummary
from app.services.reporting import build_pdf
from app.api.deps import get_current_user, require_project_access
from app.tasks.scans import run_scan_task

router = APIRouter()


@router.post("/scan", response_model=ScanSummary)
async def create_scan(
    payload: ScanCreate,
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ScanSummary:
    target_url = payload.target_url
    if payload.demo_mode:
        target_url = "http://localhost:8000/demo/users/1"
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Target URL must start with http or https")

    await require_project_access(payload.project_id, user, session)

    scan_id = str(uuid.uuid4())
    scan = models.Scan(
        id=scan_id,
        project_id=payload.project_id,
        created_by=user.id,
        target_url=target_url,
        status="queued",
    )
    session.add(scan)
    await session.commit()

    run_scan_task.delay(scan_id, target_url, payload.bearer_token)

    return ScanSummary(
        id=scan.id,
        project_id=scan.project_id,
        target_url=scan.target_url,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        summary_risk=scan.summary_risk,
    )


@router.get("/scans", response_model=list[ScanSummary])
async def list_scans(
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> list[ScanSummary]:
    result = await session.execute(
        select(models.Scan)
        .join(models.Project)
        .join(models.Workspace)
        .join(models.Membership, models.Membership.workspace_id == models.Workspace.id)
        .where(models.Membership.user_id == user.id)
        .order_by(models.Scan.created_at.desc())
    )
    scans = result.scalars().all()
    return [
        ScanSummary(
            id=scan.id,
            project_id=scan.project_id,
            target_url=scan.target_url,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            summary_risk=scan.summary_risk,
        )
        for scan in scans
    ]


@router.get("/scan/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: str,
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> ScanOut:
    result = await session.execute(
        select(models.Scan).options(selectinload(models.Scan.findings)).where(models.Scan.id == scan_id)
    )
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await require_project_access(scan.project_id, user, session)

    return ScanOut(
        id=scan.id,
        project_id=scan.project_id,
        target_url=scan.target_url,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        summary_risk=scan.summary_risk,
        findings=[
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in scan.findings
        ],
    )


@router.get("/scan/{scan_id}/report")
async def export_report(
    scan_id: str,
    format: str = "json",
    session: AsyncSession = Depends(get_db),
    user: models.User = Depends(get_current_user),
) -> Response:
    result = await session.execute(
        select(models.Scan).options(selectinload(models.Scan.findings)).where(models.Scan.id == scan_id)
    )
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    await require_project_access(scan.project_id, user, session)

    if format.lower() == "pdf":
        pdf_bytes = build_pdf(scan, scan.findings)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.pdf"},
        )

    payload = {
        "id": scan.id,
        "project_id": scan.project_id,
        "target_url": scan.target_url,
        "status": scan.status,
        "created_at": scan.created_at.isoformat(),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "summary_risk": scan.summary_risk,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity,
                "cvss_score": f.cvss_score,
                "confidence": f.confidence,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in scan.findings
        ],
    }
    return JSONResponse(payload)
