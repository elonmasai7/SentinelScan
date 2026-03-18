from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.db import models
from app.db.session import AsyncSessionLocal
from app.domain.scoring import cvss_score
from app.services.engine import run_plugins
from app.services.remediation import get_remediation_service


async def run_scan(session: AsyncSession, scan_id: str, target_url: str, bearer_token: str | None) -> None:
    scan = await session.get(models.Scan, scan_id)
    if scan:
        scan.status = "running"
        await session.commit()

    result = await run_plugins(target_url, bearer_token)
    remediation_service = get_remediation_service()

    scan = await session.get(models.Scan, scan_id)
    if not scan:
        return

    for finding in result.findings:
        remediation_text = await remediation_service.explain(finding)
        session.add(
            models.Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                title=finding.title,
                category=finding.category,
                severity=finding.severity,
                cvss_score=cvss_score(finding.severity),
                confidence=finding.confidence,
                plugin=finding.plugin,
                cwe=finding.cwe,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
                remediation=remediation_text,
            )
        )

    scan.status = "completed"
    scan.completed_at = datetime.utcnow()
    scan.summary_risk = max((cvss_score(f.severity) for f in result.findings), default=0.0)
    await session.commit()


async def run_scan_background(scan_id: str, target_url: str, bearer_token: str | None) -> None:
    async with AsyncSessionLocal() as session:
        try:
            await run_scan(session, scan_id, target_url, bearer_token)
        except Exception:
            scan = await session.get(models.Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                scan.summary_risk = 0.0
                session.add(scan)
                await session.commit()
