import uuid
from datetime import datetime

from sqlalchemy import select

from app.core.config import get_settings
from app.core.security import hash_password
from app.db import models
from app.db.session import AsyncSessionLocal


async def seed_demo_user() -> None:
    settings = get_settings()
    if not settings.demo_seed:
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(models.User).where(models.User.email == settings.demo_email))
        existing = result.scalars().first()
        if existing:
            return

        user = models.User(
            id=str(uuid.uuid4()),
            email=settings.demo_email,
            password_hash=hash_password(settings.demo_password),
        )
        session.add(user)

        workspace = models.Workspace(
            id=str(uuid.uuid4()),
            name="Demo Workspace",
            owner_id=user.id,
        )
        session.add(workspace)

        membership = models.Membership(
            id=str(uuid.uuid4()),
            user_id=user.id,
            workspace_id=workspace.id,
            role="owner",
        )
        session.add(membership)

        project = models.Project(
            id=str(uuid.uuid4()),
            workspace_id=workspace.id,
            name="Demo Project",
        )
        session.add(project)

        await session.commit()


async def seed_demo_data() -> None:
    settings = get_settings()
    if not settings.demo_seed:
        return

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(models.User).where(models.User.email == settings.demo_email))
        user = result.scalars().first()

        if not user:
            user = models.User(
                id=str(uuid.uuid4()),
                email=settings.demo_email,
                password_hash=hash_password(settings.demo_password),
            )
            session.add(user)

        result = await session.execute(select(models.Workspace).where(models.Workspace.owner_id == user.id))
        workspace = result.scalars().first()
        if not workspace:
            workspace = models.Workspace(
                id=str(uuid.uuid4()),
                name="Demo Workspace",
                owner_id=user.id,
            )
            session.add(workspace)
            membership = models.Membership(
                id=str(uuid.uuid4()),
                user_id=user.id,
                workspace_id=workspace.id,
                role="owner",
            )
            session.add(membership)

        result = await session.execute(select(models.Project).where(models.Project.workspace_id == workspace.id))
        project = result.scalars().first()
        if not project:
            project = models.Project(
                id=str(uuid.uuid4()),
                workspace_id=workspace.id,
                name="Demo Project",
            )
            session.add(project)

        await session.commit()

        result = await session.execute(select(models.Scan).where(models.Scan.project_id == project.id))
        existing_scan = result.scalars().first()
        if existing_scan:
            return

        scan_id = str(uuid.uuid4())
        now = datetime.utcnow()
        scan = models.Scan(
            id=scan_id,
            project_id=project.id,
            created_by=user.id,
            target_url="http://localhost:8000/demo/users/1",
            status="completed",
            created_at=now,
            completed_at=now,
            summary_risk=7.6,
        )
        session.add(scan)

        findings = [
            models.Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                title="Broken Object Level Authorization (IDOR)",
                category="BOLA/IDOR",
                severity="High",
                cvss_score=8.1,
                confidence="High",
                plugin="bola_idor",
                cwe="CWE-639",
                evidence="Accessed /demo/users/2 without authorization and received user data.",
                recommendation="Enforce object-level authorization checks for every request.",
                remediation="Validate ownership or role-based permissions on resource access.",
            ),
            models.Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                title="Missing Strict-Transport-Security",
                category="Security Headers",
                severity="Medium",
                cvss_score=5.0,
                confidence="Medium",
                plugin="missing_headers",
                cwe="CWE-319",
                evidence="Response missing HSTS header.",
                recommendation="Enable HSTS with a long max-age and includeSubDomains.",
                remediation="Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            ),
            models.Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                title="Excessive Data Exposure",
                category="Excessive Data Exposure",
                severity="Medium",
                cvss_score=6.2,
                confidence="Medium",
                plugin="excessive_data",
                cwe="CWE-200",
                evidence="Response includes fields: ssn, dob, phone, email.",
                recommendation="Return only required fields and implement output filtering.",
                remediation="Use response DTOs/serializers to whitelist fields.",
            ),
            models.Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                title="Rate Limiting Not Enforced",
                category="Rate Limiting",
                severity="Low",
                cvss_score=3.7,
                confidence="Low",
                plugin="rate_limit",
                cwe="CWE-770",
                evidence="No 429 after 20 rapid requests.",
                recommendation="Apply per-IP and per-token rate limits.",
                remediation="Enable Redis-backed rate limiting middleware.",
            ),
        ]
        session.add_all(findings)
        await session.commit()
